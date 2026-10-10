use crate::config::schema::*;
use bytes::Bytes;
use crate::config::compiler::{CompiledConfig, CompiledTarget};
use crate::gateway::request_context::*;
use crate::plugins::firewall::{evaluate_conditions, resolve_condition_value};
use crate::plugins::{GatewayResponse, PluginFlow};
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

// Load Balancer Plugin

#[derive(Debug)]
pub struct LoadBalancerPlugin {
    pub rr_counters: DashMap<String, AtomicUsize>,
    pub connection_counts: DashMap<String, AtomicU64>,
    pub latency_ewma: DashMap<String, AtomicU64>,
}

impl LoadBalancerPlugin {
    pub fn new() -> Self {
        Self {
            rr_counters: DashMap::new(),
            connection_counts: DashMap::new(),
            latency_ewma: DashMap::new(),
        }
    }

    pub async fn execute(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
    ) -> PluginFlow {
        let lb_plugin = match &config.load_balancer {
            Some(c) if c.enabled => c,
            _ => return PluginFlow::Continue,
        };

        for lb in &lb_plugin.load_balancers {
            if !lb.enabled {
                continue;
            }

            // Evaluate conditions - fast-path for empty conditions
            let matched = lb.conditions.is_empty() || evaluate_conditions(ctx, &lb.conditions);

            if !matched {
                continue;
            }

            let healthy_targets: Vec<&CompiledTarget> =
                lb.targets.iter().filter(|t| t.enabled).collect();

            if healthy_targets.is_empty() {
                ctx.status_code = Some(503);
                return PluginFlow::Respond(GatewayResponse {
                    status: 503,
                    headers: Arc::new(vec![
                        ("content-type".to_string(), "application/json".to_string()),
                    ]),
                    body: Bytes::from_static(b"{\"error\":\"no_healthy_upstream\"}"),
                });
            }

            let selected = match &lb.algorithm.algorithm_type {
                AlgorithmType::RoundRobin => self.select_round_robin(&lb.id, &healthy_targets),
                AlgorithmType::WeightedRoundRobin => {
                    self.select_weighted_round_robin(&lb.id, &healthy_targets)
                }
                AlgorithmType::LeastConnections => {
                    self.select_least_connections(&healthy_targets)
                }
                AlgorithmType::FastResponse => self.select_fast_response(&healthy_targets),
                AlgorithmType::StickySession => {
                    let key = lb
                        .algorithm
                        .key
                        .as_deref()
                        .unwrap_or("req.ip");
                    self.select_sticky_session(ctx, key, &healthy_targets)
                }
            };

            let target = selected;

            {
                ctx.load_balancer.lb_id = Some(Arc::clone(&lb.id));
                ctx.load_balancer.lb_name = Some(Arc::clone(&lb.name));
                ctx.load_balancer.algorithm = Some(format!("{:?}", lb.algorithm.algorithm_type));
                ctx.load_balancer.target_id = Some(Arc::clone(&target.id));
                ctx.load_balancer.target_host = Some(Arc::clone(&target.host));
                ctx.load_balancer.target_port = Some(target.port);
                ctx.load_balancer.target_protocol = Some(Arc::from(target.protocol.as_str()));
                ctx.load_balancer.target_tls_verify = Some(target.tls_verify);
                ctx.load_balancer.target_tls_sni = target.tls_sni.as_ref().map(Arc::clone);
            }

            ctx.upstream_name = Some(lb.name.clone());
            ctx.upstream_target = Some(target.host.clone());
            ctx.upstream_protocol = Some(match target.protocol {
                TargetProtocol::Http => UpstreamProtocol::Http,
                TargetProtocol::Https => UpstreamProtocol::Https,
            });

            let conn_key = format!("{}:{}", target.host, target.port);
            self.connection_counts
                .entry(conn_key)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);

            return PluginFlow::Continue;
        }

        PluginFlow::Continue
    }

    fn select_round_robin<'a>(
        &self,
        lb_id: &str,
        targets: &[&'a CompiledTarget],
    ) -> &'a CompiledTarget {
        let counter = self
            .rr_counters
            .entry(lb_id.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        let idx = counter.fetch_add(1, Ordering::Relaxed) % targets.len();
        targets[idx]
    }

    fn select_weighted_round_robin<'a>(
        &self,
        lb_id: &str,
        targets: &[&'a CompiledTarget],
    ) -> &'a CompiledTarget {
        let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
        if total_weight == 0 {
            return targets[0];
        }

        let counter = self
            .rr_counters
            .entry(format!("wrr_{}", lb_id))
            .or_insert_with(|| AtomicUsize::new(0));

        let current = counter.fetch_add(1, Ordering::Relaxed) as u32;
        let mut position = current % total_weight;

        for target in targets {
            if position < target.weight {
                return target;
            }
            position -= target.weight;
        }

        targets[0]
    }

    fn select_least_connections<'a>(&self, targets: &[&'a CompiledTarget]) -> &'a CompiledTarget {
        let mut min_conns = u64::MAX;
        let mut selected = targets[0];

        for target in targets {
            let key = format!("{}:{}", target.host, target.port);
            let conns = self
                .connection_counts
                .get(&key)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);

            if conns < min_conns {
                min_conns = conns;
                selected = target;
            }
        }

        selected
    }

    fn select_fast_response<'a>(&self, targets: &[&'a CompiledTarget]) -> &'a CompiledTarget {
        let mut best_latency = u64::MAX;
        let mut selected = targets[0];

        for target in targets {
            let key = format!("{}:{}", target.host, target.port);
            let latency = self
                .latency_ewma
                .get(&key)
                .map(|l| l.load(Ordering::Relaxed))
                .unwrap_or(u64::MAX);

            if latency < best_latency {
                best_latency = latency;
                selected = target;
            }
        }

        selected
    }

    fn select_sticky_session<'a>(
        &self,
        ctx: &mut RequestContext,
        key_path: &str,
        targets: &[&'a CompiledTarget],
    ) -> &'a CompiledTarget {
        let sticky_value = resolve_condition_value(ctx, key_path)
            .map(|v| match v {
                serde_json::Value::String(s) => s,
                other => format!("{:?}", other),
            })
            .unwrap_or_else(|| "default".to_string());

        let mut best_score: u64 = 0;
        let mut selected = targets[0];

        for target in targets {
            let combined = format!("{}:{}", target.id, sticky_value);
            let hash = hash_to_u64(&combined);
            if hash > best_score {
                best_score = hash;
                selected = target;
            }
        }

        selected
    }

    pub fn update_latency(&self, target_host: &str, target_port: u16, latency_us: u64) {
        let key = format!("{}:{}", target_host, target_port);
        let entry = self
            .latency_ewma
            .entry(key)
            .or_insert_with(|| AtomicU64::new(latency_us));

        let old = entry.load(Ordering::Relaxed);
        let new_val = (old * 3 + latency_us) / 4;
        entry.store(new_val, Ordering::Relaxed);
    }

    pub fn release_connection(&self, target_host: &str, target_port: u16) {
        let key = format!("{}:{}", target_host, target_port);
        if let Some(counter) = self.connection_counts.get(&key) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn hash_to_u64(input: &str) -> u64 {
    let mut hasher = FxHasher::default();
    input.hash(&mut hasher);
    hasher.finish()
}