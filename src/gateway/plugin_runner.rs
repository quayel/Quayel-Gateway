use crate::config::compiler::CompiledConfig;
use crate::gateway::request_context::{RequestContext, TerminationPhase};
use crate::plugins::cache::CachePlugin;
use crate::plugins::firewall::FirewallPlugin;
use crate::plugins::ip_intel::IpIntelPlugin;
use crate::plugins::load_balancer::LoadBalancerPlugin;
use crate::plugins::rate_limit::RateLimitPlugin;
use crate::plugins::transform::apply_request_transform;
use crate::plugins::PluginFlow;
use std::sync::Arc;

// ── Plugin Runner ────────────────────────────────────────────────────────────
// Central pipeline executor. Executes plugins in fixed order:
//   ip_intel → firewall → rate_limiting → request_transform → cache → load_balancer → logging
//
// request_transform runs after the protection plugins, so firewall and rate
// limits always see the request the client actually sent, and before cache, so
// the cache key is built from the rewritten request. response_transform is not
// a pipeline step: it runs on the way out (gateway.rs).
//
// NOTE: cache runs BEFORE load_balancer so cache HITs never select a target or
// bump connection counts. SWR revalidation is not a background fetch — the
// request holding the revalidation lock returns Continue and falls through to
// load_balancer like a MISS. The plugin runner is the ONLY place defining
// global plugin order.

pub struct PluginRunner {
    pub ip_intel: IpIntelPlugin,
    pub firewall: FirewallPlugin,
    pub rate_limiting: RateLimitPlugin,
    pub load_balancer: LoadBalancerPlugin,
    pub cache: CachePlugin,
}

impl PluginRunner {
    pub fn new(_config: &CompiledConfig) -> Self {
        let ip_intel = IpIntelPlugin::new();

        Self {
            ip_intel,
            firewall: FirewallPlugin,
            rate_limiting: RateLimitPlugin::new(),
            load_balancer: LoadBalancerPlugin::new(),
            cache: CachePlugin::new(),
        }
    }

    /// Execute the full plugin pipeline. Returns the PluginFlow result.
    /// If any plugin returns Respond, we skip remaining plugins (except logging).
    ///
    /// HOT PATH: All timing/metrics recording removed to eliminate
    /// Instant::now() syscalls and atomic operations on every request.
    pub async fn execute_pipeline(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
        _metrics: &crate::utils::metrics::PluginMetrics,
    ) -> PluginFlow {
        // 1. IP Intelligence
        if let Some(ip_intel_config) = &config.ip_intel {
            if ip_intel_config.enabled {
                let flow = self.ip_intel.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::IpIntel);
                    return flow;
                }
            }
        }

        // 2. Firewall
        if let Some(fw_config) = &config.firewall {
            if fw_config.enabled {
                let flow = self.firewall.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::Firewall);
                    return flow;
                }
            }
        }

        // 3. Rate Limiting
        if let Some(rl_config) = &config.rate_limiting {
            if rl_config.enabled {
                let flow = self.rate_limiting.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::RateLimit);
                    return flow;
                }
            }
        }

        // 4. Request Transform — rewrites ctx; replayed upstream in upstream_request_filter
        if let Some(rt) = &config.request_transform {
            apply_request_transform(ctx, rt);
        }

        // 5. Cache — HITs respond here without selecting a backend
        if let Some(cache_config) = &config.cache {
            if cache_config.enabled {
                let flow = self.cache.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::Cache);
                    return flow;
                }
            }
        }

        // 6. Load Balancer — only reached on MISS / BYPASS / EXPIRED / revalidation
        if let Some(lb_config) = &config.load_balancer {
            if lb_config.enabled {
                let flow = self.load_balancer.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::LoadBalancer);
                    return flow;
                }
            }
        }

        PluginFlow::Continue
    }
}
