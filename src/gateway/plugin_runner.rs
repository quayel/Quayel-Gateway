use crate::config::compiler::CompiledConfig;
use crate::gateway::request_context::{RequestContext, TerminationPhase};
use crate::plugins::cache::CachePlugin;
use crate::plugins::firewall::FirewallPlugin;
use crate::plugins::ip_intel::IpIntelPlugin;
use crate::plugins::load_balancer::LoadBalancerPlugin;
use crate::plugins::rate_limit::RateLimitPlugin;
use crate::plugins::PluginFlow;
use std::sync::Arc;

// ── Plugin Runner ────────────────────────────────────────────────────────────
// Central pipeline executor. Executes plugins in fixed order:
//   ip_intel → firewall → rate_limiting → load_balancer → cache → logging
//
// NOTE: load_balancer runs BEFORE cache so that cache can use upstream_target
// for background revalidation (SWR). The plugin runner is the ONLY place
// defining global plugin order.

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

        // 4. Load Balancer (runs BEFORE cache so upstream_target is available for revalidation)
        if let Some(lb_config) = &config.load_balancer {
            if lb_config.enabled {
                let flow = self.load_balancer.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::LoadBalancer);
                    return flow;
                }
            }
        }

        // 5. Cache
        if let Some(cache_config) = &config.cache {
            if cache_config.enabled {
                let flow = self.cache.execute(ctx, config).await;
                if let PluginFlow::Respond(_) = &flow {
                    ctx.termination_phase = Some(TerminationPhase::Cache);
                    return flow;
                }
            }
        }

        PluginFlow::Continue
    }
}