use crate::config::schema::GatewayConfig;
use std::fs;
use std::path::Path;

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<GatewayConfig, String> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {:?}: {}", path, e))?;

    let config: GatewayConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    validate_config(&config)?;
    Ok(config)
}

pub fn load_config_from_str(content: &str) -> Result<GatewayConfig, String> {
    let config: GatewayConfig = serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &GatewayConfig) -> Result<(), String> {
    // Validate client IP config
    match &config.client_ip.source {
        crate::config::schema::ClientIpSource::Header
        | crate::config::schema::ClientIpSource::HeaderIndex => {
            if config.client_ip.header.is_none() {
                return Err(format!(
                    "client_ip.source is {:?} but no header specified",
                    config.client_ip.source
                ));
            }
        }
        _ => {}
    }

    if config.client_ip.source == crate::config::schema::ClientIpSource::HeaderIndex
        && config.client_ip.index.is_none()
    {
        return Err("client_ip.source is header_index but no index specified".to_string());
    }

    // Validate firewall rules
    if let Some(fw) = &config.plugins.firewall {
        for rule in &fw.rules {
            if rule.conditions.is_empty() {
                return Err(format!(
                    "Firewall rule '{}' has no conditions",
                    rule.id
                ));
            }
        }
    }

    // Validate rate limiting rules
    if let Some(rl) = &config.plugins.rate_limiting {
        for rule in &rl.rules {
            if rule.limit == 0 {
                return Err(format!(
                    "Rate limit rule '{}' has zero limit",
                    rule.id
                ));
            }
            if rule.window_seconds == 0 {
                return Err(format!(
                    "Rate limit rule '{}' has zero window",
                    rule.id
                ));
            }
        }
    }

    // Validate load balancer targets
    if let Some(lb_plugin) = &config.plugins.load_balancer {
        for lb in &lb_plugin.load_balancers {
            if lb.targets.is_empty() {
                return Err(format!(
                    "Load balancer '{}' has no targets",
                    lb.id
                ));
            }
        }
    }

    Ok(())
}