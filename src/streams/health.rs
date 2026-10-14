//! Active health checks for stream targets (`accepts_connections`).
//!
//! One loop for all streams. Each second it reads the current config, so
//! targets added or removed by a reload are picked up without restarting
//! anything. A target is marked down after `unhealthy_threshold` failed
//! connects in a row, and up again after `healthy_threshold` successes.

use crate::gateway::gateway::GatewayState;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Probe {
    next: Option<Instant>,
    ok: u32,
    fail: u32,
    running: bool,
}

pub fn spawn(state: Arc<GatewayState>, handle: &tokio::runtime::Handle) {
    let h = handle.clone();
    handle.spawn(async move {
        let probes: Arc<parking_lot::Mutex<HashMap<Arc<str>, Probe>>> = Default::default();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let config = state.config.load_full();
            let now = Instant::now();
            let mut keys: HashMap<Arc<str>, ()> = HashMap::new();
            let mut due = Vec::new();
            {
                let mut p = probes.lock();
                for s in &config.streams.list {
                    for t in &s.targets {
                        keys.insert(Arc::clone(&t.key), ());
                    }
                    let Some(hc) = &s.health_check else {
                        // Checks turned off: whatever was down counts as up.
                        for t in &s.targets {
                            state.streams.health.remove(&t.key);
                        }
                        continue;
                    };
                    for t in &s.targets {
                        let e = p.entry(Arc::clone(&t.key)).or_default();
                        if e.running || e.next.is_some_and(|n| n > now) {
                            continue;
                        }
                        e.running = true;
                        e.next = Some(now + Duration::from_secs(hc.interval_seconds.max(1)));
                        due.push((
                            Arc::clone(&t.key),
                            format!("{}:{}", t.host, t.port),
                            Duration::from_millis(hc.timeout_ms.max(1)),
                            hc.healthy_threshold.max(1),
                            hc.unhealthy_threshold.max(1),
                        ));
                    }
                }
                p.retain(|k, _| keys.contains_key(k));
            }
            state.streams.retain(&keys);

            for (key, addr, timeout, up_after, down_after) in due {
                let state = state.clone();
                let probes = probes.clone();
                h.spawn(async move {
                    let ok = matches!(
                        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await,
                        Ok(Ok(_))
                    );
                    let mut p = probes.lock();
                    let Some(e) = p.get_mut(&key) else { return };
                    e.running = false;
                    if ok {
                        e.fail = 0;
                        e.ok = e.ok.saturating_add(1);
                        if e.ok >= up_after && !state.streams.is_healthy(&key) {
                            tracing::info!(target = %key, "Stream target is healthy again");
                            state.streams.health.insert(key, true);
                        }
                    } else {
                        e.ok = 0;
                        e.fail = e.fail.saturating_add(1);
                        if e.fail >= down_after && state.streams.is_healthy(&key) {
                            tracing::warn!(target = %key, "Stream target is unhealthy");
                            state.streams.health.insert(key, false);
                        }
                    }
                });
            }
        }
    });
}
