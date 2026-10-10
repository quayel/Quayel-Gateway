# Getting Started

## Prerequisites

- Linux x86_64 (Ubuntu 22.04+ recommended)
- No external dependencies (no Redis, no database, no Docker)

## Installation

### 1. Download the binary

```bash
# Copy the release binary to your server
scp target/release/quayel-gateway user@server:/usr/local/bin/quayel-gateway
chmod +x /usr/local/bin/quayel-gateway
```

### 2. Create a config file

```bash
mkdir -p /etc/quayel
cat > /etc/quayel/config.json << 'EOF'
{
  "gateway_id": "gw-prod-01",
  "gateway_name": "production",
  "server_name": "api.example.com",
  "config_version": "2026-01-01-001",
  "listen": {
    "http": "0.0.0.0:8080"
  },
  "client_ip": {
    "source": "header",
    "header": "X-Forwarded-For",
    "index": 0,
    "fallback": "peer_ip"
  },
  "plugins": {
    "ip_intel": { "enabled": true },
    "load_balancer": {
      "enabled": true,
      "load_balancers": [
        {
          "id": "default",
          "name": "My Backend",
          "enabled": true,
          "conditions": [],
          "algorithm": { "type": "round_robin" },
          "targets": [
            {
              "id": "backend-1",
              "host": "10.0.0.1",
              "port": 8080,
              "protocol": "http",
              "weight": 100,
              "enabled": true
            }
          ],
          "host_header": { "mode": "visitor" },
          "health_check": { "mode": "off" }
        }
      ]
    },
    "logging": {
      "enabled": true,
      "mode": "file",
      "file": {
        "path": "/var/log/quayel/access.jsonl",
        "buffer_size": 8192,
        "flush_interval_ms": 1000
      }
    }
  }
}
EOF
```

### 3. Start the gateway

```bash
# Foreground (for testing)
quayel-gateway /etc/quayel/config.json

# With systemd
cat > /etc/systemd/system/quayel-gateway.service << 'EOF'
[Unit]
Description=Quayel Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quayel-gateway /etc/quayel/config.json
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now quayel-gateway
```

### 4. Test it

```bash
# Health check
curl -v http://localhost:8080/

# Check logs
tail -f /var/log/quayel/access.jsonl | jq .
```

## Minimal Config

The absolute minimum `config.json`:

```json
{
  "gateway_id": "gw-01",
  "gateway_name": "default",
  "server_name": "localhost",
  "config_version": "1",
  "listen": { "http": "0.0.0.0:8080" },
  "plugins": {
    "load_balancer": {
      "enabled": true,
      "load_balancers": [{
        "id": "default",
        "name": "Backend",
        "enabled": true,
        "conditions": [],
        "algorithm": { "type": "round_robin" },
        "targets": [{
          "id": "t1",
          "host": "127.0.0.1",
          "port": 3000,
          "protocol": "http",
          "weight": 100,
          "enabled": true
        }],
        "host_header": { "mode": "visitor" },
        "health_check": { "mode": "off" }
      }]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `QUAYEL_IP_INTEL_CACHE_SIZE` | `65536` | LRU cache size for IP lookups |

## Auto-SSL (Optional)

The gateway can automatically obtain TLS certificates from Let's Encrypt. Add this to your config:

```json
{
  "plugins": {
    "auto_ssl": {
      "enabled": true,
      "email": "admin@example.com",
      "domains": ["example.com", "www.example.com"],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": true,
      "renewal_days_before": 30
    }
  }
}
```

**Requirements:**
- Port 80 must be accessible from the internet
- DNS must point to the gateway's public IP
- Use `"staging": true` for testing (no rate limits, untrusted certs)

See [Auto-SSL Plugin](plugins/auto-ssl.md) for full documentation.

## Building from Source

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Strip debug symbols (smaller binary)
strip target/release/quayel-gateway

# Run
./target/release/quayel-gateway config.json
```

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 64 MB | 128 MB |
| Disk | 200 MB | 500 MB (for logs) |
| Binary size | ~153 MB | — (includes embedded data) |
| Runtime RSS | ~29 MB | — |