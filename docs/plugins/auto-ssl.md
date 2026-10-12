# Auto-SSL Plugin

On-demand TLS certificate provisioning using ACME (Let's Encrypt). Certificates are obtained automatically when the first HTTPS request arrives for a configured domain — no manual certificate management required.

> **Fixed in 0.3.1.** In 0.3.0 and earlier the ACME client didn't sign its requests correctly, so Let's Encrypt rejected them and no certificate was ever issued (the gateway kept serving its self-signed fallback). 0.3.1 uses the [`instant-acme`](https://crates.io/crates/instant-acme) client, keeps one ACME account on disk, and is tested end to end against Pebble, Let's Encrypt's ACME test server.

## How It Works

```
TLS ClientHello (SNI = "example.com")
    │
    ├── cert_map has real cert? → serve it (O(1))
    │
    ├── NOT in allowed_domains? → serve default self-signed cert
    │
    ├── state = Pending? → serve fallback (worker running)
    │
    ├── state = Failed AND elapsed < 24h? → serve fallback (cooldown)
    │
    └── otherwise → dedup insert + spawn bg worker + serve fallback
        │
        └── Worker completes → cert loaded into memory → next handshake gets real cert ✅
```

### Three Triggers

| Trigger | When | Behavior |
|---------|------|----------|
| **TLS handshake** | First request for a domain in config | Serve fallback cert immediately, spawn background ACME worker |
| **Config change** | `auto_ssl.domains` list updated | Update allowed domains list only — no cert fetched |
| **Daily** | Every 24 hours | Renew certs expiring within `renewal_days_before`, retry 1 failed cert |

### On-Demand Flow

1. A TLS ClientHello arrives with SNI = `example.com`
2. Gateway checks the in-memory `cert_map` — no cert found
3. Gateway checks `allowed_domains` — domain is in the config
4. Gateway checks `cert_state` — no state yet (first request)
5. Gateway inserts domain into `provisioning_set` (dedup guard)
6. Gateway spawns a background ACME worker
7. Gateway returns a self-signed fallback cert — connection succeeds, traffic flows
8. Background worker obtains a real cert from Let's Encrypt
9. Cert is loaded into `cert_map` and persisted to disk
10. Next TLS handshake for this domain gets the real cert ✅

### Deduplication

A `DashSet<String>` ensures only **one ACME worker per domain** runs at a time. If 100 requests arrive simultaneously for the same domain without a cert, only the first spawns a worker. The rest get the fallback cert.

### Failed Cert Handling

When cert provisioning fails:

| Field | Value |
|-------|-------|
| State | `Failed` |
| Error | Stored in memory |
| Timestamp | `failed_at` recorded |
| Retry | Only when: new request arrives AND `failed_at >= 24h` |

**No aggressive retries.** A failed cert stays failed until:
- A new TLS handshake arrives for that domain AND 24 hours have passed
- The daily renewal cycle retries one failed cert per cycle

## Configuration

```json
{
  "plugins": {
    "auto_ssl": {
      "enabled": true,
      "email": "admin@example.com",
      "domains": [
        "example.com",
        "www.example.com",
        "api.example.com"
      ],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": false,
      "renewal_days_before": 30
    }
  }
}
```

## Config Fields

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `enabled` | bool | `true` | — | Enable/disable Auto-SSL |
| `email` | string | — | ✅ | Email for Let's Encrypt account registration |
| `domains` | string[] | `[]` | ✅ | Domain names to provision certificates for |
| `cert_storage_path` | string | `"/var/lib/quayel/certs"` | — | Directory to store PEM files (write-through cache) |
| `staging` | bool | `false` | — | Use Let's Encrypt staging environment (for testing) |
| `directory_url` | string | — | — | ACME directory of another CA. Overrides `staging` |
| `ca_root` | string | — | — | PEM file with the root CA of a private ACME server's HTTPS endpoint |
| `renewal_days_before` | int | `30` | — | Renew certificates this many days before expiry |

### `email`

Required. Used to register a Let's Encrypt account. Let's Encrypt sends expiry warnings to this address.

### `domains`

List of domain names the gateway should obtain certificates for. Certificates are only provisioned when the first TLS handshake arrives for a domain — adding a domain to this list does not immediately trigger cert fetching.

### `cert_storage_path`

Directory where PEM files are stored as a write-through cache. On startup, cached certs are loaded from disk into memory. This is for restart recovery only — all runtime lookups use in-memory data structures.

Directory structure:
```
/var/lib/quayel/certs/
├── acme-account-1a2b3c4d5e6f.json   ← ACME account key + URL (0600), one per directory_url
├── example.com/
│   ├── cert.pem
│   └── key.pem
├── www.example.com/
│   ├── cert.pem
│   └── key.pem
└── api.example.com/
    ├── cert.pem
    └── key.pem
```

`key.pem` and the account file are written with mode `0600` (owner only). Keep this directory on a persistent volume: losing it means registering a new account and issuing new certificates, which counts against Let's Encrypt's rate limits.

### `staging`

When `true`, uses Let's Encrypt's staging environment (`acme-staging-v02.api.letsencrypt.org`). Staging certificates are not trusted by browsers but have much higher rate limits. Use this for testing.

| Environment | URL | Rate Limits | Trusted |
|-------------|-----|-------------|---------|
| Production | `acme-v02.api.letsencrypt.org` | 50 certs/domain/week | ✅ |
| Staging | `acme-staging-v02.api.letsencrypt.org` | Much higher | ❌ |

### `directory_url` and `ca_root`

Use another ACME CA instead of Let's Encrypt, for example a private [step-ca](https://smallstep.com/docs/step-ca/) or [Pebble](https://github.com/letsencrypt/pebble) for tests. `directory_url` overrides `staging`. If the CA's own HTTPS endpoint uses a private root, point `ca_root` at that root's PEM file; otherwise the system roots are used.

```json
"auto_ssl": {
  "enabled": true,
  "email": "ops@example.com",
  "domains": ["internal.example.com"],
  "directory_url": "https://ca.internal:9000/acme/acme/directory",
  "ca_root": "/etc/quayel/step-ca-root.pem"
}
```

CAs that require External Account Binding (ZeroSSL, Google Trust Services) aren't supported yet.

### ACME account

The gateway registers one ACME account the first time it needs a certificate and saves it as `acme-account-<hash>.json` in `cert_storage_path`. Every later certificate and renewal uses that account, also after restarts. Switching `staging` or `directory_url` uses a separate account file, so accounts never get mixed between CAs.

### `renewal_days_before`

The daily renewal check renews certificates that will expire within this many days. Default is 30 days (Let's Encrypt certs are valid for 90 days).

## In-Memory Architecture

All runtime state lives in `Arc`-wrapped concurrent data structures. No disk I/O on the hot path.

| Store | Type | Purpose | Lookup |
|-------|------|---------|--------|
| `cert_map` | `DashMap<String, Arc<CertifiedKey>>` | Domain → TLS certificate | O(1) |
| `cert_state` | `DashMap<String, CertState>` | Domain → provisioning state | O(1) |
| `allowed_domains` | `RwLock<HashSet<String>>` | Config-sourced whitelist | O(1) |
| `challenge_tokens` | `DashMap<String, String>` | HTTP-01 token → key-auth | O(1) |
| `provisioning_set` | `DashSet<String>` | Dedup guard (one worker/domain) | O(1) |

### Cert States

| State | Meaning | Retry Behavior |
|-------|---------|----------------|
| `Valid` | Cert loaded, has `expires_at` | — |
| `Pending` | ACME worker in progress | — |
| `Failed` | Error + timestamp + attempt count | Next request after 24h, or daily cycle |
| `Expired` | Detected by daily check | Triggers re-provision |

## Disk I/O

| Operation | When | Pattern |
|-----------|------|---------|
| **Read** | Startup only | Load cached PEMs from `cert_storage_path` into `cert_map` |
| **Write** | After cert obtained | Fire-and-forget `tokio::spawn` — save PEM to disk in background |

Memory is the source of truth. Disk is a write-through cache for restart recovery.

## HTTP-01 Challenge

The ACME HTTP-01 challenge works by serving a token at a well-known URL:

```
http://DOMAIN/.well-known/acme-challenge/TOKEN
```

When Let's Encrypt verifies domain ownership:

1. The ACME client stores the token + key-authorization in `challenge_tokens`
2. The gateway's `request_filter` intercepts `/.well-known/acme-challenge/*` requests
3. The gateway serves the key-authorization as plain text
4. Let's Encrypt verifies the token and issues the cert
5. The token is removed from memory

**Port 80 must be accessible** from the internet for HTTP-01 challenges to work. If the gateway only listens on HTTPS, HTTP-01 challenges will fail.

## Startup Behavior

The gateway starts serving traffic immediately. HTTPS uses a self-signed fallback cert until real certs are provisioned.

```
main.rs:
  HTTP listener starts (:8080)     ← traffic flows immediately
  HTTPS listener starts (:8443)    ← uses fallback cert
  if auto_ssl.enabled:
    load cached certs from disk
    (no blocking — provisioning happens on first request)
```

**Non-blocking.** The gateway does not wait for certificates to be provisioned before starting. Traffic flows immediately with fallback certs.

## Config Hot-Reload

When the config file changes:

1. Config watcher detects SHA-256 hash change
2. New config is validated and compiled
3. `auto_ssl.domains` list is updated in memory
4. **No certs are fetched** — that happens on the next TLS handshake

Adding a new domain to the config only updates the allowed list. The cert is provisioned when the first request arrives for that domain.

## Daily Renewal

A background task runs every 24 hours:

1. Check all domains in `allowed_domains`
2. If a cert expires within `renewal_days_before` days → re-provision
3. If a cert is expired → re-provision
4. If a cert is failed AND `failed_at >= 24h` → retry (max 1 failed cert per cycle)

## Prerequisites

1. **Port 80** must be accessible from the internet (for HTTP-01 challenges)
2. **DNS** must point the configured domains to the gateway's public IP
3. **Let's Encrypt rate limits**: 50 certificates per registered domain per week (production)

## Examples

### Basic setup

```json
{
  "plugins": {
    "auto_ssl": {
      "enabled": true,
      "email": "admin@example.com",
      "domains": ["example.com", "www.example.com"],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": false,
      "renewal_days_before": 30
    }
  }
}
```

### Testing with staging

```json
{
  "plugins": {
    "auto_ssl": {
      "enabled": true,
      "email": "dev@example.com",
      "domains": ["staging.example.com"],
      "staging": true,
      "renewal_days_before": 7
    }
  }
}
```

### Multiple domains

```json
{
  "plugins": {
    "auto_ssl": {
      "enabled": true,
      "email": "ops@example.com",
      "domains": [
        "example.com",
        "www.example.com",
        "api.example.com",
        "admin.example.com",
        "cdn.example.com"
      ],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": false,
      "renewal_days_before": 30
    }
  }
}
```

### Full gateway config with Auto-SSL

```json
{
  "gateway_id": "gw-prod-01",
  "gateway_name": "production",
  "server_name": "example.com",
  "config_version": "2026-01-01-001",
  "listen": {
    "http": "0.0.0.0:80",
    "https": "0.0.0.0:443"
  },
  "client_ip": {
    "source": "header",
    "header": "X-Forwarded-For"
  },
  "plugins": {
    "ip_intel": { "enabled": true },
    "auto_ssl": {
      "enabled": true,
      "email": "admin@example.com",
      "domains": ["example.com", "www.example.com"],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": false,
      "renewal_days_before": 30
    },
    "firewall": {
      "enabled": true,
      "rules": [
        {
          "id": "block-tor",
          "name": "Block Tor Exit Nodes",
          "enabled": true,
          "conditions": [
            { "left": "ip.is_tor", "operator": "equals", "value": true }
          ],
          "action": { "type": "block", "status": 403 }
        }
      ]
    },
    "load_balancer": {
      "enabled": true,
      "load_balancers": [
        {
          "id": "default",
          "name": "Backend",
          "enabled": true,
          "conditions": [],
          "algorithm": { "type": "round_robin" },
          "targets": [
            {
              "id": "backend-1",
              "host": "127.0.0.1",
              "port": 3000,
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
```

## Troubleshooting

### Cert not being provisioned

1. Check that port 80 is accessible from the internet
2. Check that DNS points to the gateway's IP
3. Check logs for ACME errors: `RUST_LOG=debug`
4. Try with `"staging": true` first to avoid rate limits

### Challenge verification fails

Let's Encrypt needs to reach `http://DOMAIN/.well-known/acme-challenge/TOKEN`. Common issues:

- Port 80 is blocked by a firewall
- DNS is not pointing to the gateway
- Another service is listening on port 80
- The domain is behind a CDN that doesn't proxy port 80

### Cert provisioning takes too long

ACME provisioning typically takes 5-30 seconds. If it's taking longer:

- Check network connectivity to `acme-v02.api.letsencrypt.org`
- Check logs for timeout errors
- The gateway waits up to 120 seconds each for challenge validation and for issuance, polling with backoff

### Fallback cert shown in browser

If browsers show a certificate warning:

- The real cert hasn't been provisioned yet (first request)
- The cert provisioning failed (check logs)
- The domain is not in the `auto_ssl.domains` list

## Performance

| Metric | Value |
|--------|-------|
| Cert lookup | O(1) — DashMap |
| SNI resolution | O(1) — in-memory |
| Disk I/O on hot path | None — memory is source of truth |
| Startup delay | None — non-blocking |
| Memory per cert | ~4 KB (CertifiedKey + metadata) |
| ACME provisioning time | 5-30 seconds (first request only) |

## Limitations

- **HTTP-01 only**: Only HTTP-01 challenges are supported (not DNS-01 or TLS-ALPN-01)
- **Single domain per cert**: Each certificate covers one domain (no multi-SAN)
- **No wildcard certs**: Wildcard certificates require DNS-01 challenges
- **Port 80 required**: HTTP-01 challenges need port 80 accessible from the internet
- **No External Account Binding**: ACME CAs that require EAB (ZeroSSL, Google Trust Services) aren't supported yet

## Testing

`scripts/test/auto-ssl.py` runs the whole flow against [Pebble](https://github.com/letsencrypt/pebble) in Docker: issuance on the first handshake, a certificate that verifies against the CA root, account reuse across domains and restarts, `0600` files, unlisted and refused domains. `cargo test le_staging -- --ignored` registers and reloads an account on the real Let's Encrypt staging server.