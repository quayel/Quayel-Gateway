# syntax=docker/dockerfile:1
# Quayel Gateway — multi-stage build
#
# Stage 1 (builder): Rust toolchain + system build tools, compiles the release
#                    binary with all IP-intelligence datasets embedded
#                    (include_bytes!/include_str! — the gateway runs offline).
# Stage 2 (runtime): debian:bookworm-slim + the stripped binary. No Rust, no
#                    source, no toolchain — just the gateway and CA roots.

########## build ##########
FROM rust:1-bookworm AS builder

# Same system build tools as setup.sh's cargo phase
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential pkg-config cmake clang libclang-dev \
        ca-certificates curl jq gzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/quayel-gateway

# Copy the full tree (target/, .git/ and local config.json excluded via .dockerignore)
COPY . .

# Datasets are compiled into the binary, but *.mmdb is gitignored so a fresh
# clone has none. Reuse the build context's copies when present; otherwise
# download them (setup.sh keeps the previous copy if a source is down).
RUN if [ ! -f src/data/dbip-city-lite.mmdb ]; then ./setup.sh --data-only; fi

# Build with BuildKit cache mounts so crate downloads and dependency
# compilation survive across builds even when the source changes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/quayel-gateway/target \
    cargo build --release --locked \
    && cp target/release/quayel-gateway /usr/local/bin/quayel-gateway

########## runtime ##########
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Quayel Gateway" \
      org.opencontainers.image.description="High-performance Rust API gateway built on Cloudflare Pingora — IP intelligence, firewall, rate limiting, cache, load balancing, auto-SSL" \
      org.opencontainers.image.source="https://github.com/quayel/Quayel-Gateway"

# libgcc_s is the only extra runtime lib the binary needs (see ldd);
# ca-certificates for outbound HTTPS (ACME, health checks, upstream TLS);
# libcap2-bin provides setcap, used below.
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates libgcc-s1 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/quayel-gateway /usr/local/bin/quayel-gateway

# The gateway parses untrusted input, so it runs as an unprivileged user. It
# still needs to bind 80/443, which the file capability grants without root.
RUN groupadd --system --gid 10001 quayel \
    && useradd --system --uid 10001 --gid quayel --no-create-home --shell /usr/sbin/nologin quayel \
    && setcap cap_net_bind_service=+ep /usr/local/bin/quayel-gateway

# Auto-SSL state (ACME account key, issued certs + private keys) lives in
# /var/lib/quayel/certs (the default `cert_storage_path`). It MUST survive
# container restarts — otherwise every start re-issues certificates and hits
# Let's Encrypt rate limits. Mount a volume over it:
#   -v quayel-certs:/var/lib/quayel/certs   (or see docker-compose.yml)
RUN mkdir -p /var/lib/quayel/certs /var/log/quayel \
    && chown -R quayel:quayel /var/lib/quayel /var/log/quayel
VOLUME ["/var/lib/quayel/certs"]

# Default config = the demo, with Let's Encrypt staging so a fresh container
# does not request production certificates. The release archives and .deb keep
# the demo as shipped. Mount your own config over it:
#   docker run -v $PWD/config.json:/etc/quayel-gateway/config.json:ro ...
COPY examples/config.demo.json /etc/quayel-gateway/config.json
RUN sed -i 's/"staging": false/"staging": true/' /etc/quayel-gateway/config.json \
    && grep -q '"staging": true' /etc/quayel-gateway/config.json

WORKDIR /etc/quayel-gateway

# The bundled demo config listens on 80/443, the gateway's defaults. ACME
# HTTP-01 needs port 80 reachable from the internet: run with -p 80:80 -p 443:443.
EXPOSE 80 443

USER quayel:quayel

# The gateway shuts down gracefully on SIGTERM (5s grace + 5s drain — set in
# main.rs), so container stop is clean within Docker's default 10s timeout.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/quayel-gateway"]
CMD ["/etc/quayel-gateway/config.json"]
