#!/usr/bin/env bash
# ==============================================================================
#  Quayel Gateway — setup.sh
# ==============================================================================
#  One-shot bootstrap for a fresh checkout:
#
#    1. Downloads every embedded IP-intelligence dataset into src/data/
#       • MMDB databases (DB-IP Lite, monthly):
#           dbip-city-lite.mmdb   dbip-asn-lite.mmdb   dbip-country.mmdb
#       • Latest ASN / IP lists:
#           cloudflare.txt   hosting-asns.txt   proxy.txt   tor.txt   vpn.txt
#
#       Datacenter/hosting detection is ASN-based: src/data/provider-asns.txt
#       ('ASN|Label', e.g. 47583|Hostinger) is versioned in the repo and needs
#       no download. The ASN MMDB resolves any client IP to its ASN and the
#       registry maps that ASN to a provider — datacenter IP ranges are not
#       shipped. To add a provider: add ONE line to provider-asns.txt.
#
#    2. Installs the Rust toolchain (if missing), system build tools and all
#       cargo packages (crate dependencies) declared in Cargo.toml/Cargo.lock.
#
#  Usage:
#    ./setup.sh               # datasets + cargo packages (default)
#    ./setup.sh --data-only   # only download the datasets
#    ./setup.sh --asns-only   # only refresh ASN lists (hosting-asns + registry)
#    ./setup.sh --cargo-only  # only toolchain + cargo packages
#    ./setup.sh --help
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${ROOT_DIR}/src/data"

# ── pretty printing ──────────────────────────────────────────────────────────
info() { printf '\033[1;34m[info]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Quayel Gateway — setup.sh

  1. Downloads all embedded IP-intelligence datasets into src/data/
     (MMDB databases + cloudflare/hosting-asns/proxy/tor/vpn lists)
  2. Installs the Rust toolchain, system build tools and all cargo packages.

  Datacenter/hosting detection is ASN-based — no datacenter IP ranges are
  downloaded. src/data/provider-asns.txt maps 'ASN|Label' (e.g. 47583|Hostinger)
  and is versioned in the repo. Add a provider by adding one line to that file.

Usage:
  ./setup.sh               # datasets + cargo packages (default)
  ./setup.sh --data-only   # only download the datasets
  ./setup.sh --asns-only   # only refresh ASN lists (hosting-asns + registry)
  ./setup.sh --cargo-only  # only toolchain + cargo packages
  ./setup.sh --help
EOF
}

# ── helpers ──────────────────────────────────────────────────────────────────

# fetch_raw URL — stream a URL to stdout, tolerate transient failures
fetch_raw() {
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$@"
}

# clean_list (stdin → stdout) — trim CR/whitespace, drop comments/blank lines,
# keep only IPv4/IPv6 addresses, CIDR ranges or bare ASN numbers, deduplicate
# and sort.
clean_list() {
    sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | grep -E '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' \
        | sort -u
}

# save_list FILENAME (stdin → file) — atomically install a cleaned list in
# src/data/. On failure the previous copy is kept so the build never breaks.
save_list() {
    local name="$1"
    local dest="${DATA_DIR}/${name}"
    local tmp="${DATA_DIR}/.${name}.tmp.$$"

    clean_list > "${tmp}"
    if [[ ! -s "${tmp}" ]]; then
        rm -f "${tmp}"
        [[ -s "${dest}" ]] || die "${name}: download produced no data and no previous copy exists"
        warn "${name}: download produced no data — keeping previous copy"
        return 0
    fi
    mv -f "${tmp}" "${dest}"
    ok "${name}  ($(wc -l < "${dest}" | tr -d ' ') entries)"
}

# download_mmdb OUT_NAME URL — download a gzipped MMDB and decompress it
download_mmdb() {
    local name="$1" url="$2"
    local dest="${DATA_DIR}/${name}"
    local tmp="${DATA_DIR}/.${name}.tmp.$$"

    info "downloading ${name} …"
    if fetch_raw "${url}" -o "${tmp}.gz"; then
        gzip -dc "${tmp}.gz" > "${tmp}"
        rm -f "${tmp}.gz"
        [[ -s "${tmp}" ]] || die "${name}: decompressed file is empty"
        mv -f "${tmp}" "${dest}"
        ok "${name}  ($(du -h "${dest}" | cut -f1))"
    else
        rm -f "${tmp}" "${tmp}.gz"
        [[ -s "${dest}" ]] || die "${name}: download failed and no previous copy exists"
        warn "${name}: download failed — keeping previous copy"
    fi
}

# mmdb_month — DB-IP publishes monthly; early in a month the new file may not
# be out yet, so fall back to the previous month when needed.
mmdb_month() {
    local current previous
    current="$(date +%Y-%m)"
    previous="$(date -d 'last month' +%Y-%m)"
    if curl -fsI --connect-timeout 15 \
        "https://download.db-ip.com/free/dbip-city-lite-${current}.mmdb.gz" >/dev/null 2>&1; then
        echo "${current}"
    else
        echo "${previous}"
    fi
}

# ── ASN lists ────────────────────────────────────────────────────────────────
# provider-asns.txt ('ASN|Label') is versioned in the repo — the single source
# of truth for datacenter/hosting provider classification. Edit it directly.

# download_hosting_asns — refresh hosting-asns.txt (bad-asn-list): ASNs known
# for hosting/abuse. Requests from these ASNs are flagged is_datacenter too.
download_hosting_asns() {
    info 'downloading hosting-asns.txt …'
    fetch_raw 'https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv' \
        | tail -n +2 | cut -d',' -f1 \
        | save_list 'hosting-asns.txt'
}

# refresh_asn_lists — hosting-asns.txt download + provider registry summary
refresh_asn_lists() {
    echo
    info '=== ASN lists ==='
    download_hosting_asns
    local reg="${DATA_DIR}/provider-asns.txt"
    if [[ -s "${reg}" ]]; then
        ok "provider-asns.txt  ($(grep -cE '^[0-9]' "${reg}" || true) ASNs, $(grep -E '^[0-9]' "${reg}" | cut -d'|' -f2 | sort -u | wc -l | tr -d ' ') providers)"
    else
        warn 'provider-asns.txt missing — restore it from the repository'
    fi
}

# ── phase 1: datasets ────────────────────────────────────────────────────────

setup_datasets() {
    mkdir -p "${DATA_DIR}"
    local month
    month="$(mmdb_month)"

    echo
    info "=== 1/2  IP-intelligence datasets → src/data/ ==="
    info "MMDB release month: ${month}"

    # ── MMDB databases (DB-IP Lite, CC-BY 4.0) ───────────────────────────────
    local dbip='https://download.db-ip.com/free'
    download_mmdb 'dbip-city-lite.mmdb' "${dbip}/dbip-city-lite-${month}.mmdb.gz"
    download_mmdb 'dbip-asn-lite.mmdb'  "${dbip}/dbip-asn-lite-${month}.mmdb.gz"
    download_mmdb 'dbip-country.mmdb'   "${dbip}/dbip-country-lite-${month}.mmdb.gz"

    # ── cloudflare.txt — Cloudflare edge ranges (IPv4 + IPv6) ────────────────
    info 'downloading cloudflare.txt …'
    {
        fetch_raw 'https://www.cloudflare.com/ips-v4' || warn 'cloudflare ips-v4 failed'
        fetch_raw 'https://www.cloudflare.com/ips-v6' || warn 'cloudflare ips-v6 failed'
    } | save_list 'cloudflare.txt'

    # ── vpn.txt — X4BNet VPN provider ranges ─────────────────────────────────
    info 'downloading vpn.txt …'
    fetch_raw 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt' \
        | save_list 'vpn.txt'

    # ── tor.txt — Tor Project exit nodes ─────────────────────────────────────
    info 'downloading tor.txt …'
    fetch_raw 'https://check.torproject.org/torbulkexitlist' \
        | save_list 'tor.txt'

    # ── hosting-asns.txt — ASNs known for hosting/abuse ──────────────────────
    download_hosting_asns

    # ── proxy.txt — FireHOL anonymous proxy ranges ───────────────────────────
    info 'downloading proxy.txt …'
    fetch_raw 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset' \
        | save_list 'proxy.txt'
}

# ── phase 2: cargo packages ──────────────────────────────────────────────────

setup_cargo() {
    echo
    info '=== 2/2  Rust toolchain + cargo packages ==='

    # system build tools (Debian/Ubuntu; safe no-op elsewhere)
    if command -v apt-get >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
        info 'installing system build tools (build-essential, pkg-config, cmake, clang, jq) …'
        apt-get update -qq || warn 'apt-get update failed — continuing'
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            build-essential pkg-config cmake clang libclang-dev \
            ca-certificates curl jq gzip \
            || warn 'apt-get install failed — continuing with existing tools'
    fi

    # Rust toolchain via rustup (only if cargo is missing)
    if ! command -v cargo >/dev/null 2>&1; then
        info 'cargo not found — installing Rust toolchain via rustup …'
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain stable
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi
    ok "toolchain: $(cargo --version)"

    # crate dependencies from Cargo.toml / Cargo.lock
    info 'fetching cargo packages (all crate dependencies) …'
    (cd "${ROOT_DIR}" && cargo fetch --locked) \
        || (cd "${ROOT_DIR}" && cargo fetch) \
        || die 'cargo fetch failed'
    ok 'cargo packages installed'
}

# ── main ─────────────────────────────────────────────────────────────────────

DO_DATA=1
DO_CARGO=1
DO_ASNS=0
case "${1:-}" in
    '')                  ;;
    --data-only)         DO_CARGO=0 ;;
    --asns-only)         DO_DATA=0; DO_CARGO=0; DO_ASNS=1 ;;
    --cargo-only)        DO_DATA=0 ;;
    -h|--help)           usage; exit 0 ;;
    *)                   die "unknown option: ${1} (try --help)" ;;
esac

echo '============================================================================='
echo ' Quayel Gateway — setup'
echo '============================================================================='

[[ "${DO_DATA}" -eq 1 ]]  && setup_datasets
[[ "${DO_ASNS}" -eq 1 ]]  && refresh_asn_lists
[[ "${DO_CARGO}" -eq 1 ]] && setup_cargo

echo
ok 'setup complete'
if [[ "${DO_DATA}" -eq 1 || "${DO_ASNS}" -eq 1 ]]; then
    echo
    info 'datasets in src/data/:'
    ls -lh "${DATA_DIR}" | tail -n +2
fi
if [[ "${DO_CARGO}" -eq 1 ]]; then
    echo
    info 'next: cargo build --release && ./target/release/quayel-gateway config.demo.json'
fi
