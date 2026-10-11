#!/usr/bin/env bash
# Build a Debian/Ubuntu package from an already-built release binary.
#
#     packaging/build-deb.sh <binary> <version> <arch> [out-dir]
#     packaging/build-deb.sh target/release/quayel-gateway 0.2.0 amd64 dist
#
# <arch> is a Debian architecture: amd64 or arm64.
# Writes <out-dir>/quayel-gateway_<version>_<arch>.deb (out-dir defaults to dist).
# Needs only dpkg-deb, which every Debian/Ubuntu system has.

set -euo pipefail

if [ $# -lt 3 ]; then
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

binary="$1"
version="${2#v}"
arch="$3"
out_dir="${4:-dist}"

repo="$(cd "$(dirname "$0")/.." && pwd)"
src="$repo/packaging/deb"
pkg="quayel-gateway_${version}_${arch}"

[ -x "$binary" ] || { echo "Error: $binary is not an executable file" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/$pkg"

install -Dm0755 "$binary"                         "$root/usr/bin/quayel-gateway"
install -Dm0644 "$src/config.json"                "$root/etc/quayel-gateway/config.json"
install -Dm0644 "$src/quayel-gateway.service"     "$root/lib/systemd/system/quayel-gateway.service"
install -Dm0644 "$src/quayel-gateway.logrotate"   "$root/etc/logrotate.d/quayel-gateway"
install -Dm0644 "$repo/examples/config.demo.json" "$root/usr/share/doc/quayel-gateway/examples/config.demo.json"
install -Dm0644 "$repo/examples/config.all-rules.json" "$root/usr/share/doc/quayel-gateway/examples/config.all-rules.json"
install -Dm0644 "$repo/LICENSE"                   "$root/usr/share/doc/quayel-gateway/copyright"
install -Dm0644 "$repo/NOTICE"                    "$root/usr/share/doc/quayel-gateway/NOTICE"
install -Dm0644 "$repo/README.md"                 "$root/usr/share/doc/quayel-gateway/README.md"

mkdir -p "$root/DEBIAN"
for script in postinst prerm postrm; do
    install -m0755 "$src/$script" "$root/DEBIAN/$script"
done

cat > "$root/DEBIAN/conffiles" <<'EOF'
/etc/quayel-gateway/config.json
/etc/logrotate.d/quayel-gateway
EOF

installed_kb="$(du -sk "$root" | cut -f1)"

cat > "$root/DEBIAN/control" <<EOF
Package: quayel-gateway
Version: ${version}
Architecture: ${arch}
Maintainer: Quayel <noreply@quayel.com>
Installed-Size: ${installed_kb}
Depends: libc6 (>= 2.35), libgcc-s1, adduser
Recommends: ca-certificates, logrotate
Section: net
Priority: optional
Homepage: https://github.com/quayel/Quayel-Gateway
Description: High-performance API gateway built on Cloudflare Pingora
 Quayel Gateway is a reverse proxy and API gateway with built-in IP
 intelligence (country, ASN, VPN, Tor, proxy and datacenter detection),
 firewall rules, rate limiting, caching, load balancing and automatic
 Let's Encrypt certificates. The IP databases are embedded in the binary.
EOF

mkdir -p "$out_dir"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out_dir/$pkg.deb" >/dev/null
echo "$out_dir/$pkg.deb"
