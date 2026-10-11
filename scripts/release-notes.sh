#!/usr/bin/env bash
# Print the GitHub release notes for a tag: the matching CHANGELOG.md section,
# followed by download/install instructions and a link to the full diff.
#
#   scripts/release-notes.sh v0.2.0 [owner/repo] > notes.md
#
# Exits non-zero if CHANGELOG.md has no section for the version (or it is
# empty), so a release can't go out without notes.
set -euo pipefail

tag="${1:?usage: $0 <tag> [owner/repo]}"
repo="${2:-quayel/Quayel-Gateway}"
version="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"

section="$(awk -v ver="${version}" '
  /^## \[/ { if (found) exit; found = index($0, "## [" ver "]") == 1; next }
  /^\[[^]]+\]: / { next }
  found { print }
' "${root}/CHANGELOG.md")"

# Trim leading/trailing blank lines.
section="$(printf '%s\n' "${section}" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [ -z "${section//[[:space:]]/}" ]; then
  echo "error: CHANGELOG.md has no notes under '## [${version}]'" >&2
  exit 1
fi

prev="$(git -C "${root}" describe --tags --abbrev=0 --match 'v*' "${tag}^" 2>/dev/null || true)"
if [ -n "${prev}" ]; then
  full="https://github.com/${repo}/compare/${prev}...${tag}"
else
  full="https://github.com/${repo}/commits/${tag}"
fi

dl="https://github.com/${repo}/releases/download/${tag}"
image="ghcr.io/$(echo "${repo%%/*}" | tr '[:upper:]' '[:lower:]')/quayel-gateway"

cat <<EOF
${section}

## Install

**Debian / Ubuntu (.deb)**, Ubuntu 22.04+ or Debian 12+:

\`\`\`bash
curl -LO ${dl}/quayel-gateway_${version}_amd64.deb   # or _arm64.deb
sudo apt install ./quayel-gateway_${version}_amd64.deb
sudo nano /etc/quayel-gateway/config.json   # point it at your backend
sudo systemctl start quayel-gateway
\`\`\`

**Docker**, any Linux:

\`\`\`bash
docker run -d -p 80:80 -p 443:443 \\
  -v \$PWD/config.json:/etc/quayel-gateway/config.json:ro \\
  ${image}:${version}
\`\`\`

Without your own config the image starts the demo config on ports 8080/8443.

**Plain binary**, glibc 2.35+:

\`\`\`bash
curl -LO ${dl}/quayel-gateway-${tag}-x86_64-unknown-linux-gnu.tar.gz   # or aarch64-
tar xzf quayel-gateway-${tag}-x86_64-unknown-linux-gnu.tar.gz
\`\`\`

Verify downloads with \`sha256sum -c SHA256SUMS --ignore-missing\`.

**Full changelog:** ${full}
EOF
