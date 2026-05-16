#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Heimdall IDS — .deb builder
# Usage: ./build-deb.sh [version]
#   e.g. ./build-deb.sh 1.1.0
#
# Requirements: esbuild (npm install -g esbuild)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="${1:-1.4}"
PKG="heimdall-ids_${VERSION}_all"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="${ROOT}/packaging/build/${PKG}"

echo "▶  Building heimdall-ids v${VERSION}"

# ── 1. Check esbuild ──────────────────────────────────────────────────────────
if ! command -v esbuild >/dev/null 2>&1; then
  echo "ERROR: esbuild not found. Install with: npm install -g esbuild"; exit 1
fi

# ── 2. Compile all skins ──────────────────────────────────────────────────────
echo "▶  Compiling skins…"
FLAGS="--bundle --minify --jsx-factory=React.createElement --jsx-fragment=React.Fragment"

compile_skins() {
  local SRC_ROOT="$1"

  for skin in original chronicles mosaic seal; do
    src="${SRC_ROOT}/frontend/skins/${skin}/app.jsx"
    out="${SRC_ROOT}/frontend/skins/${skin}/app.js"
    printf "    %-12s " "$skin"
    esbuild "$src" $FLAGS \
      --outfile="$out" \
      --external:react --external:react-dom
    printf "%s KB\n" "$(du -k "$out" | cut -f1)"
  done
}

compile_skins "${ROOT}"

# ── 3. Create package tree ────────────────────────────────────────────────────
rm -rf "${BUILD}"
mkdir -p \
  "${BUILD}/DEBIAN" \
  "${BUILD}/opt/heimdall/frontend/skins/original" \
  "${BUILD}/opt/heimdall/frontend/skins/chronicles" \
  "${BUILD}/opt/heimdall/frontend/skins/mosaic" \
  "${BUILD}/opt/heimdall/frontend/skins/seal" \
  "${BUILD}/var/lib/heimdall" \
  "${BUILD}/var/log/heimdall" \
  "${BUILD}/lib/systemd/system" \
  "${BUILD}/etc/heimdall" \
  "${BUILD}/usr/bin"

# ── 4. DEBIAN control files ───────────────────────────────────────────────────
cat > "${BUILD}/DEBIAN/control" << EOF
Package: heimdall-ids
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Heimdall IDS <heimdall@localhost>
Description: Heimdall IDS Dashboard
 Real-time Suricata IDS dashboard with AI-powered alert explanation,
 skin system, threat intel, suppression rules, webhooks, RBAC,
 and multi-view analytics. License: AGPL-3.0.
EOF

cp "${ROOT}/packaging/postinst"       "${BUILD}/DEBIAN/postinst"
cp "${ROOT}/packaging/prerm"          "${BUILD}/DEBIAN/prerm"
cp "${ROOT}/packaging/postrm"         "${BUILD}/DEBIAN/postrm"
echo "/etc/heimdall/heimdall.conf" >  "${BUILD}/DEBIAN/conffiles"
chmod 755 "${BUILD}/DEBIAN/postinst" "${BUILD}/DEBIAN/prerm" "${BUILD}/DEBIAN/postrm"

# ── 5. Backend ────────────────────────────────────────────────────────────────
cp "${ROOT}/backend/"*.py "${BUILD}/opt/heimdall/"

# System-path config override
cat > "${BUILD}/opt/heimdall/config.py" << 'PYEOF'
"""Heimdall IDS Dashboard — Configuration (installed system paths)."""
from pathlib import Path

DEFAULT_EVE       = "/var/log/suricata/eve.json"
DEFAULT_PORT      = 8765
DEFAULT_HOST      = "0.0.0.0"
DEFAULT_DB        = Path("/var/lib/heimdall/events.db")
DEFAULT_DNS_DB    = Path("/var/lib/heimdall/dns.db")
DEFAULT_CONFIG_DB = Path("/var/lib/heimdall/config.db")

RETAIN_DAYS  = 90
PURGE_EVERY  = 3600
PING_EVERY   = 10
MAX_QUEUE    = 500
SESSION_TTL  = 86400 * 7
PBKDF2_ITERS = 260_000
FRONTEND_DIR = Path("/opt/heimdall/frontend")
PYEOF

# ── 6. Frontend ───────────────────────────────────────────────────────────────
cp "${ROOT}/frontend/react.min.js"    "${BUILD}/opt/heimdall/frontend/"
cp "${ROOT}/frontend/react-dom.min.js" "${BUILD}/opt/heimdall/frontend/"
sed "s/__HEIMDALL_VERSION__/${VERSION}/g" \
    "${ROOT}/frontend/index.html" > "${BUILD}/opt/heimdall/frontend/index.html"
cp "${ROOT}/frontend/login.html"      "${BUILD}/opt/heimdall/frontend/"
cp "${ROOT}/frontend/login.js"        "${BUILD}/opt/heimdall/frontend/"
sed "s/__HEIMDALL_VERSION__/${VERSION}/g" \
    "${ROOT}/frontend/skin-loader.js" > "${BUILD}/opt/heimdall/frontend/skin-loader.js"
mkdir -p "${BUILD}/opt/heimdall/frontend/fonts"
cp "${ROOT}/frontend/fonts/"*.woff2   "${BUILD}/opt/heimdall/frontend/fonts/"
cp "${ROOT}/frontend/fonts/fonts.css" "${BUILD}/opt/heimdall/frontend/fonts/"

for skin in original chronicles mosaic seal; do
  cp "${ROOT}/frontend/skins/${skin}/app.js"     "${BUILD}/opt/heimdall/frontend/skins/${skin}/"
  cp "${ROOT}/frontend/skins/${skin}/styles.css" "${BUILD}/opt/heimdall/frontend/skins/${skin}/"
done

# ── 7. systemd + config ───────────────────────────────────────────────────────
cp "${ROOT}/packaging/heimdall.service" "${BUILD}/lib/systemd/system/heimdall.service"

cat > "${BUILD}/etc/heimdall/heimdall.conf" << 'CONF'
# Heimdall IDS Dashboard — Configuration
# Edit then run: systemctl restart heimdall
#--eve /var/log/suricata/eve.json
#--port 8765
#--retain-days 90
#--skin original

# AI Explanation (optional — can also be set via the UI)
# Supported providers: openai | anthropic | deepseek
#--ai-provider openai
#--ai-key sk-your-api-key-here
CONF

# ── 8. CLI wrapper ────────────────────────────────────────────────────────────
cat > "${BUILD}/usr/bin/heimdall" << 'WRAPPER'
#!/bin/sh
exec /usr/bin/python3 /opt/heimdall/server.py "$@"
WRAPPER
chmod 755 "${BUILD}/usr/bin/heimdall"
chmod 755 "${BUILD}/var/lib/heimdall" "${BUILD}/var/log/heimdall" "${BUILD}/etc/heimdall"

# ── 9. Build ──────────────────────────────────────────────────────────────────
mkdir -p "${ROOT}/packaging/build"
dpkg-deb --build --root-owner-group \
  "${BUILD}" \
  "${ROOT}/packaging/build/heimdall-ids_${VERSION}_all.deb"

echo ""
echo "✓  Built: packaging/build/heimdall-ids_${VERSION}_all.deb"
echo "   Size:  $(du -sh "${ROOT}/packaging/build/heimdall-ids_${VERSION}_all.deb" | cut -f1)"
echo ""
echo "   Install: sudo apt install ./packaging/build/heimdall-ids_${VERSION}_all.deb"

# ── 10. AI-free build ─────────────────────────────────────────────────────────
echo ""
echo "▶  Building AI-free variant (heimdall-ids-noai)…"

NOAI_DIR="/tmp/heimdall-noai-src"
rm -rf "${NOAI_DIR}"

python3 "${ROOT}/strip-ai.py" "${ROOT}" "${NOAI_DIR}"

# Compile AI-free skins with content-hash filenames
echo "▶  Compiling AI-free skins…"
compile_skins "${NOAI_DIR}"

NOAI_PKG="heimdall-ids-noai_${VERSION}_all"
NOAI_BUILD="${ROOT}/packaging/build/${NOAI_PKG}"
rm -rf "${NOAI_BUILD}"
mkdir -p \
  "${NOAI_BUILD}/DEBIAN" \
  "${NOAI_BUILD}/opt/heimdall/frontend/skins/original" \
  "${NOAI_BUILD}/opt/heimdall/frontend/skins/chronicles" \
  "${NOAI_BUILD}/opt/heimdall/frontend/skins/mosaic" \
  "${NOAI_BUILD}/opt/heimdall/frontend/skins/seal" \
  "${NOAI_BUILD}/var/lib/heimdall" \
  "${NOAI_BUILD}/var/log/heimdall" \
  "${NOAI_BUILD}/lib/systemd/system" \
  "${NOAI_BUILD}/etc/heimdall" \
  "${NOAI_BUILD}/usr/bin"

cat > "${NOAI_BUILD}/DEBIAN/control" << EOF
Package: heimdall-ids-noai
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Heimdall IDS <heimdall@localhost>
Description: Heimdall IDS Dashboard (AI-free build)
 Real-time Suricata IDS dashboard with skin system, threat intel,
 suppression rules, webhooks, RBAC, and multi-view analytics.
 AI Explain feature is not included in this build. License: AGPL-3.0.
EOF

cp "${NOAI_DIR}/packaging/postinst"       "${NOAI_BUILD}/DEBIAN/postinst"
cp "${NOAI_DIR}/packaging/prerm"          "${NOAI_BUILD}/DEBIAN/prerm"
cp "${NOAI_DIR}/packaging/postrm"         "${NOAI_BUILD}/DEBIAN/postrm"
echo "/etc/heimdall/heimdall.conf"      >  "${NOAI_BUILD}/DEBIAN/conffiles"
chmod 755 "${NOAI_BUILD}/DEBIAN/postinst" "${NOAI_BUILD}/DEBIAN/prerm" "${NOAI_BUILD}/DEBIAN/postrm"

cp "${NOAI_DIR}/backend/"*.py "${NOAI_BUILD}/opt/heimdall/"

cat > "${NOAI_BUILD}/opt/heimdall/config.py" << 'PYEOF'
"""Heimdall IDS Dashboard — Configuration (installed system paths)."""
from pathlib import Path

DEFAULT_EVE       = "/var/log/suricata/eve.json"
DEFAULT_PORT      = 8765
DEFAULT_HOST      = "0.0.0.0"
DEFAULT_DB        = Path("/var/lib/heimdall/events.db")
DEFAULT_DNS_DB    = Path("/var/lib/heimdall/dns.db")
DEFAULT_CONFIG_DB = Path("/var/lib/heimdall/config.db")

RETAIN_DAYS  = 90
PURGE_EVERY  = 3600
PING_EVERY   = 10
MAX_QUEUE    = 500
SESSION_TTL  = 86400 * 7
PBKDF2_ITERS = 260_000
FRONTEND_DIR = Path("/opt/heimdall/frontend")
PYEOF

cp "${NOAI_DIR}/frontend/react.min.js"    "${NOAI_BUILD}/opt/heimdall/frontend/"
cp "${NOAI_DIR}/frontend/react-dom.min.js" "${NOAI_BUILD}/opt/heimdall/frontend/"
sed "s/__HEIMDALL_VERSION__/${VERSION}/g" \
    "${NOAI_DIR}/frontend/index.html" > "${NOAI_BUILD}/opt/heimdall/frontend/index.html"
cp "${NOAI_DIR}/frontend/login.html"      "${NOAI_BUILD}/opt/heimdall/frontend/"
cp "${NOAI_DIR}/frontend/login.js"        "${NOAI_BUILD}/opt/heimdall/frontend/"
sed "s/__HEIMDALL_VERSION__/${VERSION}/g" \
    "${NOAI_DIR}/frontend/skin-loader.js" > "${NOAI_BUILD}/opt/heimdall/frontend/skin-loader.js"
mkdir -p "${NOAI_BUILD}/opt/heimdall/frontend/fonts"
cp "${NOAI_DIR}/frontend/fonts/"*.woff2   "${NOAI_BUILD}/opt/heimdall/frontend/fonts/"
cp "${NOAI_DIR}/frontend/fonts/fonts.css" "${NOAI_BUILD}/opt/heimdall/frontend/fonts/"

for skin in original chronicles mosaic seal; do
  cp "${NOAI_DIR}/frontend/skins/${skin}/app.js"      "${NOAI_BUILD}/opt/heimdall/frontend/skins/${skin}/"
  cp "${NOAI_DIR}/frontend/skins/${skin}/styles.css"  "${NOAI_BUILD}/opt/heimdall/frontend/skins/${skin}/"
done

cp "${NOAI_DIR}/packaging/heimdall.service" "${NOAI_BUILD}/lib/systemd/system/heimdall.service"

cat > "${NOAI_BUILD}/etc/heimdall/heimdall.conf" << 'CONF'
# Heimdall IDS Dashboard (AI-free build) — Configuration
# Edit then run: systemctl restart heimdall
#--eve /var/log/suricata/eve.json
#--port 8765
#--retain-days 90
#--skin original
CONF

cat > "${NOAI_BUILD}/usr/bin/heimdall" << 'WRAPPER'
#!/bin/sh
exec /usr/bin/python3 /opt/heimdall/server.py "$@"
WRAPPER
chmod 755 "${NOAI_BUILD}/usr/bin/heimdall"
chmod 755 "${NOAI_BUILD}/var/lib/heimdall" "${NOAI_BUILD}/var/log/heimdall" "${NOAI_BUILD}/etc/heimdall"

dpkg-deb --build --root-owner-group \
  "${NOAI_BUILD}" \
  "${ROOT}/packaging/build/heimdall-ids-noai_${VERSION}_all.deb"

echo ""
echo "✓  Built: packaging/build/heimdall-ids-noai_${VERSION}_all.deb"
echo "   Size:  $(du -sh "${ROOT}/packaging/build/heimdall-ids-noai_${VERSION}_all.deb" | cut -f1)"
echo ""
echo "   Install: sudo apt install ./packaging/build/heimdall-ids-noai_${VERSION}_all.deb"

# Cleanup intermediate noai source dir
rm -rf "${NOAI_DIR}"
