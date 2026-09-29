#!/usr/bin/env bash
# One-command mcvpn server install (Linux x86_64/arm64 VPS).
#   curl -fsSL https://raw.githubusercontent.com/neboysa65-lab/mc/main/scripts/install.sh | sudo bash
set -euo pipefail

REPO="neboysa65-lab/mc"
BASE="https://github.com/$REPO/releases/latest/download"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/mcvpn"
CONF="$CONF_DIR/server.toml"
SERVICE="$CONF_DIR/mcvpn.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo bash)" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) PKG="mcvpn-server-linux-amd64.tar.gz" ;;
  aarch64|arm64) PKG="mcvpn-server-linux-arm64.tar.gz" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo "==> downloading mcvpn-server ($ARCH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$BASE/$PKG" -o "$TMP/mcvpn.tar.gz"
tar xzf "$TMP/mcvpn.tar.gz" -C "$TMP"
install -m 755 "$TMP/mcvpn-server" "$BIN_DIR/mcvpn-server"
command -v mcvpn-cli >/dev/null 2>&1 || install -m 755 "$TMP/mcvpn-cli" "$BIN_DIR/mcvpn-cli" 2>/dev/null || true

echo "==> config"
mkdir -p "$CONF_DIR"
if [ -f "$CONF" ]; then
  echo "    keeping existing $CONF"
else
  "$BIN_DIR/mcvpn-server" --init --config "$CONF"
  chmod 600 "$CONF"
fi
TOKEN="$(grep -oP '(?<=^token = ")[^"]+' "$CONF" | head -1)"

echo "==> systemd service"
cat > "$SERVICE" <<'EOF'
[Unit]
Description=mcvpn — Minecraft-camouflaged VPN server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mcvpn-server --config /etc/mcvpn/server.toml
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mcvpn

echo "==> firewall note"
echo "    make sure TCP 25565 is open on your provider firewall"

IP="$(curl -fsSL -4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
echo
echo "=============================================================="
echo " mcvpn is running. Connect clients with:"
echo "   server: $IP   port: 25565"
echo "   token:  $TOKEN"
echo " config: $CONF"
echo " logs:   journalctl -u mcvpn -f"
echo "=============================================================="
