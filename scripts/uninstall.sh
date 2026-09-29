#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo bash)" >&2
  exit 1
fi
systemctl disable --now mcvpn 2>/dev/null || true
rm -f /etc/systemd/system/mcvpn.service /usr/local/bin/mcvpn-server /usr/local/bin/mcvpn-cli
systemctl daemon-reload
echo "Removed. (Config kept at /etc/mcvpn — remove manually if you like.)"
