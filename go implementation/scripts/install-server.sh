#!/usr/bin/env bash
# Install the gfk server on a Linux VPS as a systemd service.
#
# Usage:
#   sudo ./install-server.sh [path-to-gfk-binary]
#
# If no binary is given, the script builds one from source (needs Go 1.25+).
# It installs the binary to /usr/local/bin/gfk, a config to /etc/gfk/server.yaml
# (edit it before starting!), and a systemd unit gfk.service.
#
# The service runs with -dropRST so gfk installs its iptables RST-suppression rules
# on start and removes them on stop.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo)"; exit 1
fi

BIN_SRC="${1:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "$BIN_SRC" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "no binary given and Go is not installed; pass a prebuilt binary path"; exit 1
  fi
  echo "building gfk from source..."
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o /tmp/gfk ./cmd/gfk )
  BIN_SRC=/tmp/gfk
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/gfk
mkdir -p /etc/gfk
if [[ ! -f /etc/gfk/server.yaml ]]; then
  install -m 0644 "$REPO_ROOT/config/server.example.yaml" /etc/gfk/server.yaml
  echo "installed /etc/gfk/server.yaml (EDIT vps_ip, auth.key, backend_ip before starting)"
else
  echo "/etc/gfk/server.yaml already exists; leaving it untouched"
fi

cat > /etc/systemd/system/gfk.service <<'UNIT'
[Unit]
Description=gfk TCP-violation tunnel (server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gfk -config /etc/gfk/server.yaml -dropRST
Restart=always
RestartSec=3
# Raw sockets + iptables require root and these capabilities.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
echo
echo "Done. Next steps:"
echo "  1. edit /etc/gfk/server.yaml"
echo "  2. sudo systemctl enable --now gfk"
echo "  3. sudo journalctl -u gfk -f"
