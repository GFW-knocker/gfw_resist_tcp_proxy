#!/usr/bin/env bash
# gfk — installer & service manager for the GFW-Knocker TCP-violation tunnel (server side, Linux).
#
# This script lives in the repo (go implementation/scripts/gfk.sh); only the
# compiled binaries are attached to the GitHub release. Install two ways:
#
#   # A) one-liner (pulls this script from the repo, binary from the release):
#   bash <(curl -fsSL 'https://raw.githubusercontent.com/GFW-knocker/gfw_resist_tcp_proxy/main/go%20implementation/scripts/gfk.sh') install
#
#   # B) if you already have this file on the VPS:
#   bash gfk.sh install
#
# Afterwards manage it with:  gfk {start|stop|restart|status|log|edit|update|uninstall}
set -euo pipefail

REPO="GFW-knocker/gfw_resist_tcp_proxy"
BRANCH="main"
GFK_DIR="/root/gfk"                 # binary + config live together here
BIN="$GFK_DIR/gfk"
CONFIG="$GFK_DIR/server.yaml"
SELF="/usr/local/bin/gfk"           # this script, runnable as `gfk`
SERVICE_NAME="gfk"
SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
# The script comes from the repo; %20 is the space in the "go implementation" dir.
SELF_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/go%20implementation/scripts/gfk.sh"
# Only the binaries are release assets.
bin_url() { echo "https://github.com/${REPO}/releases/latest/download/gfk-linux-$1"; }

grn=$'\e[32m'; yel=$'\e[33m'; red=$'\e[31m'; rst=$'\e[0m'
info() { echo "${grn}[gfk]${rst} $*"; }
warn() { echo "${yel}[gfk]${rst} $*"; }
err()  { echo "${red}[gfk]${rst} $*" >&2; }

need_root() { [ "$(id -u)" -eq 0 ] || { err "please run as root (e.g. sudo gfk $*)"; exit 1; }; }

fetch() { # fetch <url> <outfile>
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else err "need curl or wget installed"; exit 1; fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) err "unsupported architecture: $(uname -m) (only amd64/arm64 released)"; exit 1 ;;
  esac
}

download_binary() {
  local arch url; arch="$(detect_arch)"; url="$(bin_url "$arch")"
  info "downloading gfk binary ($arch) from GitHub release…"
  mkdir -p "$GFK_DIR"
  fetch "$url" "$BIN.tmp"
  chmod +x "$BIN.tmp"
  mv -f "$BIN.tmp" "$BIN"   # atomic; safe even while the service holds the old inode
  info "binary → $BIN"
}

install_self() {
  # Make this script invocable as `gfk`. If run from a real file, copy it;
  # if piped (curl|bash, a non-regular fd), re-download it from the release.
  local src="${BASH_SOURCE[0]:-}"
  if [ -n "$src" ] && [ -f "$src" ]; then
    cp "$src" "$SELF"
  else
    fetch "$SELF_URL" "$SELF"
  fi
  chmod +x "$SELF"
}

write_default_config() {
  if [ -f "$CONFIG" ]; then info "keeping existing $CONFIG"; return 0; fi
  info "writing default $CONFIG"
  cat > "$CONFIG" <<'YAML'
# gfk SERVER config (VPS). EDIT auth.key so it matches the client.
mode: server
transport: kcp
carrier:
  vps_ip: ""              # empty = auto-derive reply source IP (recommended)
  server_port: 45000      # must match client
  client_port: 40000      # must match client
  interface: ""           # auto-detect default NIC; set e.g. "eth0" if wrong
  mtu: 1400               # must match client
firewall:
  manage: ask             # the service passes -dropRST, so RST rules are applied automatically
auth:
  key: "CHANGE-ME-to-a-long-random-shared-secret"   # <-- EDIT (must match client)
kcp:
  nodelay: 1
  interval: 10
  resend: 2
  nc: 1
  sndwnd: 128             # size to your link speed (see client config profiles)
  rcvwnd: 128
  fec_data: 0
  fec_parity: 0
  stream_buffer: 0        # 0 = auto
  session_buffer: 0
server:
  backend_ip: "127.0.0.1" # where forwarded connections are dialed (your local xray)
  allow_socks5: false
  allowed_ports: []       # restrict destination ports, e.g. [443, 2096, 2052]. Empty = any.
log_level: info
YAML
}

write_service() {
  info "installing systemd service ($SERVICE)"
  cat > "$SERVICE" <<UNIT
[Unit]
Description=gfk GFW-resist TCP-violation tunnel (server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$GFK_DIR
ExecStart=$BIN -config $CONFIG -dropRST
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

cmd_install() {
  need_root install
  command -v systemctl >/dev/null 2>&1 || { err "systemd not found; this installer targets systemd"; exit 1; }
  download_binary
  write_default_config
  write_service
  install_self
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true   # start at boot
  systemctl restart "$SERVICE_NAME"
  echo
  info "installed & started (enabled at boot)."
  echo
  warn "NEXT: edit your config (set auth.key to match the client, pick backend_ip/ports), then restart:"
  echo "        gfk edit          # or:  nano $CONFIG"
  echo "        gfk restart"
  echo
  info "binary + config live together in:  $GFK_DIR"
  info "manage with:  gfk {start|stop|restart|status|log|edit|update|uninstall}"
}

cmd_update() {
  need_root update
  download_binary
  write_service
  systemctl restart "$SERVICE_NAME"
  info "updated to the latest binary and restarted (config preserved)."
}

cmd_uninstall() {
  need_root uninstall
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE"; systemctl daemon-reload 2>/dev/null || true
  rm -f "$SELF"
  info "service and 'gfk' command removed."
  if [ -d "$GFK_DIR" ]; then
    read -rp "Also delete $GFK_DIR (binary + config)? [y/N] " ans || ans=n
    case "${ans:-n}" in
      y|Y) rm -rf "$GFK_DIR"; info "removed $GFK_DIR" ;;
      *)   info "kept $GFK_DIR (config preserved)" ;;
    esac
  fi
}

cmd_edit() {
  need_root edit
  [ -f "$CONFIG" ] || { err "no config at $CONFIG — run 'gfk install' first"; exit 1; }
  "${EDITOR:-nano}" "$CONFIG"
  warn "run 'gfk restart' to apply changes."
}

usage() {
  cat <<EOF
gfk — GFW-resist tunnel (server) manager

usage: gfk <command>

  install      download binary, install boot-enabled service, start
  update       re-download latest binary and restart (keeps config)
  reinstall    alias for update
  start        start the service
  stop         stop the service
  restart      restart the service
  status       show service status
  log          follow the service log (Ctrl-C to exit)
  edit         edit $CONFIG, then remind to restart
  uninstall    stop, disable and remove the service (optionally the config)

files:
  binary   $BIN
  config   $CONFIG
EOF
}

case "${1:-menu}" in
  install)          cmd_install ;;
  update|reinstall) cmd_update ;;
  start)   need_root start;   systemctl start "$SERVICE_NAME";   systemctl --no-pager --lines=5 status "$SERVICE_NAME" || true ;;
  stop)    need_root stop;    systemctl stop "$SERVICE_NAME";    info "stopped." ;;
  restart) need_root restart; systemctl restart "$SERVICE_NAME"; info "restarted." ;;
  status)  systemctl --no-pager status "$SERVICE_NAME" || true ;;
  log)     journalctl -u "$SERVICE_NAME" -f -n 50 || true ;;
  edit)    cmd_edit ;;
  uninstall) cmd_uninstall ;;
  menu|help|-h|--help) usage ;;
  *) err "unknown command: $1"; echo; usage; exit 1 ;;
esac
