#!/usr/bin/env bash
# Install fwatcher sebagai service systemd.
# Jalankan dengan sudo dari direktori repo:  sudo bash systemd/install.sh
set -euo pipefail

BIN_SRC="${BIN_SRC:-./fwatcher-linux-amd64}"
BIN_DST="/usr/local/bin/fwatcher"
CONFIG_DIR="/etc/fwatcher"
CONFIG_SRC="${CONFIG_SRC:-./config.linux.yaml}"
CONFIG_DST="${CONFIG_DIR}/config.yaml"
LOG_DIR="/var/log/fwatcher"
STATE_DIR="/var/lib/fwatcher"
UNIT_SRC="./systemd/fwatcher.service"
UNIT_DST="/etc/systemd/system/fwatcher.service"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

[[ -f "$BIN_SRC" ]] || { echo "Binary not found: $BIN_SRC" >&2; exit 1; }
[[ -f "$CONFIG_SRC" ]] || { echo "Config not found: $CONFIG_SRC" >&2; exit 1; }
[[ -f "$UNIT_SRC" ]] || { echo "Unit not found: $UNIT_SRC" >&2; exit 1; }

install -m 0755 "$BIN_SRC" "$BIN_DST"
install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$LOG_DIR"
install -d -m 0755 "$STATE_DIR"

if [[ ! -f "$CONFIG_DST" ]]; then
  install -m 0644 "$CONFIG_SRC" "$CONFIG_DST"
  echo "Installed default config -> $CONFIG_DST  (edit me)"
else
  echo "Config already exists, leaving as-is: $CONFIG_DST"
fi

install -m 0644 "$UNIT_SRC" "$UNIT_DST"

systemctl daemon-reload
systemctl enable fwatcher.service
echo
echo "Done. Edit $CONFIG_DST then start the service:"
echo "  sudo systemctl start fwatcher"
echo "  sudo systemctl status fwatcher"
echo "  sudo tail -f /var/log/fwatcher/fwatcher.json"
