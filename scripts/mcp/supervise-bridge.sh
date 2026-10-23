#!/usr/bin/env bash
# nohup restart loop for Proton Bridge --noninteractive. Stop: kill "$(cat ~/.local/state/pam/bridge-supervisor.pid)"
set -u
STATE="$HOME/.local/state/pam"; mkdir -p "$STATE"; chmod 700 "$STATE"; echo $$ > "$STATE/bridge-supervisor.pid"
trap 'kill "${child:-}" 2>/dev/null; pkill -f "bridge --noninteractive"; exit 0' TERM INT
delay=2
while true; do
  start=$(date +%s)
  "${BRIDGE_BIN:-protonmail-bridge}" --noninteractive >> "$STATE/bridge.log" 2>&1 & child=$!
  wait "$child"; rc=$?
  echo "$(date -Is) bridge exited rc=$rc; restart in ${delay}s" >> "$STATE/bridge-supervisor.log"
  [ $(( $(date +%s) - start )) -gt 60 ] && delay=2
  sleep "$delay"; delay=$(( delay < 60 ? delay * 2 : 60 ))
done
