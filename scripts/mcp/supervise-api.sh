#!/usr/bin/env bash
# nohup supervisor loop for the proton-agent-mail REST API (auto-restart, backoff). No systemd.
# Start:  nohup scripts/mcp/supervise-api.sh >/dev/null 2>&1 &
# Stop:   kill "$(cat ~/.local/state/pam/supervisor.pid)"
set -u
ENV_FILE="${PAM_ENV_FILE:-$HOME/.config/proton-agent-mail/agent.env}"
STATE="$HOME/.local/state/pam"; mkdir -p "$STATE"; chmod 700 "$STATE"
echo $$ > "$STATE/supervisor.pid"
[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE (promote draft after Bridge login)" >> "$STATE/supervisor.log"; exit 1; }
set -a; . "$ENV_FILE"; set +a
[ "${PROTON_AGENT_BIND:-127.0.0.1}" = "127.0.0.1" ] || { echo "refusing non-loopback bind" >> "$STATE/supervisor.log"; exit 1; }
trap 'kill "${child:-}" 2>/dev/null; exit 0' TERM INT
delay=2
while true; do
  start=$(date +%s)
  "${PAM_BIN:-proton-agent-mail}" serve >> "$STATE/api.log" 2>&1 & child=$!
  wait "$child"; rc=$?
  echo "$(date -Is) api exited rc=$rc; restart in ${delay}s" >> "$STATE/supervisor.log"
  [ $(( $(date +%s) - start )) -gt 60 ] && delay=2
  sleep "$delay"; delay=$(( delay < 60 ? delay * 2 : 60 ))
done
