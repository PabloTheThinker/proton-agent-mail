#!/usr/bin/env bash
# One-command install: venv + package + MCP entry point. Does not sign in to Bridge.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VENV="${PAM_VENV:-$HOME/.venvs/proton-agent-mail}"
command -v protonmail-bridge >/dev/null || command -v proton-bridge >/dev/null || \
  echo "WARN: Proton Mail Bridge not found. Install it from https://proton.me/mail/bridge"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -e "$REPO"
echo "Installed. Next:"
echo "  1. $VENV/bin/proton-agent-mail setup   (then sign in yourself: protonmail-bridge -c -> login)"
echo "  2. Create ~/.config/proton-agent-mail/agent.env (see README 'MCP connector')"
echo "  3. nohup $REPO/scripts/mcp/supervise-bridge.sh >/dev/null 2>&1 &"
echo "     nohup env PAM_BIN=$VENV/bin/proton-agent-mail $REPO/scripts/mcp/supervise-api.sh >/dev/null 2>&1 &"
echo "  4. Register MCP command: $VENV/bin/proton-agent-mail-mcp"
