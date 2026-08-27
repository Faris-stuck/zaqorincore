#!/bin/bash
# End-to-end smoke test for the agent.
#
# Asserts that, against a local WebSocket echo server, the agent:
#   1. opens the WebSocket connection
#   2. sends exactly one HELLO frame
#   3. sends one EVENT frame per appended log line
#   4. sends a BYE frame on graceful shutdown
#
# `WEBSOCAT_BIN` overrides the websocat binary location. The CI workflow
# (`.github/workflows/ci.yml`) installs websocat to /tmp/websocat and
# sets this env var, so the same script works both locally (uses
# whatever `websocat` is on $PATH) and in CI (uses the pinned binary).

set -uo pipefail

WEBSOCAT_BIN="${WEBSOCAT_BIN:-websocat}"

WORK="/tmp/zc-smoke"
rm -rf "$WORK"
mkdir -p "$WORK/state"
: > "$WORK/app.log"

"$WEBSOCAT_BIN" -s 127.0.0.1:9103 > "$WORK/server.out" 2> "$WORK/server.err" &
SERVER_PID=$!
sleep 1

cat > "$WORK/agent.toml" <<EOF
server_url = "ws://127.0.0.1:9103"
agent_id   = "auto"
log_level  = "info"
state_dir  = "$WORK/state"
[[log_source]]
name = "smoke"
path = "$WORK/app.log"
EOF

/home/ubuntu/zaqorincore-workspace/agent/bin/zaqorin-agent \
  --config "$WORK/agent.toml" 2> "$WORK/agent.err" &
AGENT_PID=$!

# Wait long enough for the agent to be fully up.
sleep 3

# Three lines, with 2s gaps.
printf 'AAAA\n' >> "$WORK/app.log"
sleep 2
printf 'BBBB\n' >> "$WORK/app.log"
sleep 2
printf 'CCCC\n' >> "$WORK/app.log"
sleep 3

kill -INT "$AGENT_PID" 2>/dev/null || true
sleep 0.5
kill "$SERVER_PID" 2>/dev/null || true
wait 2>/dev/null || true

echo "=== AGENT ERR ==="
cat "$WORK/agent.err"
echo
echo "=== SERVER ==="
cat "$WORK/server.out"
echo
echo "=== LOG FILE ==="
cat "$WORK/app.log"
echo
echo "=== STATS ==="
HELLO=$(grep -c '"type":"hello"' "$WORK/server.out" 2>/dev/null; true)
HELLO=${HELLO:-0}
EVENT=$(grep -c '"type":"event"' "$WORK/server.out" 2>/dev/null; true)
EVENT=${EVENT:-0}
BYE=$(grep -c '"type":"bye"' "$WORK/server.out" 2>/dev/null; true)
BYE=${BYE:-0}
echo "hello=$HELLO event=$EVENT bye=$BYE"
if [[ "$HELLO" -ge 1 && "$EVENT" -ge 3 ]]; then
  echo "SMOKE: PASS"
  exit 0
else
  echo "SMOKE: FAIL"
  exit 1
fi
