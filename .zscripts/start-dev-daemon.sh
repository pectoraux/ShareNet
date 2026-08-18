#!/bin/bash
# ShareNet dev server daemon launcher.
# Uses the classic Unix double-fork to fully detach from the Bash tool's
# process group, so the Next.js dev server survives the originating
# bash invocation exiting.
#
# Usage: .zscripts/start-dev-daemon.sh
# Logs:  .zscripts/dev.log
# PID:   .zscripts/dev.pid

set -e

PROJECT_DIR="/home/z/my-project"
LOG_FILE="$PROJECT_DIR/.zscripts/dev.log"
PID_FILE="$PROJECT_DIR/.zscripts/dev.pid"
PORT="${PORT:-3000}"

cd "$PROJECT_DIR"

# Clean any stale lock
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[daemon] dev server already running (PID $OLD_PID), leaving it alone."
    exit 0
  fi
  rm -f "$PID_FILE"
fi

# Spawn a fully-detached process group.
# setsid + double-detach + redirect all std streams + ignore SIGHUP/SIGTERM.
nohup setsid bash -c '
  cd "'"$PROJECT_DIR"'"
  exec /home/z/my-project/node_modules/.bin/next dev -p '"$PORT"'
' >"$LOG_FILE" 2>&1 < /dev/null &

DAEMON_PID=$!
echo "$DAEMON_PID" > "$PID_FILE"
echo "[daemon] launched Next.js dev server (initial PID $DAEMON_PID) on port $PORT"
echo "[daemon] log: $LOG_FILE"

# Wait briefly so the caller sees whether it actually came up
for i in $(seq 1 15); do
  if curl -s -o /dev/null --max-time 1 "http://localhost:$PORT" 2>/dev/null; then
    echo "[daemon] server is responding after ${i}s"
    break
  fi
  sleep 1
done

# Show final state
if [ -f "$LOG_FILE" ]; then
  echo "[daemon] --- last 15 log lines ---"
  tail -15 "$LOG_FILE" 2>/dev/null || true
fi
