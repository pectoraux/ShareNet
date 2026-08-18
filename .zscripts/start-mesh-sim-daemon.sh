#!/bin/bash
set -e
PROJECT_DIR="/home/z/my-project"
MS_DIR="$PROJECT_DIR/mini-services/mesh-simulator"
LOG_FILE="$PROJECT_DIR/.zscripts/mini-service-mesh-simulator.log"
PID_FILE="$PROJECT_DIR/.zscripts/mini-service-mesh-simulator.pid"

cd "$MS_DIR"
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[mesh-sim] already running (PID $OLD_PID)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

nohup setsid bash -c 'cd "'"$MS_DIR"'" && exec /usr/local/bin/bun --hot run index.ts' >"$LOG_FILE" 2>&1 < /dev/null &
DAEMON_PID=$!
echo "$DAEMON_PID" > "$PID_FILE"
echo "[mesh-sim] launched (initial PID $DAEMON_PID) on port 3030"
for i in $(seq 1 10); do
  if curl -s -o /dev/null --max-time 1 http://127.0.0.1:3030/status 2>/dev/null; then
    echo "[mesh-sim] responding after ${i}s"
    break
  fi
  sleep 1
done
echo "[mesh-sim] log tail:"
tail -10 "$LOG_FILE" 2>/dev/null
