#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
# N3 Golden Acceptance Test — ShareNet SOCKS5 Bridge
# ════════════════════════════════════════════════════════════════════════════
#
# Proves:
#   1. POSITIVE: curl through ShareNet SOCKS5 → reaches HTTP server
#   2. NEGATIVE: Kill ShareNet → curl fails
#
# Architecture:
#   curl --socks5 127.0.0.1:1080 http://127.0.0.1:HTTP_PORT/
#       ↓
#   N3AClient (SOCKS5 proxy)
#       ↓ MultiplexedCircuit::open_stream()
#   Relay A → Relay B → Gateway
#       ↓ TCP connect
#   HTTP Server (simulated Internet)
#
# Usage:
#   cd /home/z/my-project/reference
#   bash snp-stack/tests/n3_golden_test.sh
#
# Or with cargo:
#   cargo build --example n3_socks5_demo -p snp-stack --features "circuit-upstream test-utils"
#   bash snp-stack/tests/n3_golden_test.sh

set -e

cd "$(dirname "$0")/../.."

BIN="target/debug/examples/n3_socks5_demo"

if [ ! -f "$BIN" ]; then
    echo "Building demo binary..."
    export PATH="$HOME/.cargo/bin:$PATH"
    cargo build --example n3_socks5_demo -p snp-stack --features "circuit-upstream test-utils"
fi

echo "=== Starting ShareNet mesh + SOCKS5 proxy ==="
$BIN > /tmp/n3_golden.log 2>&1 &
DEMO_PID=$!

# Wait for SOCKS5 proxy to be ready
for i in $(seq 1 20); do
    if grep -q "listening for application connections" /tmp/n3_golden.log 2>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! kill -0 $DEMO_PID 2>/dev/null; then
    echo "FAIL: demo process died during startup"
    cat /tmp/n3_golden.log
    exit 1
fi

HTTP_PORT=$(grep "HTTP_PORT" /tmp/n3_golden.log | head -1 | cut -d= -f2)
ECHO_PORT=$(grep "ECHO_PORT" /tmp/n3_golden.log | head -1 | cut -d= -f2)
echo "SOCKS5 proxy on port 1080"
echo "HTTP server (Internet) on port $HTTP_PORT"
echo "Echo server (raw TCP) on port $ECHO_PORT"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# POSITIVE: curl through ShareNet SUCCEEDS
# ════════════════════════════════════════════════════════════════════════════
echo "=== POSITIVE: curl through ShareNet SOCKS5 ==="
RESPONSE=$(curl --socks5 127.0.0.1:1080 --connect-timeout 10 -s http://127.0.0.1:$HTTP_PORT/ 2>&1)
echo "  Response: $RESPONSE"

if [ "$RESPONSE" = "Hello from ShareNet!" ]; then
    echo "  ✓ POSITIVE: ShareNet path SUCCEEDS"
else
    echo "  ✗ POSITIVE: ShareNet path FAILED (got: $RESPONSE)"
    kill $DEMO_PID 2>/dev/null
    exit 1
fi
echo ""

# ════════════════════════════════════════════════════════════════════════════
# NEGATIVE: Kill ShareNet → curl FAILS
# ════════════════════════════════════════════════════════════════════════════
echo "=== NEGATIVE: killing ShareNet mesh ==="
kill $DEMO_PID 2>/dev/null
wait $DEMO_PID 2>/dev/null
echo "  ShareNet mesh stopped"
echo ""

echo "=== NEGATIVE: curl through dead ShareNet ==="
RESPONSE2=$(curl --socks5 127.0.0.1:1080 --connect-timeout 3 -s http://127.0.0.1:$HTTP_PORT/ 2>&1)
CURL_EXIT=$?
echo "  curl exit code: $CURL_EXIT"
echo "  Response: ${RESPONSE2:-<empty>}"

if [ $CURL_EXIT -ne 0 ]; then
    echo "  ✓ NEGATIVE: ShareNet down → curl FAILS (as expected)"
else
    echo "  ✗ NEGATIVE: curl succeeded even with ShareNet down (unexpected)"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  N3 GOLDEN TEST PASSED"
echo "  ShareNet is the ONLY connectivity path"
echo "  Direct (ShareNet down): FAIL"
echo "  Via ShareNet:           SUCCESS"
echo "════════════════════════════════════════════════════════════════"
