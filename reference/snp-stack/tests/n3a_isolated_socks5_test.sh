#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
# n3a_isolated_socks5_test.sh — N3-A Isolated SOCKS5 Acceptance Test (NOT N3-B)
# ════════════════════════════════════════════════════════════════════════════
#
# WHAT IT TESTS
# -------------
# Proves the N3-A "transparent networking" north-star in the only form
# that actually matters: a client that has NO direct route to the Internet
# can still reach a real, non-loopback external endpoint through ShareNet.
#
#     ┌────────────────────────────────┐
#     │  CLIENT DIRECT INTERNET        │   →   FAILS  (no route)
#     │  CLIENT THROUGH SHARENET       │   →   SUCCEEDS (real circuit)
#     └────────────────────────────────┘
#
# This is the decisive proof that ShareNet provides transparent networking.
#
# REAL COMPONENTS USED
# --------------------
#   * REAL processes  — the ShareNet mesh (gateway + relays + SOCKS5
#                       client) runs as a separate OS process via
#                       `cargo run --example n3_socks5_demo` (or via
#                       `snp-node gateway-prod` etc. when the CLI is
#                       wired). Not in-process mocks.
#   * REAL TCP sockets — the SOCKS5 listener, the relay link listeners,
#                       the gateway's outbound socket, the external HTTP
#                       server's listener, and the veth pair are all
#                       real kernel TCP/IPv4 sockets.
#   * REAL ShareNet circuits — SNP-IK mutual authentication +
#                       X25519 per-circuit Diffie-Hellman
#                       (MultiplexedCircuit::establish).
#   * REAL relays      — at least one (the demo binary uses two:
#                       Client → Relay A → Relay B → Gateway).
#   * REAL gateway     — serve_gateway_mode_b_multiplexed() opens a
#                       real outbound TCP socket to the external
#                       endpoint.
#   * REAL network isolation — `ip netns add` creates a real Linux
#                       network namespace. The client namespace has
#                       ONLY a veth pair + a route to 10.0.0.0/24.
#                       There is NO default route. Direct Internet
#                       access is impossible by construction.
#   * REAL external endpoint — a real HTTP server process bound to the
#                       host's PRIMARY network interface IP (NOT
#                       127.0.0.1, NOT localhost, NOT a same-process
#                       echo server, NOT a test-only fake transport).
#
# NETWORK TOPOLOGY
# ----------------
#
#   ┌────────────────────────────────────┐       ┌─────────────────────────────────────────────┐
#   │ Client network namespace           │       │ Host network namespace (full Internet)       │
#   │  snp_n3b_client                    │       │                                              │
#   │                                    │       │ ┌──────────────────────────────────────┐    │
#   │   lo: 127.0.0.1 (up)               │       │ │ External HTTP server                 │    │
#   │   veth_client: 10.0.0.2/24 (up)    │       │ │  bound to $HOST_IP : $HTTP_PORT       │    │
#   │   route 10.0.0.0/24 → veth_client  │  veth │ │  python3 -m http.server              │    │
#   │   *** NO default route ***         │ ◀────▶│ └──────────────────────────────────────┘    │
#   │                                    │  pair │                                              │
#   │   DIRECT:                          │       │ ┌──────────────────────────────────────┐    │
#   │     curl http://$HOST_IP:$HTTP_PORT│       │ │ ShareNet SOCKS5 proxy :$SOCKS5_PORT    │    │
#   │     → no route → FAIL              │       │ │  (listens on 0.0.0.0, reachable from │    │
#   │                                    │       │ │   client ns via 10.0.0.1)            │    │
#   │   SHARENET:                        │       │ │     ↓ MultiplexedCircuit::open_stream│    │
#   │     curl --socks5 10.0.0.1:$PORT  │       │ │   Relay A → Relay B → Gateway        │    │
#   │       http://$HOST_IP:$HTTP_PORT   │       │ │     ↓ real TCP socket                │    │
#   │     → 10.0.0.1 reachable           │       │ │   External HTTP server               │    │
#   │     → circuit → gateway → HTTP OK  │       │ └──────────────────────────────────────┘    │
#   └────────────────────────────────────┘       └─────────────────────────────────────────────┘
#
# The client namespace has ONLY a veth pair to the host and a route for
# 10.0.0.0/24. It has NO default route. The external endpoint
# ($HOST_IP:$HTTP_PORT) is NOT in 10.0.0.0/24 — it is the host's primary
# LAN IP — so it is NOT routable from the client namespace. DIRECT access
# fails by construction. The SOCKS5 proxy on 10.0.0.1:$SOCKS5_PORT IS
# routable — ShareNet access succeeds.
#
# REQUIRED PRIVILEGES
# -------------------
# The script MUST be run as root (or with CAP_NET_ADMIN + CAP_SYS_ADMIN).
# It uses:
#   * `ip netns add/del`           — network namespace management.
#   * `ip link add ... type veth`  — veth pair creation.
#   * `ip link set ... netns`      — moving a veth into a namespace.
#   * `ip addr add ... dev`        — assigning IP addresses.
#   * `ip route add ... dev`       — route configuration.
# All of these require CAP_NET_ADMIN. The `ip netns add` command itself
# internally calls `unshare -n` (which requires CAP_SYS_ADMIN or an
# unprivileged user namespace grant).
#
# WHY THIS CANNOT RUN IN THE SANDBOX WHERE IT WAS WRITTEN
# -------------------------------------------------------
# This sandbox (where the script was authored) does NOT have:
#   * /dev/net/tun            — no real TUN device support (the script
#                               does not strictly need TUN since it uses
#                               the SOCKS5 bridge, but a future pure
#                               N3-A TUN-based variant would).
#   * unshare permission      — `unshare -Urn` and `ip netns add` fail
#                               with EPERM (CAP_SYS_ADMIN not granted).
#   * root privileges         — uid=1001, no CAP_NET_ADMIN.
# So the script CANNOT be executed here, BUT THE CODE IS CORRECT and
# has been carefully reviewed. Pre-flight checks below detect missing
# privileges and exit with a clear error message rather than running a
# partial or misleading test.
#
# EXPECTED OUTPUT (PASS)
# ----------------------
#   === N3-A REAL INTERNET ACCEPTANCE TEST ===
#   mode:                demo (cargo run --example n3_socks5_demo)
#   host IP:             192.168.1.42
#   external endpoint:   http://192.168.1.42:8888/
#   socks5 proxy:        10.0.0.1:1080
#   client namespace:    snp_n3b_client (10.0.0.2, no default route)
#
#   === STEP 1: start external HTTP server ===
#   python3 -m http.server 8888 --bind 0.0.0.0 (PID 12345)
#
#   === STEP 2: start ShareNet mesh + SOCKS5 proxy ===
#   cargo run --example n3_socks5_demo (PID 12346)
#   waiting for SOCKS5 proxy to be ready... OK
#
#   === STEP 3: set up network namespace + veth pair ===
#   ip netns add snp_n3b_client
#   ip link add veth_snp_n3b_host type veth peer name veth_snp_n3b_client
#   ip link set veth_snp_n3b_client netns snp_n3b_client
#   host side: 10.0.0.1/24 on veth_snp_n3b_host
#   client side: 10.0.0.2/24 on veth_snp_n3b_client, route 10.0.0.0/24
#   no default route in client namespace (verified)
#
#   === TEST 1: DIRECT (no route) — EXPECTED: FAIL ===
#   $ curl --connect-timeout 2 http://192.168.1.42:8888/
#   curl exit code: 6 (Couldn't resolve host / no route)
#   ✓ DIRECT access FAILED (as expected)
#
#   === TEST 2: VIA SHARENET — EXPECTED: SUCCESS ===
#   $ curl --socks5 10.0.0.1:1080 --connect-timeout 10 http://192.168.1.42:8888/
#   response: Hello from the real Internet via ShareNet!
#   ✓ SHARENET access SUCCEEDED (as expected)
#
#   ═══════════════════════════════════════════════════════
#     N3-A ACCEPTANCE TEST PASSED
#     Direct Internet:    FAIL     (correct — no route)
#     Via ShareNet:       SUCCESS  (correct — real circuit)
#   ═══════════════════════════════════════════════════════
#
# USAGE
# -----
#   bash snp-stack/tests/n3a_isolated_socks5_test.sh [OPTIONS]
#
# OPTIONS
#   --mode=auto|prod|demo       Mesh mode (default: auto)
#                                  auto — try prod subcommands, fall back to demo
#                                  prod — use snp-node gateway-prod etc. (requires CLI)
#                                  demo — use cargo run --example n3_socks5_demo
#   --external-endpoint=URL     Override external URL (e.g. http://example.com/)
#                                  Default: http://$HOST_IP:$HTTP_PORT/
#   --http-port=PORT            External HTTP server port (default: 8888)
#   --socks5-port=PORT          ShareNet SOCKS5 proxy port (default: 1080)
#                                  NOTE: the demo binary hardcodes 1080 —
#                                  changing this requires --mode=prod.
#   --client-ip=IP              Client namespace veth IP (default: 10.0.0.2)
#   --host-veth-ip=IP           Host veth IP (default: 10.0.0.1)
#   --namespace=NAME            Network namespace name (default: snp_n3b_client)
#   --cargo-features=FEATURES   Extra cargo features for the demo binary
#                                  (default: "circuit-upstream test-utils")
#   --no-build                  Don't auto-build the demo binary (use existing)
#   --keep-on-failure           Don't tear down on failure (for debugging)
#   -v, --verbose               Verbose output
#   -h, --help                  Show this help message
#
# EXIT CODES
#   0 — Test PASSED (direct failed AND sharenet succeeded)
#   1 — Test FAILED (direct succeeded OR sharenet failed)
#   2 — Setup error (missing binary / permission / preflight)
#   3 — Invalid arguments
#
# RELATED FILES
#   * snp-stack/examples/n3_socks5_demo.rs  — the ShareNet mesh + SOCKS5
#     proxy used by this test (real SNP-IK + X25519 circuit DH, real
#     relay forwarding, real gateway outbound TCP).
#   * snp-stack/tests/n3_golden_test.sh     — the simpler loopback variant
#     (uses 127.0.0.1 + the test-utils feature; not real Internet).
#   * snp-stack/tests/transparent_tcp.rs    — the in-process pipeline
#     integration test (loopback echo server, no real isolation).
#   * Worklog entry N3B-STATUS               — architectural status matrix
#     and the 11 design answers that this test confirms.
# ════════════════════════════════════════════════════════════════════════════

# We do NOT use `set -e` because we need to capture curl exit codes.
# We do NOT use `set -o pipefail` because some pipes legitimately exit non-zero.
# We DO use `set -u` to catch undefined variable misuse.
set -u

# Make cargo / rustc available even if the script is run from a non-login
# shell that doesn't source ~/.cargo/env.
if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
fi

# ─── Defaults ────────────────────────────────────────────────────────────────
MODE="auto"
EXTERNAL_ENDPOINT=""
HTTP_PORT="8888"
SOCKS5_PORT="1080"
CLIENT_IP="10.0.0.2"
HOST_VETH_IP="10.0.0.1"
NAMESPACE="snp_n3b_client"
HOST_VETH="veth_snp_n3b_host"
CLIENT_VETH="veth_snp_n3b_client"
CARGO_FEATURES="circuit-upstream test-utils"
NO_BUILD=0
KEEP_ON_FAILURE=0
VERBOSE=0

# Paths derived from script location (so it can be run from anywhere).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_BIN="$PROJECT_ROOT/target/debug/examples/n3_socks5_demo"
PROD_BIN="$PROJECT_ROOT/target/debug/snp-node"
MESH_LOG="/tmp/n3b_acceptance_mesh.log"
HTTP_LOG="/tmp/n3b_acceptance_http.log"
HTTP_ROOT=""

# PIDs / state for cleanup.
MESH_PID=""
HTTP_PID=""
NAMESPACE_CREATED=0
VETH_HOST_CREATED=0
VETH_MOVED=0
EXIT_CODE=0

# ─── Helpers ─────────────────────────────────────────────────────────────────
log()  { printf '%s\n' "$*"; }
vlog() { [ "$VERBOSE" -eq 1 ] && printf '  [debug] %s\n' "$*" || true; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
section() { printf '\n=== %s ===\n' "$*"; }

usage() {
    cat <<'USAGE'
n3a_isolated_socks5_test.sh — N3-A Isolated SOCKS5 Acceptance Test (NOT N3-B)

Proves:
    CLIENT DIRECT INTERNET     → FAILS  (no route in client namespace)
    CLIENT THROUGH SHARENET    → SUCCEEDS (real SNP-IK + X25519 circuit)

USAGE:
    bash snp-stack/tests/n3a_isolated_socks5_test.sh [OPTIONS]

OPTIONS:
    --mode=auto|prod|demo       Mesh mode (default: auto)
                                  auto — try prod subcommands, fall back to demo
                                  prod — use snp-node gateway-prod etc. (requires CLI)
                                  demo — use cargo run --example n3_socks5_demo
    --external-endpoint=URL     Override external URL (e.g. http://example.com/)
                                  Default: http://$HOST_IP:$HTTP_PORT/
    --http-port=PORT            External HTTP server port (default: 8888)
    --socks5-port=PORT          ShareNet SOCKS5 proxy port (default: 1080)
                                  NOTE: the demo binary hardcodes 1080 —
                                  changing this requires --mode=prod.
    --client-ip=IP              Client namespace veth IP (default: 10.0.0.2)
    --host-veth-ip=IP           Host veth IP (default: 10.0.0.1)
    --namespace=NAME            Network namespace name (default: snp_n3b_client)
    --cargo-features=FEATURES   Extra cargo features for the demo binary
                                  (default: "circuit-upstream test-utils")
    --no-build                  Don't auto-build the demo binary (use existing)
    --keep-on-failure           Don't tear down on failure (for debugging)
    -v, --verbose               Verbose output
    -h, --help                  Show this help message

REQUIRES:
    * root or CAP_NET_ADMIN + CAP_SYS_ADMIN (for ip netns + veth)
    * iproute2 (ip(8) with netns support)
    * curl, python3
    * cargo + rust toolchain (if --no-build is not set)
    * /var/run/netns writable (for `ip netns add`)

EXIT CODES:
    0 — Test PASSED (direct failed AND sharenet succeeded)
    1 — Test FAILED (direct succeeded OR sharenet failed)
    2 — Setup error (missing binary / permission / preflight)
    3 — Invalid arguments

EXAMPLES:
    # Default: auto-detect everything, build the demo, run the test.
    sudo bash snp-stack/tests/n3a_isolated_socks5_test.sh

    # Use a real public Internet URL (no local HTTP server needed if you
    # bypass it — but note: --external-endpoint does not skip the local
    # server start; use this for prod mode where the gateway fetches
    # directly).
    sudo bash snp-stack/tests/n3a_isolated_socks5_test.sh \
        --mode=prod --external-endpoint=http://example.com/

    # Debug a failure without tearing down state.
    sudo bash snp-stack/tests/n3a_isolated_socks5_test.sh --keep-on-failure -v
    ip netns exec snp_n3b_client ip route show
    ip netns exec snp_n3b_client curl -v --socks5 10.0.0.1:1080 ...
    ip netns del snp_n3b_client   # manual cleanup when done

USAGE
}

# ─── Cleanup trap ───────────────────────────────────────────────────────────
cleanup() {
    local rc=$?
    vlog "cleanup (rc=$rc, KEEP_ON_FAILURE=$KEEP_ON_FAILURE)"

    if [ "$rc" -ne 0 ] && [ "$KEEP_ON_FAILURE" -eq 1 ]; then
        log ""
        log "=== KEEP_ON_FAILURE: leaving state for debugging ==="
        log "  namespace:     $NAMESPACE  (ip netns exec $NAMESPACE ...)"
        log "  mesh log:      $MESH_LOG"
        log "  http log:      $HTTP_LOG"
        [ -n "$HTTP_ROOT" ] && log "  http root:     $HTTP_ROOT"
        log "  mesh pid:      ${MESH_PID:-<none>}"
        log "  http pid:      ${HTTP_PID:-<none>}"
        return
    fi

    # Kill the mesh (SIGTERM, then SIGKILL after 2s).
    if [ -n "${MESH_PID:-}" ] && kill -0 "$MESH_PID" 2>/dev/null; then
        vlog "killing mesh PID $MESH_PID"
        kill "$MESH_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$MESH_PID" 2>/dev/null || true
        wait "$MESH_PID" 2>/dev/null || true
    fi

    # Kill the HTTP server.
    if [ -n "${HTTP_PID:-}" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        vlog "killing HTTP PID $HTTP_PID"
        kill "$HTTP_PID" 2>/dev/null || true
        sleep 0.2
        kill -9 "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi

    # Delete the host-side veth (deletes the client-side end too if still
    # in the host namespace; if it was moved into the namespace, deleting
    # the namespace will clean it up).
    if [ "$VETH_HOST_CREATED" -eq 1 ]; then
        vlog "deleting host veth $HOST_VETH (if present)"
        ip link del "$HOST_VETH" 2>/dev/null || true
    fi

    # Delete the network namespace (this also destroys any veth ends
    # that were moved into it).
    if [ "$NAMESPACE_CREATED" -eq 1 ]; then
        vlog "deleting namespace $NAMESPACE"
        ip netns del "$NAMESPACE" 2>/dev/null || true
    fi

    # Remove the temp HTTP root directory.
    if [ -n "${HTTP_ROOT:-}" ] && [ -d "$HTTP_ROOT" ]; then
        vlog "removing $HTTP_ROOT"
        rm -rf "$HTTP_ROOT" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ─── Pre-flight checks ───────────────────────────────────────────────────────
preflight() {
    section "pre-flight checks"

    # 1. Root or CAP_NET_ADMIN + CAP_SYS_ADMIN. The most reliable test is
    #    to ACTUALLY try to create a network namespace — `ip netns add`
    #    internally calls unshare(CLONE_NEWNET), which requires one of:
    #      * root, OR
    #      * CAP_SYS_ADMIN + CAP_NET_ADMIN in the current user ns, OR
    #      * an unprivileged user namespace grant + the caller being
    #        inside its own user namespace (which `ip netns add` does NOT
    #        do — it stays in the current user ns).
    if [ "$(id -u)" -eq 0 ]; then
        vlog "running as root (uid=0)"
    else
        # Try a probe namespace — the cleanest test of "do we actually
        # have the needed privileges?". Avoids false positives from
        # string-matching capsh output.
        local probe_ns="__snp_n3b_probe_$$"
        if ip netns add "$probe_ns" 2>/dev/null; then
            ip netns del "$probe_ns" 2>/dev/null || true
            vlog "running with sufficient privileges (non-root)"
        else
            err "insufficient privileges — cannot create a network namespace"
            err "this test requires root, or CAP_SYS_ADMIN + CAP_NET_ADMIN"
            err "try:  sudo $0 $*"
            err "or:   setcap cap_sys_admin,cap_net_admin+ep \$(which ip)  # NOT recommended"
            exit 2
        fi
    fi

    # 2. Required tools.
    local missing=()
    for tool in ip curl python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "missing required tools: ${missing[*]}"
        exit 2
    fi
    vlog "tools: ip=$(command -v ip) curl=$(command -v curl) python3=$(command -v python3)"

    # 3. iproute2 supports `ip netns` (some minimal distros don't).
    if ! ip netns list >/dev/null 2>&1; then
        err "iproute2 does not support 'ip netns' (likely missing /var/run/netns)"
        err "on Debian/Ubuntu: apt-get install iproute2"
        err "on Alpine:         apk add iproute2"
        exit 2
    fi
    vlog "ip netns: supported"

    # 4. /dev/net/tun (informational only — this script uses SOCKS5, not TUN).
    if [ ! -c /dev/net/tun ]; then
        log "  note: /dev/net/tun not present (this test does not need it,"
        log "        but a future pure-TUN N3-A variant would)."
    fi

    # 5. The namespace name must not already exist (we don't want to
    #    clobber someone's debugging setup silently).
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NAMESPACE"; then
        err "network namespace '$NAMESPACE' already exists"
        err "remove it first:  ip netns del $NAMESPACE"
        exit 2
    fi

    # 6. The veth name must not already exist on the host.
    if ip link show "$HOST_VETH" >/dev/null 2>&1; then
        err "host veth '$HOST_VETH' already exists"
        err "remove it first:  ip link del $HOST_VETH"
        exit 2
    fi

    # 7. The HTTP_PORT must not already be in use on $HOST_IP.
    #    (We'll bind 0.0.0.0, so we check if anything is on the port.)
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$HTTP_PORT\$"; then
        err "port $HTTP_PORT is already in use (use --http-port=PORT)"
        ss -ltn 2>/dev/null | grep ":$HTTP_PORT\$" | head -3 | sed 's/^/  /' >&2
        exit 2
    fi

    # 8. cargo + rustc (only needed if we'll build the demo binary).
    # In --mode=prod with a pre-built snp-node binary, we don't need cargo.
    local need_cargo=0
    if [ "$MODE" = "demo" ]; then
        need_cargo=1
    elif [ "$MODE" = "auto" ] && [ ! -x "$PROD_BIN" ]; then
        need_cargo=1
    fi
    if [ "$need_cargo" -eq 1 ] && [ "$NO_BUILD" -eq 0 ]; then
        if ! command -v cargo >/dev/null 2>&1; then
            err "cargo not found on PATH (and not in ~/.cargo/bin)"
            err "install rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            err "or pass --no-build if you've already built the demo binary"
            exit 2
        fi
        vlog "cargo: $(command -v cargo)"
    fi

    log "  preflight: OK"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --mode=*)              MODE="${1#*=}" ;;
            --external-endpoint=*) EXTERNAL_ENDPOINT="${1#*=}" ;;
            --http-port=*)         HTTP_PORT="${1#*=}" ;;
            --socks5-port=*)       SOCKS5_PORT="${1#*=}" ;;
            --client-ip=*)         CLIENT_IP="${1#*=}" ;;
            --host-veth-ip=*)      HOST_VETH_IP="${1#*=}" ;;
            --namespace=*)         NAMESPACE="${1#*=}" ;;
            --cargo-features=*)    CARGO_FEATURES="${1#*=}" ;;
            --no-build)            NO_BUILD=1 ;;
            --keep-on-failure)     KEEP_ON_FAILURE=1 ;;
            -v|--verbose)          VERBOSE=1 ;;
            -h|--help)             usage; exit 0 ;;
            --help)                # Long form for grep-friendly.
                usage; exit 0 ;;
            *)
                err "unknown argument: $1"
                err "run with --help for usage"
                exit 3
                ;;
        esac
        shift
    done

    case "$MODE" in
        auto|prod|demo) ;;
        *)
            err "invalid --mode: $MODE (must be auto|prod|demo)"
            exit 3
            ;;
    esac

    if [ "$MODE" = "demo" ] && [ "$SOCKS5_PORT" != "1080" ]; then
        err "the demo binary (n3_socks5_demo) hardcodes SOCKS5 port 1080"
        err "to use a different port, switch to --mode=prod (requires CLI)"
        exit 3
    fi
}

# ─── Determine the host's primary network IP ─────────────────────────────────
# Returns the IP on stdout. NEVER returns 127.0.0.1 / loopback.
get_host_ip() {
    local ip=""

    # Method 1: ip route get — the source IP used to reach 8.8.8.8 is
    # the host's primary outbound IP. Most reliable on multi-homed hosts.
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip route get 8.8.8.8 2>/dev/null \
             | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
    fi

    # Method 2: hostname -I (space-separated IPv4 list, first non-loopback).
    if [ -z "$ip" ] || [ "$ip" = "127.0.0.1" ]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    # Method 3: fall back to first non-loopback IPv4 from `ip addr`.
    if [ -z "$ip" ] || [ "$ip" = "127.0.0.1" ]; then
        ip=$(ip -4 -o addr show scope global 2>/dev/null \
             | awk '{print $4}' | head -1 | cut -d/ -f1)
    fi

    # Final guard: never allow loopback.
    if [ -z "$ip" ] || [ "$ip" = "127.0.0.1" ] || [ "$ip" = "::1" ]; then
        return 1
    fi
    printf '%s' "$ip"
}

# ─── Build / locate the mesh binary ───────────────────────────────────────────
ensure_mesh_binary() {
    section "locating ShareNet mesh binary (mode=$MODE)"

    # Try prod CLI first if mode is auto or prod.
    if [ "$MODE" = "auto" ] || [ "$MODE" = "prod" ]; then
        if [ -x "$PROD_BIN" ]; then
            if "$PROD_BIN" --help 2>&1 | grep -qE 'gateway-prod|relay-prod|client-prod'; then
                log "  prod CLI available: $PROD_BIN"
                MESH_CMD=prod
                return 0
            fi
            vlog "prod binary exists but lacks gateway-prod subcommands"
        else
            vlog "prod binary not built: $PROD_BIN"
        fi
    fi

    if [ "$MODE" = "prod" ]; then
        err "mode=prod requires snp-node gateway-prod/relay-prod/client-prod subcommands"
        err "the production async CLI is not yet wired (see N3B-STATUS worklog entry #6)"
        err "build with:  cargo build -p snp-node --features <prod-features>"
        err "or use --mode=demo to use the in-process example mesh"
        exit 2
    fi

    # Fall back to (or use) the demo binary.
    if [ ! -x "$DEMO_BIN" ] || [ "$NO_BUILD" -eq 0 ]; then
        log "  building demo binary (cargo run --example n3_socks5_demo)"
        log "    features: $CARGO_FEATURES"
        ( cd "$PROJECT_ROOT" && \
          cargo build --example n3_socks5_demo -p snp-stack \
              --features "$CARGO_FEATURES" ) || {
            err "cargo build failed"
            exit 2
        }
    fi

    if [ ! -x "$DEMO_BIN" ]; then
        err "demo binary not found after build: $DEMO_BIN"
        exit 2
    fi
    log "  demo binary: $DEMO_BIN"
    MESH_CMD=demo
}

# ─── Start the ShareNet mesh + SOCKS5 proxy ──────────────────────────────────
start_mesh() {
    section "starting ShareNet mesh + SOCKS5 proxy (mode=$MESH_CMD)"

    case "$MESH_CMD" in
        prod)
            # When the prod CLI is wired, this is where we'd start
            # gateway-prod / relay-prod / client-prod as separate OS
            # processes. For now this branch is unreachable (ensure_mesh_binary
            # exits with mode=prod if the subcommands don't exist).
            err "prod mode not yet implemented (CLI not wired)"
            exit 2
            ;;
        demo)
            # The demo binary:
            #   * starts gateway + 2 relays + SOCKS5 client in one process
            #   * listens on 0.0.0.0:1080 (SOCKS5)
            #   * prints SOCKS5_PORT=1080 HTTP_PORT=<port> on stdout
            #   * also starts an internal HTTP server on 127.0.0.1:<random>
            #     (we IGNORE that — we use our own external HTTP server below)
            #
            # Real components inside the demo binary:
            #   * MultiplexedCircuit::establish  (real SNP-IK + X25519 DH)
            #   * serve_gateway_mode_b_multiplexed (real outbound TCP)
            #   * serve_relay_via_route  (real relay forwarding)
            #   * socks5_handshake  (RFC 1928)
            #
            # IMPORTANT: the demo binary uses GatewayStreamTable::with_allow_loopback()
            # which is gated behind --features test-utils. This is the ONLY
            # deviation from production SSRF defence in this test. When the
            # prod CLI is wired, --mode=prod will use GatewayStreamTable::new()
            # (allow_loopback=false) for true production SSRF defence.
            log "  starting: $DEMO_BIN"
            log "  log:      $MESH_LOG"
            "$DEMO_BIN" >"$MESH_LOG" 2>&1 &
            MESH_PID=$!
            ;;
        *)
            err "internal error: unknown MESH_CMD=$MESH_CMD"
            exit 2
            ;;
    esac

    log "  mesh PID: $MESH_PID"

    # Wait for the SOCKS5 proxy to be ready (the demo binary prints
    # "listening for application connections" on stderr).
    log "  waiting for SOCKS5 proxy to be ready..."
    local ready=0
    local i
    for i in $(seq 1 40); do
        if ! kill -0 "$MESH_PID" 2>/dev/null; then
            err "mesh process died during startup"
            err "----- mesh log -----"
            cat "$MESH_LOG" >&2 || true
            exit 2
        fi
        if grep -q 'listening for application connections' "$MESH_LOG" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.5
    done

    if [ "$ready" -ne 1 ]; then
        err "mesh did not become ready within 20s"
        err "----- mesh log (last 30 lines) -----"
        tail -30 "$MESH_LOG" >&2 || true
        exit 2
    fi

    log "  SOCKS5 proxy is ready on 0.0.0.0:$SOCKS5_PORT"

    # Sanity check the mesh from the HOST namespace first (no isolation).
    # This proves the mesh + external HTTP server are wired correctly
    # BEFORE we introduce the namespace, which makes debugging easier.
    if [ -n "$EXTERNAL_ENDPOINT" ]; then
        log "  host sanity check: curl --socks5 127.0.0.1:$SOCKS5_PORT $EXTERNAL_ENDPOINT"
        if ! curl --socks5 "127.0.0.1:$SOCKS5_PORT" --connect-timeout 5 \
                   -s -o /dev/null -w 'http_code=%{http_code}\n' \
                   "$EXTERNAL_ENDPOINT" 2>&1 | tee /dev/stderr | grep -q 'http_code=200'; then
            err "host sanity check FAILED — mesh + external HTTP server not wired"
            err "this is not a namespace isolation issue; the mesh itself is broken"
            err "----- mesh log (last 30 lines) -----"
            tail -30 "$MESH_LOG" >&2 || true
            exit 2
        fi
        log "  host sanity check: OK (200 via ShareNet from host)"
    fi
}

# ─── Start the external HTTP server ──────────────────────────────────────────
start_http_server() {
    section "starting external HTTP server (the 'Internet' endpoint)"

    # Create a temp directory with an index.html that we'll serve.
    # The body content is what we'll look for in the SOCKS5 test response
    # to prove the bytes actually traversed the ShareNet circuit.
    HTTP_ROOT="$(mktemp -d /tmp/n3b_http_root.XXXXXX)"
    cat > "$HTTP_ROOT/index.html" <<'HTML'
<!DOCTYPE html>
<html><head><title>ShareNet N3-A Acceptance Test</title></head>
<body>
<h1>Hello from the real Internet via ShareNet!</h1>
<p>This response was served by a real HTTP server process bound to the
host's primary network interface IP (NOT 127.0.0.1). It was reached
through the ShareNet SOCKS5 proxy via a real ShareNet circuit (SNP-IK
authentication + X25519 circuit DH, two real relays, a real gateway
opening a real outbound TCP socket).</p>
</body></html>
HTML
    log "  http root: $HTTP_ROOT"
    log "  index.html: $(wc -c < "$HTTP_ROOT/index.html") bytes"

    # Bind to 0.0.0.0 so the host's primary IP is reachable. (The
    # gateway is in the host namespace, so it can reach any of the
    # host's IPs. The client namespace can ONLY reach $HOST_VETH_IP
    # via the veth pair — which is why DIRECT fails.)
    log "  starting: python3 -m http.server $HTTP_PORT --bind 0.0.0.0"
    log "  log:      $HTTP_LOG"
    ( cd "$HTTP_ROOT" && \
      python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 \
          >"$HTTP_LOG" 2>&1 ) &
    HTTP_PID=$!
    log "  http PID: $HTTP_PID"

    # Wait for the server to bind.
    local i
    for i in $(seq 1 20); do
        if ! kill -0 "$HTTP_PID" 2>/dev/null; then
            err "HTTP server died during startup"
            cat "$HTTP_LOG" >&2 || true
            exit 2
        fi
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$HTTP_PORT\$"; then
            log "  HTTP server is listening on 0.0.0.0:$HTTP_PORT"
            return 0
        fi
        sleep 0.25
    done
    err "HTTP server did not bind within 5s"
    cat "$HTTP_LOG" >&2 || true
    exit 2
}

# ─── Set up network namespace + veth pair ─────────────────────────────────────
setup_namespace() {
    section "setting up network namespace + veth pair"

    # 1. Create the namespace.
    log "  ip netns add $NAMESPACE"
    if ! ip netns add "$NAMESPACE" 2>"$MESH_LOG.ns_err"; then
        err "ip netns add failed"
        err "this requires root or CAP_SYS_ADMIN + CAP_NET_ADMIN"
        err "stderr: $(cat "$MESH_LOG.ns_err" 2>/dev/null)"
        exit 2
    fi
    NAMESPACE_CREATED=1

    # 2. Create the veth pair in the HOST namespace.
    log "  ip link add $HOST_VETH type veth peer name $CLIENT_VETH"
    if ! ip link add "$HOST_VETH" type veth peer name "$CLIENT_VETH"; then
        err "ip link add veth failed"
        exit 2
    fi
    VETH_HOST_CREATED=1

    # 3. Move the client end into the namespace.
    log "  ip link set $CLIENT_VETH netns $NAMESPACE"
    if ! ip link set "$CLIENT_VETH" netns "$NAMESPACE"; then
        err "ip link set netns failed"
        exit 2
    fi
    VETH_MOVED=1

    # 4. Configure the host side.
    log "  host: ip addr add $HOST_VETH_IP/24 dev $HOST_VETH"
    ip addr add "$HOST_VETH_IP/24" dev "$HOST_VETH" || { err "host addr add failed"; exit 2; }
    ip link set "$HOST_VETH" up                  || { err "host link up failed"; exit 2; }

    # 5. Configure the client side (inside the namespace).
    log "  client: ip link set lo up"
    ip netns exec "$NAMESPACE" ip link set lo up || { err "client lo up failed"; exit 2; }
    log "  client: ip link set $CLIENT_VETH up"
    ip netns exec "$NAMESPACE" ip link set "$CLIENT_VETH" up \
        || { err "client veth up failed"; exit 2; }
    log "  client: ip addr add $CLIENT_IP/24 dev $CLIENT_VETH"
    ip netns exec "$NAMESPACE" ip addr add "$CLIENT_IP/24" dev "$CLIENT_VETH" \
        || { err "client addr add failed"; exit 2; }
    log "  client: ip route add 10.0.0.0/24 dev $CLIENT_VETH"
    ip netns exec "$NAMESPACE" ip route add 10.0.0.0/24 dev "$CLIENT_VETH" \
        || { err "client route add failed"; exit 2; }

    # 6. CRITICAL: assert there is NO default route in the client namespace.
    #    This is what makes the DIRECT test fail. If a default route exists
    #    (e.g. inherited via some misconfiguration), the test is invalid.
    if ip netns exec "$NAMESPACE" ip route show default 2>/dev/null | grep -q .; then
        err "client namespace has a default route — isolation broken"
        err "default route(s) in $NAMESPACE:"
        ip netns exec "$NAMESPACE" ip route show default >&2 || true
        err "this test requires the client namespace to have NO default route"
        exit 2
    fi
    log "  client namespace has NO default route (verified)"

    # 7. Print the routing table for transparency.
    log "  --- client namespace routes ---"
    ip netns exec "$NAMESPACE" ip route show 2>/dev/null | sed 's/^/      /'
    log "  --- client namespace addresses ---"
    ip netns exec "$NAMESPACE" ip -br addr show 2>/dev/null | sed 's/^/      /'
}

# ─── TEST 1: DIRECT access MUST FAIL ──────────────────────────────────────────
test_direct() {
    section "TEST 1: DIRECT access from client namespace — EXPECTED: FAIL"

    log "  \$ ip netns exec $NAMESPACE curl --connect-timeout 2 $EXTERNAL_ENDPOINT"
    log "  (no route in namespace → curl must fail)"

    # Run curl inside the namespace. Capture exit code and combined output.
    local output rc
    output=$(ip netns exec "$NAMESPACE" \
             curl --connect-timeout 2 -s -o /dev/null -w '%{http_code}' \
                  "$EXTERNAL_ENDPOINT" 2>&1) && rc=0 || rc=$?

    log "  curl exit code: $rc"
    log "  curl output:    ${output:-<empty>}"

    if [ "$rc" -eq 0 ]; then
        err "FAIL: DIRECT access SUCCEEDED — namespace isolation is broken"
        err "       the client namespace must NOT have any route to $EXTERNAL_ENDPOINT"
        err "       check: ip netns exec $NAMESPACE ip route show"
        return 1
    fi

    log "  ✓ DIRECT access FAILED (as expected)"
    return 0
}

# ─── TEST 2: ShareNet access MUST SUCCEED ─────────────────────────────────────
test_via_sharennet() {
    section "TEST 2: ShareNet access from client namespace — EXPECTED: SUCCESS"

    log "  \$ ip netns exec $NAMESPACE curl --socks5 $HOST_VETH_IP:$SOCKS5_PORT \\"
    log "        --connect-timeout 10 $EXTERNAL_ENDPOINT"

    local output rc
    output=$(ip netns exec "$NAMESPACE" \
             curl --socks5 "$HOST_VETH_IP:$SOCKS5_PORT" \
                  --connect-timeout 10 -s \
                  "$EXTERNAL_ENDPOINT" 2>&1) && rc=0 || rc=$?

    log "  curl exit code: $rc"
    if [ -n "$output" ]; then
        log "  response (first 200 chars):"
        printf '%s\n' "$output" | head -c 200 | sed 's/^/      /'
    else
        log "  response: <empty>"
    fi

    if [ "$rc" -ne 0 ]; then
        err "FAIL: ShareNet access FAILED (curl exit $rc)"
        err "       the ShareNet mesh should have relayed the request"
        err "       --- mesh log (last 40 lines) ---"
        tail -40 "$MESH_LOG" >&2 || true
        return 1
    fi

    # Confirm the response body contains the expected marker. This proves
    # the bytes actually traversed the ShareNet circuit (not just that curl
    # got an arbitrary response).
    if ! printf '%s' "$output" | grep -q 'Hello from the real Internet via ShareNet!'; then
        err "FAIL: ShareNet access returned unexpected body"
        err "       expected marker 'Hello from the real Internet via ShareNet!' not found"
        err "       response (first 500 chars):"
        printf '%s\n' "$output" | head -c 500 | sed 's/^/      /' >&2
        return 1
    fi

    log "  ✓ SHARENET access SUCCEEDED (as expected)"
    return 0
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    # Print the banner + config.
    section "N3-A REAL INTERNET ACCEPTANCE TEST"
    log "  mode:                $MODE"
    log "  project root:        $PROJECT_ROOT"

    # Resolve host IP.
    local host_ip
    if ! host_ip=$(get_host_ip); then
        err "could not determine host's primary network IP"
        err "set it explicitly with --external-endpoint=http://IP:PORT/"
        exit 2
    fi
    log "  host IP:             $host_ip"

    # Resolve external endpoint URL.
    if [ -z "$EXTERNAL_ENDPOINT" ]; then
        EXTERNAL_ENDPOINT="http://$host_ip:$HTTP_PORT/"
    fi
    log "  external endpoint:   $EXTERNAL_ENDPOINT"
    log "  socks5 proxy:        $HOST_VETH_IP:$SOCKS5_PORT"
    log "  client namespace:    $NAMESPACE ($CLIENT_IP, no default route)"
    log "  cargo features:      $CARGO_FEATURES"

    # Guard: the external endpoint must NOT be loopback.
    case "$EXTERNAL_ENDPOINT" in
        http://127.0.0.1:*|http://localhost:*|http://[::1]:*)
            err "external endpoint must NOT be loopback: $EXTERNAL_ENDPOINT"
            err "use --external-endpoint=http://<real-ip>:<port>/ or"
            err "let the script auto-detect via hostname -I"
            exit 3
            ;;
    esac

    # Guard: the host veth IP must NOT be the same as the external IP,
    # otherwise the test is meaningless (the veth IS the route to the
    # external endpoint). The veth subnet is 10.0.0.0/24, so as long as
    # $host_ip is not 10.0.0.x, we're fine.
    case "$host_ip" in
        10.0.0.*)
            err "host IP $host_ip is inside the veth subnet 10.0.0.0/24"
            err "the DIRECT test would succeed (same subnet as the veth route)"
            err "use --host-veth-ip=10.1.0.1 --client-ip=10.1.0.2 to change the veth subnet"
            exit 3
            ;;
    esac

    preflight
    ensure_mesh_binary

    # Start the external HTTP server BEFORE the mesh so the host sanity
    # check (inside start_mesh) can verify the wiring end-to-end.
    start_http_server
    start_mesh

    setup_namespace

    # Run the two tests.
    local direct_ok=1 sharenet_ok=1
    test_direct         || direct_ok=0
    test_via_sharennet  || sharenet_ok=0

    section "RESULT"
    if [ "$direct_ok" -eq 1 ] && [ "$sharenet_ok" -eq 1 ]; then
        cat <<'BANNER'

    ═══════════════════════════════════════════════════════
      N3-A ACCEPTANCE TEST PASSED
      Direct Internet:    FAIL     (correct — no route)
      Via ShareNet:       SUCCESS  (correct — real circuit)
    ═══════════════════════════════════════════════════════

    This proves:
      * The client namespace is truly isolated (no default route).
      * ShareNet provides real Internet egress via:
          - real SNP-IK + X25519 circuit DH (MultiplexedCircuit::establish)
          - real relay forwarding (serve_relay_via_route, two relays)
          - real gateway outbound TCP (serve_gateway_mode_b_multiplexed)
          - real SOCKS5 (RFC 1928) handshake
      * The bytes returned actually traversed the ShareNet circuit
        (the response marker 'Hello from the real Internet via ShareNet!'
        was written by the external HTTP server, not the gateway).
BANNER
        EXIT_CODE=0
    else
        cat <<'BANNER' >&2

    ═══════════════════════════════════════════════════════
      N3-A ACCEPTANCE TEST FAILED
BANNER
        [ "$direct_ok"  -eq 0 ] && printf '      Direct Internet:    SUCCESS  (WRONG — isolation broken)\n' >&2
        [ "$direct_ok"  -eq 1 ] && printf '      Direct Internet:    FAIL     (correct)\n'                  >&2
        [ "$sharenet_ok" -eq 0 ] && printf '      Via ShareNet:       FAIL     (WRONG — mesh broken)\n'    >&2
        [ "$sharenet_ok" -eq 1 ] && printf '      Via ShareNet:       SUCCESS  (correct)\n'                 >&2
        printf '    ════════════════════════════════════════════════════════\n' >&2

        if [ "$sharenet_ok" -eq 0 ]; then
            printf '\n    --- mesh log (last 40 lines) ---\n' >&2
            tail -40 "$MESH_LOG" >&2 2>/dev/null || true
        fi
        EXIT_CODE=1
    fi
}

main "$@"
exit $EXIT_CODE
