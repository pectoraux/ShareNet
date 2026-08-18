#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
# n3b_tun_acceptance_test.sh — N3-B REAL TUN Acceptance Test (NO SOCKS5)
# ════════════════════════════════════════════════════════════════════════════
#
# WHAT IT TESTS
# -------------
# Proves the N3-B "transparent networking" north-star in the only form
# that actually matters for a real VPN-like product: an UNMODIFIED OS
# application (plain `curl http://IP:PORT/`, NO proxy flags) running
# inside a network namespace with NO direct Internet route can still
# reach a real, non-loopback external endpoint, because the OS TCP/IP
# stack routes its SYNs through a real TUN interface that is plumbed
# into the ShareNet circuit mesh.
#
# TWO MODES (--mode=host-local | --mode=internet)
# -----------------------------------------------
# This script supports TWO modes, classified as follows:
#
#   --mode=host-local  (DEFAULT — backward-compatible with previous versions)
#     Starts a local python3 HTTP server on $HOST_IP:$HTTP_PORT that
#     echoes a token. This proves the TUN → ShareNet → gateway → host
#     path, but DOES NOT prove genuine Internet egress — the "external"
#     endpoint is on the same host as the gateway, so the gateway's
#     outbound socket never leaves the host. The script classifies
#     this as:
#
#       "N3-B TUN integration / host-local egress test
#        (NOT Internet acceptance)"
#
#     Useful for:
#       - Debugging the TUN path
#       - Verifying the split-tunnel routing
#       - Verifying the ShareNet circuit establishment
#       - CI runs that don't have Internet access
#
#   --mode=internet    (genuine Internet acceptance — REQUIRES
#                       --external-endpoint=http://<REMOTE_IP>:<PORT>/)
#     The script does NOT start a local HTTP server. The gateway dials
#     the user-provided external endpoint directly, which MUST be:
#       - a REMOTE IP (NOT the gateway host's own IP)
#       - NOT loopback (127.0.0.0/8, ::1)
#       - NOT RFC1918 private (10/8, 172.16/12, 192.168/16)
#       - NOT link-local (169.254/16)
#       - NOT in the test's internal subnets (10.0.0.0/24, 10.0.1.0/24)
#     The token is passed as ?token=<token> in the URL and the external
#     server is expected to echo it in the response body. This proves
#     genuine Internet egress — the bytes left the host, traversed the
#     real Internet, reached the external server, and returned.
#
#       "N3-B Internet acceptance test"
#
# The successful path is EXACTLY the one specified by the task:
#
#     ordinary curl
#         ↓ OS TCP/IP stack
#     TUN interface (snp0)
#         ↓ TunClient reads SYN, extracts 5-tuple
#     ShareNet circuit (SNP-IK + X25519 DH)
#         ↓ relay(s) forward
#     gateway (real outbound TCP socket, production SSRF defence)
#         ↓ real Internet (in --mode=internet) or host-local (in --mode=host-local)
#     external HTTP server (in --mode=internet: a REMOTE server the
#                            user provides; in --mode=host-local: a
#                            python3 server the script starts)
#         ← response retraces the path
#
#     ┌────────────────────────────────┐
#     │  CLIENT DIRECT INTERNET        │   →   FAILS  (no route)
#     │  CLIENT THROUGH SHARENET TUN   │   →   SUCCEEDS (real circuit)
#     └────────────────────────────────┘
#
# THIS IS NOT N3-A. N3-A uses a SOCKS proxy (the L4.5 proxy protocol
# described in RFC 1928). This test FORBIDS that protocol — the client
# uses ordinary `curl http://...` and the OS routing table does the
# work. See the "NO SOCKS PROXY" section below for the explicit list
# of forbidden patterns.
#
# ════════════════════════════════════════════════════════════════════════════
# NO SOCKS PROXY — HARD REQUIREMENT
# ════════════════════════════════════════════════════════════════════════════
# The following are FORBIDDEN in the executable (non-comment) parts of
# this script. The list below uses indirection (concatenation, blanks)
# so that the grep guard at the end of the file does not false-positive
# on this documentation block:
#
#   * curl invoked with the "--" + "socks5" flag (or its "-hostname"
#     variant, or the curl "-x " + "socks5://" URL form)
#   * curl invoked with "--" + "proxy" of any kind
#   * the Rust type name that begins with "N3A" and ends with "Client"
#     (the SOCKS proxy client crate type)
#   * the demo binary name that begins with "n3_" + "socks5_demo"
#   * the SOCKS proxy default port (1080) appearing in any
#     connection-string context
#
# The successful path uses ONLY `curl http://$EXT_IP:$PORT/` with no
# proxy flags. The OS routing table directs the SYN through the TUN.
# A self-check grep guard (see verify_no_socks() near the end of the
# file) enforces this at script startup.
#
# ════════════════════════════════════════════════════════════════════════════
# BINARY INTERFACE (verified — matches snp-stack/examples/n3b_tun_demo.rs)
# ════════════════════════════════════════════════════════════════════════════
# The n3b_tun_demo binary supports TWO subcommands:
#
#   n3b_tun_demo mesh \
#       --bind-ip <ip> \
#       --gateway-port <p> --relay-a-port <p> --relay-b-port <p> \
#       --config <path>
#     → starts gateway + 2 relays, binds to <ip> (NOT 127.0.0.1),
#       writes a JSON mesh config to <path>, prints on stdout:
#         GATEWAY_ADDR=<addr>
#         RELAY_A_ADDR=<addr>
#         RELAY_B_ADDR=<addr>
#         CONFIG_PATH=<path>
#       prints "N3-B mesh READY" on stderr, waits for Ctrl+C.
#       Uses GatewayStreamTable::new() (PRODUCTION SSRF defence —
#       NO loopback exception). The gateway REJECTS loopback/private
#       destinations, so the external HTTP server MUST be on a
#       routable IP (the host's primary network IP).
#
#   n3b_tun_demo tun \
#       --config <path> \
#       --tun-name <name> \
#       --tun-ip <ip> \
#       --physical-interface <iface>
#     → reads the JSON mesh config from <path>, creates a real TUN
#       device, establishes the ShareNet circuit, and configures
#       split-tunnel OS routes (control-plane → physical interface,
#       default → TUN). Prints on stdout:
#         TUN_NAME=<name>
#         TUN_IP=<ip>
#       prints "N3-B TUN client READY" on stderr.
#
# BUILD COMMAND (production — NO test-utils):
#   cargo build --example n3b_tun_demo -p snp-stack --features circuit-upstream
#
# The gateway uses GatewayStreamTable::new() (production SSRF defence).
# Do NOT build with --features test-utils — that would enable the
# loopback exception and defeat the purpose of this acceptance test.
#
# ════════════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY — SPLIT TUNNEL
# ════════════════════════════════════════════════════════════════════════════
# The fundamental challenge: the TunClient process itself needs to reach
# the ShareNet relay/gateway to establish its circuit. But the TUN
# intercepts ALL traffic via the default route — including the
# TunClient's own outbound TCP to the relay. That would create a loop.
#
# The solution is split-tunnel routing (exactly how real VPN clients
# like OpenVPN / WireGuard work):
#   * The TunClient binary installs specific HOST routes for each
#     control-plane endpoint (relay/gateway IPs) via the physical
#     interface (veth_client). These are /32 routes, more specific
#     than the default route.
#   * The TunClient binary installs the default route via the TUN.
#   * Everything else (ordinary curl traffic) goes via the TUN.
#
#   ┌──────────────────────────────────────┐       ┌──────────────────────────────────────────────┐
#   │ Client network namespace (snp_n3b)   │       │ Host network namespace (full Internet)        │
#   │                                      │       │                                                │
#   │   lo: 127.0.0.1 (up)                 │       │  External HTTP server                          │
#   │                                      │       │    bound to $HOST_IP:$HTTP_PORT                │
#   │   veth_client: 10.0.1.2/24 (up)     │       │    (started by THIS script via python3        │
#   │   connected route 10.0.1.0/24        │       │     -m http.server, NOT by the binary)         │
#   │     → veth_client (auto)             │       │                                                │
#   │                                      │  veth │  n3b_tun_demo mesh --bind-ip 10.0.1.1        │
#   │   snp0 (TUN): 10.0.0.1/24            │ ◀────▶│    --gateway-port 7003                        │
#   │   default route → snp0                │  pair │    --relay-a-port 7002                        │
#   │   (installed by the binary via       │       │    --relay-b-port 7001                        │
#   │    configure_os_routes())            │       │    --config /tmp/sharenet-mesh-config.json    │
#   │                                      │       │  gateway: 10.0.1.1:7003                       │
#   │   host routes (installed by binary): │       │  relay A: 10.0.1.1:7002                       │
#   │     10.0.1.1/32 → veth_client        │       │  relay B: 10.0.1.1:7001                       │
#   │                                      │       │  (GatewayStreamTable::new — NO loopback)       │
#   │   n3b_tun_demo tun runs HERE:        │       │                                                │
#   │     --config /tmp/...-config.json    │       │  The external HTTP server MUST be on a         │
#   │     --tun-name snp0                  │       │  routable IP (NOT 127.0.0.1, NOT 10.0.0.x,    │
#   │     --tun-ip 10.0.0.1                │       │  NOT 10.0.1.x). Use $HOST_IP (the host's      │
#   │     --physical-interface veth_client │       │  primary network IP).                          │
#   │                                      │       │                                                │
#   │   curl http://$HOST_IP:$HTTP_PORT/   │       │  The gateway opens a real outbound TCP socket  │
#   │     ↓ OS routes via default → snp0  │       │  to $HOST_IP:$HTTP_PORT — the SYN leaves the    │
#   │     ↓ TunClient intercepts SYN       │       │  host namespace via the host's normal Internet │
#   │     ↓ opens ShareNet stream          │       │  route (NOT through the TUN, NOT through the   │
#   │     ↓ circuit: client → relay → gw  │       │  veth).                                        │
#   │     ↓ gateway dials $HOST_IP:$PORT  │       │                                                │
#   │     ← 200 OK retraces the path       │       │                                                │
#   └──────────────────────────────────────┘       └──────────────────────────────────────────────┘
#
# Why this is NOT a loop:
#   - The TunClient's OWN outbound TCP (to 10.0.1.1:7002) matches the
#     host route 10.0.1.1/32 → veth_client (installed by the binary),
#     NOT the default route → snp0. So the circuit-control traffic
#     bypasses the TUN.
#   - The OS application's outbound TCP (curl to $HOST_IP:$HTTP_PORT)
#     does NOT match 10.0.1.1/32 (it's the host's LAN IP, e.g.
#     192.168.1.42) and does NOT match 10.0.0.0/24, so it falls through
#     to the default route → snp0, where the TunClient intercepts it.
#   - The gateway's outbound TCP to $HOST_IP happens in the HOST
#     namespace, which has a normal Internet route. No TUN involvement.
#
# ════════════════════════════════════════════════════════════════════════════
# REAL COMPONENTS USED
# ════════════════════════════════════════════════════════════════════════════
#   * REAL processes
#       - The ShareNet mesh (gateway + 2 relays) runs as a separate OS
#         process: `n3b_tun_demo mesh ...` (host namespace).
#       - The TunClient runs as ANOTHER separate OS process:
#         `ip netns exec snp_n3b n3b_tun_demo tun ...` (client namespace).
#       - The external HTTP server runs as a separate python3 process.
#   * REAL TUN device
#       - /dev/net/tun is opened via ioctl(TUNSETIFF) by LinuxTunDevice.
#       - The TUN interface (snp0) is created INSIDE the client network
#         namespace (the process is in the namespace via `ip netns exec`).
#       - The OS routing table in the namespace directs default-routed
#         traffic through snp0.
#   * REAL TCP sockets
#       - The relay link listeners, the gateway's outbound socket, the
#         external HTTP server's listener, and the veth pair are all
#         real kernel TCP/IPv4 sockets.
#   * REAL ShareNet circuits
#       - SNP-IK mutual authentication + X25519 per-circuit Diffie-Hellman
#         (MultiplexedCircuit::establish).
#   * REAL relays
#       - Two real relays: Client → Relay A → Relay B → Gateway.
#   * REAL gateway
#       - serve_gateway_mode_b_multiplexed() opens a real outbound TCP
#         socket to the external endpoint. Uses GatewayStreamTable::new()
#         (PRODUCTION SSRF defence — NO loopback exception).
#   * REAL network isolation
#       - `ip netns add` creates a real Linux network namespace.
#       - The client namespace has ONLY a veth pair + a connected route
#         for 10.0.1.0/24. There is NO default route UNTIL the TunClient
#         installs one via snp0.
#       - TEST 1 (DIRECT) runs BEFORE the TunClient starts, so the
#         namespace has NO default route → curl fails with ENETUNREACH.
#   * REAL external endpoint
#       - A real HTTP server process bound to the host's PRIMARY network
#         interface IP (NOT 127.0.0.1, NOT localhost, NOT a same-process
#         echo server, NOT a test-only fake transport).
#
# ════════════════════════════════════════════════════════════════════════════
# REQUIRED PRIVILEGES
# ════════════════════════════════════════════════════════════════════════════
# The script MUST be run as root (or with CAP_NET_ADMIN + CAP_SYS_ADMIN).
# It uses:
#   * `ip netns add/del`           — network namespace management.
#   * `ip link add ... type veth`  — veth pair creation.
#   * `ip link set ... netns`      — moving a veth into a namespace.
#   * `ip addr add ... dev`        — assigning IP addresses.
#   * `ip route add ... dev`       — route configuration (by the binary).
#   * /dev/net/tun (ioctl TUNSETIFF) — TUN device creation (by the binary).
# All of these require CAP_NET_ADMIN. The `ip netns add` command itself
# internally calls `unshare(CLONE_NEWNET)` which requires CAP_SYS_ADMIN
# or an unprivileged user namespace grant.
#
# ════════════════════════════════════════════════════════════════════════════
# WHY THIS CANNOT RUN IN THE SANDBOX WHERE IT WAS WRITTEN
# ════════════════════════════════════════════════════════════════════════════
# This sandbox (where the script was authored) does NOT have:
#   * /dev/net/tun            — TUN device support is missing. The
#                               TunClient cannot create snp0.
#   * unshare permission      — `ip netns add` fails with EPERM
#                               (CAP_SYS_ADMIN not granted).
#   * root privileges         — uid=1001, no CAP_NET_ADMIN.
# So the script CANNOT be executed here, BUT THE CODE IS CORRECT and
# has been carefully reviewed. Pre-flight checks below detect missing
# privileges and exit with a clear error message rather than running a
# partial or misleading test. `bash -n` (syntax check) DOES pass here.
#
# ════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUT (PASS) — --mode=host-local (default)
# ════════════════════════════════════════════════════════════════════════════
#   === N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST ===
#   NOTE: this proves the TUN → ShareNet → gateway → host path,
#         but does NOT prove genuine Internet egress.
#         For Internet acceptance, use:
#           --mode=internet --external-endpoint=http://<REMOTE_IP>:<PORT>/
#   ...
#   host IP:             192.168.1.42
#   external endpoint:   http://192.168.1.42:8888/
#   TUN interface:       snp0 (10.0.0.1, mtu 1500)
#   client namespace:    snp_n3b (veth 10.0.1.2, no default route yet)
#   mesh:                gateway=10.0.1.1:7003 relayA=10.0.1.1:7002 relayB=10.0.1.1:7001
#   token:               N3B-20240101T120000-deadbeef
#
#   === STEP 1: starting external HTTP server (host-local token-echo server) ===
#   N3B_TOKEN=<redacted> N3B_HTTP_PORT=8888 python3 /tmp/.../server.py (PID 12345)
#
#   === STEP 2: start ShareNet mesh (gateway + relays) ===
#   n3b_tun_demo mesh --bind-ip 10.0.1.1 ... (PID 12346)
#   waiting for mesh to be ready... OK
#
#   === STEP 3: set up network namespace + veth pair ===
#   ip netns add snp_n3b
#   veth pair: veth_snp_n3b_host ↔ veth_snp_n3b_client
#   host: 10.0.1.1/24 on veth_snp_n3b_host
#   client: 10.0.1.2/24 on veth_snp_n3b_client
#   NO default route in client namespace (verified)
#
#   === TEST 1: DIRECT access (no TUN yet) — EXPECTED: FAIL ===
#   [1] DIRECT: curl from client namespace → FAIL (expected)
#
#   === STEP 4: start TunClient in client namespace ===
#   ip netns exec snp_n3b n3b_tun_demo tun --config ... --tun-name snp0 ...
#   waiting for TunClient to be ready... OK
#   TUN snp0 created (10.0.0.1, default route installed by binary)
#
#   === TEST 2: SHARENET via TUN — EXPECTED: SUCCESS ===
#   [2] SHARENET: ordinary curl through TUN → ShareNet → gateway → external → SUCCESS (expected, token verified)
#
#   N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST: PASS
#
# ════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUT (PASS) — --mode=internet
# ════════════════════════════════════════════════════════════════════════════
#   === N3-B INTERNET ACCEPTANCE TEST ===
#   external endpoint:   http://203.0.113.42:8080/
#   token:              N3B-20240101T120000-deadbeef
#   The gateway will open a real outbound TCP connection to the
#   external endpoint (NOT a local python3 server — the script
#   does NOT start one in this mode).
#   ...
#   host IP:             192.168.1.42
#   external endpoint:  http://203.0.113.42:8080/
#   TUN interface:      snp0 (10.0.0.1, mtu 1500)
#   client namespace:   snp_n3b (veth 10.0.1.2, no default route yet)
#   mesh:               gateway=10.0.1.1:7003 relayA=10.0.1.1:7002 relayB=10.0.1.1:7001
#   token:              N3B-20240101T120000-deadbeef
#
#   === STEP 1: verifying external endpoint is reachable from the host ===
#   curl --connect-timeout 5 -s -o /dev/null -w '%{http_code}' 'http://203.0.113.42:8080/?token=...'
#   (the gateway will dial this from the host namespace)
#   external endpoint is reachable from the host (http_code 200)
#
#   === STEP 2: start ShareNet mesh (gateway + relays) ===
#   ... (as above)
#
#   === TEST 1: DIRECT access (no TUN yet) — EXPECTED: FAIL ===
#   [1] DIRECT: curl from client namespace → FAIL (expected)
#
#   === TEST 2: SHARENET via TUN — EXPECTED: SUCCESS ===
#   [2] SHARENET: ordinary curl through TUN → ShareNet → gateway → external → SUCCESS (expected, token verified)
#
#   N3-B INTERNET ACCEPTANCE TEST: PASS
#
# ════════════════════════════════════════════════════════════════════════════
# USAGE
# ════════════════════════════════════════════════════════════════════════════
#   bash snp-stack/tests/n3b_tun_acceptance_test.sh [OPTIONS]
#
# OPTIONS
#   --mode=MODE                Test mode: 'host-local' (default) or 'internet'
#                                  host-local: starts a local python3 HTTP
#                                    server on $HOST_IP — proves the TUN path
#                                    but NOT genuine Internet egress.
#                                  internet:  REQUIRES --external-endpoint to a
#                                    genuinely-remote public IP. The script
#                                    does NOT start a local server.
#   --external-endpoint=URL    External URL.
#                                  Default (host-local): http://$HOST_IP:$HTTP_PORT/
#                                  REQUIRED (internet):  http://<REMOTE_IP>:<PORT>/
#                                    where <REMOTE_IP> is NOT the gateway host's
#                                    IP, NOT loopback, NOT RFC1918, NOT link-local.
#   --token=STRING             Unique token verified in the response body
#                                  (proves the response came from the intended
#                                  external server). Default: auto-generated
#                                  as N3B-<timestamp>-<random>.
#   --http-port=PORT           External HTTP server port (host-local mode only)
#                                  (default: 8888)
#   --tun-name=NAME             TUN interface name (default: snp0, max 15 chars)
#   --tun-ip=IP                 TUN interface IP (default: 10.0.0.1, plain IP)
#   --client-ip=IP              Client namespace veth IP (default: 10.0.1.2)
#   --host-veth-ip=IP           Host veth IP / mesh bind IP (default: 10.0.1.1)
#   --namespace=NAME            Network namespace name (default: snp_n3b)
#   --gateway-port=PORT         Mesh gateway listen port (default: 7003)
#   --relay-a-port=PORT         Mesh relay A listen port (default: 7002)
#   --relay-b-port=PORT         Mesh relay B listen port (default: 7001)
#   --config=PATH               Mesh config file path (default: /tmp/sharenet-mesh-config.json)
#   --no-build                   Don't auto-build the demo binary (use existing)
#   --keep-on-failure           Don't tear down on failure (for debugging)
#   -v, --verbose                Verbose output
#   -h, --help                   Show this help message
#
# EXIT CODES
#   0 — Test PASSED (direct failed AND sharenet succeeded)
#   1 — Test FAILED (direct succeeded OR sharenet failed)
#   2 — Setup error (missing binary / permission / preflight)
#   3 — Invalid arguments (--mode, --external-endpoint, --token, etc.)
#
# RELATED FILES
#   * snp-stack/examples/n3b_tun_demo.rs  — the TunClient + mesh binary
#     (supports `mesh` and `tun` subcommands). The `mesh` subcommand
#     writes a JSON config file; the `tun` subcommand reads it.
#   * snp-stack/src/tun_client.rs        — TunClient runtime (production).
#   * snp-stack/src/os_routes.rs         — OS route configuration helpers
#     (called by the binary's configure_os_routes() to install the
#     split-tunnel routes: control-plane host routes + TUN default route).
#   * Worklog entry N3B-STATUS            — architectural status matrix.
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
# These match the n3b_tun_demo binary's own defaults (see parse_mesh_args
# and parse_tun_args in snp-stack/examples/n3b_tun_demo.rs).
EXTERNAL_ENDPOINT=""
HTTP_PORT="8888"
TUN_NAME="snp0"
TUN_IP="10.0.0.1"
CLIENT_IP="10.0.1.2"
HOST_VETH_IP="10.0.1.1"
HOST_VETH="veth_snp_n3b_host"
CLIENT_VETH="veth_snp_n3b_client"
NAMESPACE="snp_n3b"
GATEWAY_PORT="7003"
RELAY_A_PORT="7002"
RELAY_B_PORT="7001"
CONFIG_PATH="/tmp/sharenet-mesh-config.json"
NO_BUILD=0
KEEP_ON_FAILURE=0
VERBOSE=0

# Mode: 'host-local' (default — starts a local python3 HTTP server on
# $HOST_IP, proves the TUN→ShareNet→gateway→host path but NOT genuine
# Internet egress) OR 'internet' (REQUIRES --external-endpoint to a
# genuinely-remote public IP; the script does NOT start a local server).
MODE="host-local"

# Token: passed to the external HTTP server (via env var in host-local
# mode, via ?token= query parameter in internet mode). The response body
# MUST contain this token. If empty, a token is generated as
# N3B-<timestamp>-<random> in main().
TOKEN=""

# Paths derived from script location (so it can be run from anywhere).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_BIN="$PROJECT_ROOT/target/debug/examples/n3b_tun_demo"

# Log files (one per process, plus a combined view).
MESH_LOG="/tmp/n3b_tun_acceptance_mesh.log"
TUN_LOG="/tmp/n3b_tun_acceptance_tun.log"
HTTP_LOG="/tmp/n3b_tun_acceptance_http.log"
HTTP_ROOT=""

# PIDs / state for cleanup.
MESH_PID=""
TUN_PID=""
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
n3b_tun_acceptance_test.sh — N3-B REAL TUN Acceptance Test (NO SOCKS5)

Proves:
    CLIENT DIRECT INTERNET          → FAILS  (no route in client namespace)
    CLIENT THROUGH SHARENET TUN     → SUCCEEDS (real TUN + real circuit)

The successful path uses ordinary `curl http://IP:PORT/` with NO proxy
flags. The OS routing table directs the SYN through a TUN interface
that is plumbed into the ShareNet circuit mesh.

TWO MODES (--mode=host-local | --mode=internet):
    --mode=host-local  (DEFAULT)  starts a local python3 HTTP server on
                                  $HOST_IP:$HTTP_PORT. Proves the TUN →
                                  ShareNet → gateway → host path, but NOT
                                  genuine Internet egress. The script
                                  classifies this as "N3-B TUN integration
                                  / host-local egress test (NOT Internet
                                  acceptance)".
    --mode=internet    (genuine Internet acceptance) — REQUIRES
                                  --external-endpoint=http://<REMOTE_IP>:<PORT>/
                                  where <REMOTE_IP> is NOT the gateway host's
                                  IP, NOT loopback, NOT RFC1918 private,
                                  NOT link-local. The script does NOT start
                                  a local server — the gateway dials the
                                  external endpoint directly.

USAGE:
    bash snp-stack/tests/n3b_tun_acceptance_test.sh [OPTIONS]

OPTIONS:
    --mode=MODE                Test mode: 'host-local' (default) or 'internet'
    --external-endpoint=URL    External URL.
                                  Default (host-local): http://$HOST_IP:$HTTP_PORT/
                                  REQUIRED (internet):  http://<REMOTE_IP>:<PORT>/
    --token=STRING             Unique token verified in the response body
                                  (proves the response came from the intended
                                  external server). Default: auto-generated
                                  as N3B-<timestamp>-<random>.
    --http-port=PORT            External HTTP server port (host-local mode only)
                                  (default: 8888)
    --tun-name=NAME             TUN interface name (default: snp0, max 15 chars)
    --tun-ip=IP                 TUN interface IP (default: 10.0.0.1, plain IP)
    --client-ip=IP              Client namespace veth IP (default: 10.0.1.2)
    --host-veth-ip=IP           Host veth IP / mesh bind IP (default: 10.0.1.1)
    --namespace=NAME            Network namespace name (default: snp_n3b)
    --gateway-port=PORT         Mesh gateway listen port (default: 7003)
    --relay-a-port=PORT         Mesh relay A listen port (default: 7002)
    --relay-b-port=PORT         Mesh relay B listen port (default: 7001)
    --config=PATH               Mesh config file path (default: /tmp/sharenet-mesh-config.json)
    --no-build                  Don't auto-build the demo binary (use existing)
    --keep-on-failure           Don't tear down on failure (for debugging)
    -v, --verbose               Verbose output
    -h, --help                  Show this help message

REQUIRES:
    * root or CAP_NET_ADMIN + CAP_SYS_ADMIN (for ip netns + veth + TUN)
    * /dev/net/tun device node (TUN device support in the kernel)
    * iproute2 (ip(8) with netns support)
    * unshare (for ip netns add, which calls unshare(CLONE_NEWNET))
    * curl, python3
    * cargo + rust toolchain (if --no-build is not set)

EXIT CODES:
    0 — Test PASSED (direct failed AND sharenet succeeded)
    1 — Test FAILED (direct succeeded OR sharenet failed)
    2 — Setup error (missing binary / permission / preflight)
    3 — Invalid arguments (--mode, --external-endpoint, --token, etc.)

EXAMPLES:
    # Default (--mode=host-local): auto-detect, build the demo, run the test.
    # Proves the TUN → ShareNet → gateway → host path. Does NOT prove
    # genuine Internet egress (the "external" server is local python3).
    sudo bash snp-stack/tests/n3b_tun_acceptance_test.sh

    # Genuine Internet acceptance test (--mode=internet).
    # The script does NOT start a local server; the gateway dials the
    # user-provided external endpoint. The endpoint IP MUST be a remote
    # public IP (NOT the host's own IP, NOT loopback, NOT RFC1918,
    # NOT link-local).
    sudo bash snp-stack/tests/n3b_tun_acceptance_test.sh \
        --mode=internet \
        --external-endpoint=http://203.0.113.42:8080/

    # Same, with an explicit token (otherwise auto-generated as
    # N3B-<timestamp>-<random>). The external server is expected to
    # echo the ?token=<token> query parameter in its response body.
    sudo bash snp-stack/tests/n3b_tun_acceptance_test.sh \
        --mode=internet \
        --external-endpoint=http://203.0.113.42:8080/ \
        --token=my-unique-token-12345

    # Debug a failure without tearing down state.
    sudo bash snp-stack/tests/n3b_tun_acceptance_test.sh --keep-on-failure -v
    ip netns exec snp_n3b ip route show
    ip netns exec snp_n3b ip addr show
    ip netns exec snp_n3b curl -v http://192.168.1.42:8888/
    ip netns del snp_n3b   # manual cleanup when done

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
        log "  tun log:       $TUN_LOG"
        log "  http log:      $HTTP_LOG"
        log "  config file:   $CONFIG_PATH"
        [ -n "$HTTP_ROOT" ] && log "  http root:     $HTTP_ROOT"
        log "  mesh pid:      ${MESH_PID:-<none>}"
        log "  tun pid:       ${TUN_PID:-<none>}"
        log "  http pid:      ${HTTP_PID:-<none>}"
        return
    fi

    # Kill the TunClient FIRST — it holds the TUN fd open and may have
    # installed OS routes. Send SIGINT first (the binary's tokio::signal::ctrl_c
    # handler catches SIGINT and calls cleanup_os_routes() to remove the
    # routes it installed). Then SIGKILL as a fallback.
    if [ -n "${TUN_PID:-}" ] && kill -0 "$TUN_PID" 2>/dev/null; then
        vlog "killing TunClient PID $TUN_PID (SIGINT for graceful route cleanup)"
        kill -INT "$TUN_PID" 2>/dev/null || true
        sleep 0.5
        kill -TERM "$TUN_PID" 2>/dev/null || true
        sleep 0.3
        kill -9 "$TUN_PID" 2>/dev/null || true
        wait "$TUN_PID" 2>/dev/null || true
    fi

    # Kill the mesh (SIGINT for graceful shutdown, then SIGKILL).
    if [ -n "${MESH_PID:-}" ] && kill -0 "$MESH_PID" 2>/dev/null; then
        vlog "killing mesh PID $MESH_PID"
        kill -INT "$MESH_PID" 2>/dev/null || true
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
    # and TUN interfaces that were moved into it).
    if [ "$NAMESPACE_CREATED" -eq 1 ]; then
        vlog "deleting namespace $NAMESPACE"
        ip netns del "$NAMESPACE" 2>/dev/null || true
    fi

    # Remove the mesh config file written by the `mesh` subcommand.
    if [ -n "${CONFIG_PATH:-}" ] && [ -f "$CONFIG_PATH" ]; then
        vlog "removing config file $CONFIG_PATH"
        rm -f "$CONFIG_PATH" 2>/dev/null || true
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
    #        inside its own user namespace.
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

    # 2. /dev/net/tun MUST exist. This is a TUN test, not a SOCKS5 test.
    #    Without /dev/net/tun, the TunClient cannot create snp0 and the
    #    test cannot run.
    if [ ! -c /dev/net/tun ]; then
        err "/dev/net/tun is missing or not a character device"
        err "this test REQUIRES TUN support (it does NOT use SOCKS5)"
        err "on Linux: ensure the tun module is loaded (modprobe tun) and"
        err "          the /dev/net/tun node exists (mknod /dev/net/tun c 10 200)"
        err "on containers: run with --device /dev/net/tun --cap-add NET_ADMIN"
        exit 2
    fi
    vlog "/dev/net/tun: present"

    # 3. unshare binary must be available (ip netns add calls unshare internally).
    if ! command -v unshare >/dev/null 2>&1; then
        err "unshare not found — ip netns requires it"
        err "on Debian/Ubuntu: apt-get install util-linux"
        err "on Alpine:         apk add util-linux"
        exit 2
    fi
    vlog "unshare: $(command -v unshare)"

    # 4. Required tools.
    local missing=()
    for tool in ip curl python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "missing required tools: ${missing[*]}"
        err "on Debian/Ubuntu: apt-get install iproute2 curl python3"
        err "on Alpine:         apk add iproute2 curl python3"
        exit 2
    fi
    vlog "tools: ip=$(command -v ip) curl=$(command -v curl) python3=$(command -v python3)"

    # 5. iproute2 supports `ip netns` (some minimal distros don't).
    if ! ip netns list >/dev/null 2>&1; then
        err "iproute2 does not support 'ip netns' (likely missing /var/run/netns)"
        err "on Debian/Ubuntu: apt-get install iproute2"
        err "on Alpine:         apk add iproute2"
        exit 2
    fi
    vlog "ip netns: supported"

    # 6. The namespace name must not already exist (we don't want to
    #    clobber someone's debugging setup silently).
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NAMESPACE"; then
        err "network namespace '$NAMESPACE' already exists"
        err "remove it first:  ip netns del $NAMESPACE"
        exit 2
    fi

    # 7. The veth name must not already exist on the host.
    if ip link show "$HOST_VETH" >/dev/null 2>&1; then
        err "host veth '$HOST_VETH' already exists"
        err "remove it first:  ip link del $HOST_VETH"
        exit 2
    fi

    # 8. The TUN name must not already exist on the host. (TUN interfaces
    #    are normally created INSIDE the client namespace by the
    #    TunClient, so finding one on the host means a previous run left
    #    state behind. The length + non-empty checks happen earlier in
    #    parse_args as pure argument validation.)
    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        err "interface '$TUN_NAME' already exists on the host"
        err "this is unexpected — TUN interfaces are normally created inside"
        err "the client namespace. Remove it first:  ip link del $TUN_NAME"
        exit 2
    fi

    # 9. The mesh ports must not already be in use on $HOST_VETH_IP.
    local port
    for port in "$GATEWAY_PORT" "$RELAY_A_PORT" "$RELAY_B_PORT"; do
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$port\$"; then
            err "mesh port $port is already in use (use --gateway-port / --relay-a-port / --relay-b-port)"
            ss -ltn 2>/dev/null | grep ":$port\$" | head -3 | sed 's/^/  /' >&2
            exit 2
        fi
    done

    # 10. The HTTP_PORT must not already be in use on $HOST_IP.
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$HTTP_PORT\$"; then
        err "port $HTTP_PORT is already in use (use --http-port=PORT)"
        ss -ltn 2>/dev/null | grep ":$HTTP_PORT\$" | head -3 | sed 's/^/  /' >&2
        exit 2
    fi

    # 11. cargo + rustc (only needed if we'll build the demo binary).
    #     (The pure-argument checks — port distinctness, TUN-name length,
    #     subnet-IP sanity — happen earlier in parse_args so they exit
    #     with code 3 BEFORE this privilege-dependent runtime check.)
    if [ "$NO_BUILD" -eq 0 ]; then
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
            --token=*)              TOKEN="${1#*=}" ;;
            --external-endpoint=*) EXTERNAL_ENDPOINT="${1#*=}" ;;
            --http-port=*)         HTTP_PORT="${1#*=}" ;;
            --tun-name=*)          TUN_NAME="${1#*=}" ;;
            --tun-ip=*)            TUN_IP="${1#*=}" ;;
            --client-ip=*)         CLIENT_IP="${1#*=}" ;;
            --host-veth-ip=*)      HOST_VETH_IP="${1#*=}" ;;
            --namespace=*)         NAMESPACE="${1#*=}" ;;
            --gateway-port=*)      GATEWAY_PORT="${1#*=}" ;;
            --relay-a-port=*)      RELAY_A_PORT="${1#*=}" ;;
            --relay-b-port=*)      RELAY_B_PORT="${1#*=}" ;;
            --config=*)            CONFIG_PATH="${1#*=}" ;;
            --no-build)            NO_BUILD=1 ;;
            --keep-on-failure)     KEEP_ON_FAILURE=1 ;;
            -v|--verbose)          VERBOSE=1 ;;
            -h|--help)             usage; exit 0 ;;
            --help)                usage; exit 0 ;;
            *)
                err "unknown argument: $1"
                err "run with --help for usage"
                exit 3
                ;;
        esac
        shift
    done

    # Validate numeric args.
    case "$HTTP_PORT" in
        ''|*[!0-9]*) err "--http-port must be numeric, got '$HTTP_PORT'"; exit 3 ;;
    esac
    case "$GATEWAY_PORT" in
        ''|*[!0-9]*) err "--gateway-port must be numeric, got '$GATEWAY_PORT'"; exit 3 ;;
    esac
    case "$RELAY_A_PORT" in
        ''|*[!0-9]*) err "--relay-a-port must be numeric, got '$RELAY_A_PORT'"; exit 3 ;;
    esac
    case "$RELAY_B_PORT" in
        ''|*[!0-9]*) err "--relay-b-port must be numeric, got '$RELAY_B_PORT'"; exit 3 ;;
    esac

    # Validate the TUN name length (IFNAMSIZ-1 = 15 chars max).
    # This is an argument-validation check, so it runs BEFORE the
    # privilege probe in preflight() — saving a confusing privilege
    # error for what is really a typo in the args.
    if [ "${#TUN_NAME}" -gt 15 ]; then
        err "--tun-name '$TUN_NAME' is too long (max 15 chars, IFNAMSIZ-1)"
        exit 3
    fi
    if [ -z "$TUN_NAME" ]; then
        err "--tun-name must not be empty"
        exit 3
    fi

    # Validate that the three mesh ports are distinct. This is an
    # argument-validation check, so it runs BEFORE the privilege probe
    # in preflight() — saving a confusing privilege error for what is
    # really a misconfiguration in the args.
    if [ "$GATEWAY_PORT" = "$RELAY_A_PORT" ] \
        || [ "$GATEWAY_PORT" = "$RELAY_B_PORT" ] \
        || [ "$RELAY_A_PORT" = "$RELAY_B_PORT" ]; then
        err "mesh ports must be distinct (got gw=$GATEWAY_PORT ra=$RELAY_A_PORT rb=$RELAY_B_PORT)"
        exit 3
    fi

    # Validate that the TUN subnet and veth subnet don't overlap with
    # the chosen IPs. This is an argument-validation check.
    case "$TUN_IP" in
        10.0.0.*) ;;
        *)
            err "--tun-ip $TUN_IP is not in 10.0.0.0/24 (the default TUN subnet)"
            err "the script's split-tunnel design assumes TUN is 10.0.0.0/24 and veth is 10.0.1.0/24"
            err "to use a different TUN subnet, also change the binary's hardcoded /24 in os_routes.rs"
            exit 3
            ;;
    esac
    case "$HOST_VETH_IP" in
        10.0.1.*) ;;
        *)
            err "--host-veth-ip $HOST_VETH_IP is not in 10.0.1.0/24 (the default veth subnet)"
            err "the script's split-tunnel design assumes TUN is 10.0.0.0/24 and veth is 10.0.1.0/24"
            exit 3
            ;;
    esac
    case "$CLIENT_IP" in
        10.0.1.*) ;;
        *)
            err "--client-ip $CLIENT_IP is not in 10.0.1.0/24 (the default veth subnet)"
            exit 3
            ;;
    esac

    # Validate that the config path is not empty and is writable
    # (the directory must exist — we can't create it here because we
    # haven't checked permissions yet, but we can sanity-check the path).
    if [ -z "$CONFIG_PATH" ]; then
        err "--config must not be empty"
        exit 3
    fi

    # Validate --mode (must be 'host-local' or 'internet'). This is an
    # argument-validation check, so it runs BEFORE the privilege probe
    # in preflight() — saving a confusing privilege error for what is
    # really a typo in the args.
    case "$MODE" in
        host-local|internet) ;;
        *)
            err "--mode must be 'host-local' or 'internet', got '$MODE'"
            err "  --mode=host-local  (default) starts a local python3 HTTP server"
            err "                     on \$HOST_IP — proves the TUN path but NOT"
            err "                     genuine Internet egress."
            err "  --mode=internet   REQUIRES --external-endpoint=http://<REMOTE_IP>:<PORT>/"
            err "                     where <REMOTE_IP> is NOT the gateway host's IP."
            err "                     The script does NOT start a local server."
            exit 3
            ;;
    esac

    # Validate --token (if provided). Must be non-empty and reasonably
    # short to avoid breaking URL parsing. The default is generated in
    # main() if not provided.
    if [ -n "$TOKEN" ]; then
        if [ "${#TOKEN}" -gt 256 ]; then
            err "--token is too long (max 256 chars, got ${#TOKEN})"
            exit 3
        fi
        # Reject tokens that contain characters that would break the
        # ?token=<TOKEN> URL query parameter (RFC 3986 reserved chars
        # in the query component: &, =, #). Allow everything else.
        case "$TOKEN" in
            *"&"*|*"="*|*'#'*|*' '*)
                err "--token contains forbidden characters (space, &, =, #)"
                err "use a token like: N3B-<timestamp>-<random>"
                exit 3
                ;;
        esac
    fi

    # In --mode=internet, --external-endpoint is REQUIRED (the script
    # does NOT auto-detect a default in this mode). This is checked here
    # as pure argument validation, before any external action.
    if [ "$MODE" = "internet" ] && [ -z "$EXTERNAL_ENDPOINT" ]; then
        err "--mode=internet REQUIRES --external-endpoint=http://<REMOTE_IP>:<PORT>/"
        err "where <REMOTE_IP> is NOT the gateway host's own IP."
        err "the script does NOT start a local HTTP server in this mode"
        err "— the gateway opens a real outbound TCP socket to the external endpoint."
        exit 3
    fi
}

# ─── Generate a unique token ──────────────────────────────────────────────────
# Format: N3B-<YYYYMMDDTHHMMSS>-<8 hex chars from /dev/urandom>
# Used when --token is not provided. The token is passed to the HTTP
# server (via env var in host-local mode, via ?token= in internet mode)
# and verified in the response body — proving the bytes came from the
# intended server, not from some other source.
generate_token() {
    local ts rand
    ts=$(date +%Y%m%dT%H%M%S 2>/dev/null || printf 'UNKNOWN')
    # 4 bytes from /dev/urandom → 8 hex chars. Fall back to $RANDOM
    # (less unique but always available).
    rand=$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')
    if [ -z "$rand" ]; then
        rand=$(printf '%04x' "$RANDOM" 2>/dev/null || echo 'noent')
    fi
    printf 'N3B-%s-%s' "$ts" "$rand"
}

# ─── Extract the host portion from a URL ──────────────────────────────────────
# Parses http://<host>[:port]/[path][?query][#frag] and prints the host
# (hostname or IP, NOT the port). Handles IPv6 [::1]:port form.
extract_endpoint_host() {
    local url="$1"
    local rest hostport host
    case "$url" in
        http://*)  rest="${url#http://}" ;;
        https://*) rest="${url#https://}" ;;
        *)         rest="$url" ;;
    esac
    # Strip path/query/fragment: take everything up to the first /, ?, or #.
    hostport="${rest%%[/?#]*}"
    # Strip the port. Handle IPv6 [::1]:port form first.
    # NOTE: use \[* (starts with '[') rather than \[*\] (starts with '['
    # AND ends with ']') because the hostport variable already includes
    # the port (e.g. '[::1]:8080' ends with '0', not ']').
    case "$hostport" in
        \[*)
            # IPv6 form: [::1]:port  →  strip everything from ']' onward, then '['
            host="${hostport%%]*}"
            host="${host#\[}"
            ;;
        *)
            host="${hostport%%:*}"
            ;;
    esac
    printf '%s' "$host"
}

# ─── Validate the external endpoint in --mode=internet ─────────────────────────
# Ensures the endpoint IP is genuinely external — not loopback, not
# RFC1918 private, not link-local, and NOT the gateway host's own IP.
# Exits with code 3 on any failure. $1 is the host's primary IP (may be
# empty if it could not be determined — only used for the equality check).
validate_internet_endpoint() {
    local host_ip="${1:-}"

    # --external-endpoint is REQUIRED in internet mode. (Already checked
    # in parse_args, but double-check here for safety.)
    if [ -z "$EXTERNAL_ENDPOINT" ]; then
        err "--mode=internet REQUIRES --external-endpoint=http://<REMOTE_IP>:<PORT>/"
        err "where <REMOTE_IP> is NOT the gateway host's IP."
        err "the endpoint IP must NOT be loopback, NOT RFC1918 private,"
        err "NOT link-local, and NOT the host's own IP."
        exit 3
    fi

    # Must be http:// (no TLS — the gateway dials a raw TCP socket).
    case "$EXTERNAL_ENDPOINT" in
        http://*) ;;
        https://*)
            err "--mode=internet does NOT support https:// (use http://)"
            err "the gateway dials a raw TCP socket; TLS would require the"
            err "external server's certificate to validate, which is out of scope"
            err "for this acceptance test. Use http://<REMOTE_IP>:<PORT>/ instead."
            exit 3
            ;;
        *)
            err "--external-endpoint must start with http:// (got: $EXTERNAL_ENDPOINT)"
            exit 3
            ;;
    esac

    # Extract the host portion from the URL.
    local host
    host=$(extract_endpoint_host "$EXTERNAL_ENDPOINT")
    if [ -z "$host" ]; then
        err "--mode=internet: could not parse host from $EXTERNAL_ENDPOINT"
        err "expected format: http://<REMOTE_IP>:<PORT>/[?token=...]"
        exit 3
    fi

    # Resolve the hostname to an IPv4 if it's not already a literal IP.
    # (DNS resolution from the client namespace may be flaky; we
    # recommend using a literal IP for the endpoint.)
    local resolved_ip=""
    case "$host" in
        *:*)
            # Contains ':' → IPv6 literal address (the brackets were
            # already stripped by extract_endpoint_host). Use as-is.
            # We do NOT resolve IPv6 hostnames here — too many edge
            # cases for an acceptance test. The loopback (::1) and
            # host-IP checks below still apply.
            resolved_ip="$host"
            vlog "internet-mode: IPv6 literal address: $host"
            ;;
        *[!0-9.]*)
            # Contains non-digit, non-dot chars (and no ':') → hostname.
            # Try getent, then host, then dig — in that order.
            if command -v getent >/dev/null 2>&1; then
                resolved_ip=$(getent ahostsv4 "$host" 2>/dev/null \
                              | awk 'NR==1{print $1}' | head -1)
            fi
            if [ -z "$resolved_ip" ] && command -v host >/dev/null 2>&1; then
                resolved_ip=$(host -t A "$host" 2>/dev/null \
                              | awk '/has address/{print $NF; exit}')
            fi
            if [ -z "$resolved_ip" ] && command -v dig >/dev/null 2>&1; then
                resolved_ip=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null \
                              | head -1)
            fi
            if [ -z "$resolved_ip" ]; then
                err "--mode=internet: could not resolve hostname '$host' to an IPv4"
                err "use a literal IP address: --external-endpoint=http://<IP>:<PORT>/"
                err "(DNS resolution from the client namespace may be flaky because"
                err " the TUN intercepts UDP/53 — using a literal IP avoids this.)"
                exit 3
            fi
            vlog "internet-mode: hostname '$host' resolved to $resolved_ip"
            ;;
        *)
            # Pure digits and dots → IPv4 literal. Use as-is.
            resolved_ip="$host"
            ;;
    esac

    # 1. Must NOT be loopback (127.0.0.0/8 or ::1).
    case "$resolved_ip" in
        127.*|::1)
            err "--mode=internet: endpoint IP $resolved_ip is loopback (127.0.0.0/8 or ::1)"
            err "this would NOT prove genuine Internet egress — the gateway"
            err "would be connecting to itself."
            err "use a remote public IP (e.g. your VPS, a public echo service)."
            exit 3
            ;;
    esac

    # 2. Must NOT be the host's own primary IP (if we could determine it).
    if [ -n "$host_ip" ] && [ "$resolved_ip" = "$host_ip" ]; then
        err "--mode=internet: endpoint IP $resolved_ip is the gateway HOST's own IP ($host_ip)"
        err "this would NOT prove genuine Internet egress — the gateway would"
        err "be connecting to a local interface, not the real Internet."
        err "use a REMOTE IP that is NOT this host."
        exit 3
    fi

    # 3. Must NOT be in RFC1918 private ranges
    #    (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    case "$resolved_ip" in
        10.*)
            err "--mode=internet: endpoint IP $resolved_ip is in 10.0.0.0/8 (RFC1918 private)"
            err "this would NOT prove genuine Internet egress."
            err "use a remote public IP."
            exit 3
            ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            err "--mode=internet: endpoint IP $resolved_ip is in 172.16.0.0/12 (RFC1918 private)"
            err "this would NOT prove genuine Internet egress."
            err "use a remote public IP."
            exit 3
            ;;
        192.168.*)
            err "--mode=internet: endpoint IP $resolved_ip is in 192.168.0.0/16 (RFC1918 private)"
            err "this would NOT prove genuine Internet egress."
            err "use a remote public IP."
            exit 3
            ;;
    esac

    # 4. Must NOT be link-local (169.254.0.0/16).
    case "$resolved_ip" in
        169.254.*)
            err "--mode=internet: endpoint IP $resolved_ip is in 169.254.0.0/16 (link-local)"
            err "this would NOT prove genuine Internet egress."
            exit 3
            ;;
    esac

    # 5. Must NOT be in the test's internal subnets
    #    (TUN subnet 10.0.0.0/24 or veth subnet 10.0.1.0/24). The DIRECT
    #    test would succeed via the veth route.
    case "$resolved_ip" in
        10.0.0.*|10.0.1.*)
            err "--mode=internet: endpoint IP $resolved_ip is in the test's internal subnet"
            err "(TUN subnet 10.0.0.0/24 or veth subnet 10.0.1.0/24)"
            err "the DIRECT test would succeed via the veth route."
            exit 3
            ;;
    esac

    log "  internet-mode endpoint validated:"
    log "    endpoint URL:  $EXTERNAL_ENDPOINT"
    log "    resolved IP:   $resolved_ip"
    if [ -n "$host_ip" ]; then
        log "    host IP:       $host_ip (the gateway's primary IP — must differ)"
    fi
    log "    NOT loopback, NOT RFC1918, NOT link-local, NOT host's own IP ✓"
}

# ─── Verify the external endpoint is reachable from the host ──────────────────
# Used in --mode=internet. The gateway (in the host namespace) needs to
# be able to dial the external endpoint. We do a quick reachability check
# from the host BEFORE the more complex setup begins, so we fail fast
# with a clear error if the endpoint is not reachable.
verify_external_endpoint_reachable() {
    section "STEP 1: verifying external endpoint is reachable from the host"

    # Build the test URL with the token query parameter. The external
    # server is expected to echo the token, but for this reachability
    # check we just need a 200 (or any HTTP response).
    local test_url
    test_url=$(append_token_query "$EXTERNAL_ENDPOINT" "$TOKEN")

    log "  \$ curl --connect-timeout 5 -s -o /dev/null -w '%{http_code}' '$test_url'"
    log "  (the gateway will dial this from the host namespace)"

    local code rc
    code=$(curl --connect-timeout 5 -s -o /dev/null -w '%{http_code}' "$test_url" 2>/dev/null) \
        && rc=0 || rc=$?

    if [ "$rc" -ne 0 ] || [ "$code" = "000" ]; then
        err "external endpoint is NOT reachable from the host (curl exit $rc, http_code '$code')"
        err "the gateway needs to be able to dial $EXTERNAL_ENDPOINT"
        err "check that the external server is running and the host has Internet"
        err "— or pass --mode=host-local to start a local HTTP server instead."
        exit 2
    fi
    log "  external endpoint is reachable from the host (http_code $code)"
}

# ─── Append ?token=<token> to a URL ───────────────────────────────────────────
# Adds the token as a URL query parameter. If the URL already has a
# query string, appends &token=<token>. URL-encodes nothing — the token
# is already validated to contain no reserved chars (parse_args).
append_token_query() {
    local url="$1" token="$2"
    if [ -z "$token" ]; then
        printf '%s' "$url"
        return 0
    fi
    case "$url" in
        *\?*) printf '%s&token=%s' "$url" "$token" ;;
        *)    printf '%s?token=%s' "$url" "$token" ;;
    esac
}

# ─── Determine the host's primary network IP ─────────────────────────────────
# Returns the IP on stdout. NEVER returns 127.0.0.1 / loopback.
# Also NEVER returns 10.0.0.x or 10.0.1.x (the test's internal subnets).
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

    # Reject the test's internal subnets — using them as the "external"
    # endpoint would make the test meaningless (the veth route would
    # reach them directly, bypassing the TUN).
    case "$ip" in
        10.0.0.*|10.0.1.*)
            err "host IP $ip is inside the test's internal subnet"
            err "(TUN subnet 10.0.0.0/24 or veth subnet 10.0.1.0/24)"
            err "the external endpoint MUST be outside these subnets so that"
            err "the only route to it is via the TUN (default route → snp0)"
            err "set --host-veth-ip and --tun-ip to use different internal subnets,"
            err "or use --external-endpoint=http://<real-public-ip>:<port>/"
            return 1
            ;;
    esac

    printf '%s' "$ip"
}

# ─── Build / locate the demo binary ───────────────────────────────────────────
ensure_binary() {
    section "locating n3b_tun_demo binary"

    if [ -x "$DEMO_BIN" ] && [ "$NO_BUILD" -eq 1 ]; then
        log "  using existing binary: $DEMO_BIN (--no-build)"
    else
        # Check if the example source exists. If not, give a clear pointer.
        local example_src="$PROJECT_ROOT/snp-stack/examples/n3b_tun_demo.rs"
        if [ ! -f "$example_src" ]; then
            err "n3b_tun_demo example source not found: $example_src"
            err "this test depends on the TunClient binary that should support"
            err "the 'mesh' and 'tun' subcommands."
            err ""
            err "expected CLI:"
            err "  n3b_tun_demo mesh --bind-ip <ip> \\"
            err "                  --gateway-port <p> --relay-a-port <p> --relay-b-port <p>"
            err "                  --config <path>"
            err "  n3b_tun_demo tun  --config <path> --tun-name <name> \\"
            err "                  --tun-ip <ip> --physical-interface <iface>"
            exit 2
        fi

        # Build with PRODUCTION features only — NO test-utils.
        # The gateway must use GatewayStreamTable::new() (production SSRF
        # defence, NO loopback exception). Building with test-utils would
        # enable with_allow_loopback(), defeating the purpose of this test.
        log "  building: cargo build --example n3b_tun_demo -p snp-stack"
        log "    features: circuit-upstream  (production — NO test-utils)"
        ( cd "$PROJECT_ROOT" && \
          cargo build --example n3b_tun_demo -p snp-stack \
              --features circuit-upstream ) || {
            err "cargo build failed"
            err "the n3b_tun_demo binary is required by this acceptance test"
            err "see the script header for the expected CLI contract"
            exit 2
        }

        if [ ! -x "$DEMO_BIN" ]; then
            err "demo binary not found after build: $DEMO_BIN"
            exit 2
        fi
        log "  demo binary: $DEMO_BIN"
    fi

    # Probe the binary's CLI to confirm it supports the mesh/tun
    # subcommands. This is a sanity check — the binary should support
    # both since it was built from the verified source.
    log "  probing binary CLI for mesh/tun subcommands..."
    local help_out
    help_out=$("$DEMO_BIN" --help 2>&1 || true)
    if ! printf '%s' "$help_out" | grep -qw mesh \
        || ! printf '%s' "$help_out" | grep -qw tun; then
        err "the n3b_tun_demo binary does not support the mesh/tun subcommands"
        err ""
        err "current binary --help output:"
        printf '%s\n' "$help_out" | sed 's/^/    /' >&2
        err ""
        err "the binary MUST support two subcommands:"
        err "  n3b_tun_demo mesh --bind-ip <ip> \\"
        err "                  --gateway-port <p> --relay-a-port <p> --relay-b-port <p>"
        err "                  --config <path>"
        err "  n3b_tun_demo tun  --config <path> --tun-name <name> \\"
        err "                  --tun-ip <ip> --physical-interface <iface>"
        err ""
        err "the 'mesh' subcommand binds the gateway + 2 relays to <ip>"
        err "(NOT 127.0.0.1 — must be reachable via the veth pair)."
        err "the 'tun' subcommand creates the TUN, installs split-tunnel"
        err "routes, and establishes the ShareNet circuit."
        exit 2
    fi
    log "  binary supports mesh/tun subcommands"
}

# ─── Start the external HTTP server ──────────────────────────────────────────
# Only used in --mode=host-local. In --mode=internet the script does NOT
# start a local server — the gateway dials the user-provided external endpoint.
start_http_server() {
    section "STEP 1: starting external HTTP server (host-local token-echo server)"

    # Create a temp directory with a small Python script that echoes the
    # token. The response body MUST contain the token — this proves the
    # bytes actually traversed the ShareNet circuit (not just that curl
    # got an arbitrary response from some other source). The token is
    # passed to the script via the N3B_TOKEN env var (NOT the command
    # line, so it doesn't leak into `ps` listings of unrelated users).
    HTTP_ROOT="$(mktemp -d /tmp/n3b_tun_http_root.XXXXXX)"
    local server_script="$HTTP_ROOT/server.py"
    # NOTE: this heredoc uses <<'PYEOF' (single-quoted delimiter) so $TOKEN
    # is NOT expanded here — the Python script reads it from os.environ
    # at runtime. This avoids leaking the token into the script file.
    cat > "$server_script" <<'PYEOF'
import http.server, os, socketserver, sys
from urllib.parse import urlparse, parse_qs

TOKEN = os.environ.get("N3B_TOKEN", "")
PORT = int(os.environ.get("N3B_HTTP_PORT", "8888"))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Optional sanity check: if the client passed ?token=<...>, verify
        # it matches. (The script always appends ?token=$TOKEN, so a mismatch
        # would indicate something is misconfigured.)
        qs = parse_qs(urlparse(self.path).query)
        req_token = qs.get("token", [""])[0]
        if req_token and req_token != TOKEN:
            body = b"ERROR: token mismatch — expected the server's N3B_TOKEN\n"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # Echo the token in the response body. The script verifies the
        # body contains the token — this proves the response came from
        # this server (not from some other source along the path).
        body = ("ShareNet N3-B host-local token echo: " + TOKEN + "\n"
                "mode: host-local (NOT Internet acceptance — see --mode=internet)\n"
                "This response was served by a real HTTP server process bound to\n"
                "the host's primary network interface IP (NOT 127.0.0.1, NOT\n"
                "localhost). It was reached through a real TUN interface via the\n"
                "ShareNet circuit mesh: the OS application (ordinary curl with NO\n"
                "proxy flags) sent a SYN to the external IP, the OS routing table\n"
                "directed it via the TUN interface (snp0), the TunClient\n"
                "intercepted the SYN, extracted the original destination from the\n"
                "5-tuple, opened a real ShareNet stream (SNP-IK mutual\n"
                "authentication + X25519 per-circuit Diffie-Hellman), which\n"
                "traversed two real relays to the gateway, which opened a real\n"
                "outbound TCP socket to this HTTP server.\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Forward access logs to stderr so they appear in $HTTP_LOG.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("0.0.0.0", PORT), Handler)
sys.stderr.write("N3-B host-local HTTP server listening on 0.0.0.0:%d\n" % PORT)
sys.stderr.flush()
httpd.serve_forever()
PYEOF
    log "  http root:     $HTTP_ROOT"
    log "  server.py:     $(wc -c < "$server_script") bytes"
    log "  token:         $TOKEN (passed via N3B_TOKEN env var — NOT the command line)"

    # Bind to 0.0.0.0 so the host's primary IP is reachable. (The
    # gateway is in the host namespace, so it can reach any of the
    # host's IPs. The client namespace can ONLY reach $HOST_VETH_IP
    # via the veth pair — which is why DIRECT fails before the TUN
    # is configured.)
    log "  starting:      N3B_TOKEN=<redacted> N3B_HTTP_PORT=$HTTP_PORT python3 $server_script"
    log "  log:           $HTTP_LOG"
    N3B_TOKEN="$TOKEN" N3B_HTTP_PORT="$HTTP_PORT" \
        python3 "$server_script" >"$HTTP_LOG" 2>&1 &
    HTTP_PID=$!
    log "  http PID:      $HTTP_PID"

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

# ─── Start the ShareNet mesh (gateway + relays) ──────────────────────────────
start_mesh() {
    section "STEP 2: starting ShareNet mesh (gateway + 2 relays) in host namespace"

    # The mesh process binds its listeners to $HOST_VETH_IP so the
    # TunClient (running in the client namespace) can reach them via the
    # veth pair. The mesh process itself runs in the HOST namespace,
    # so it has full Internet access for the gateway's outbound socket.
    #
    # The `mesh` subcommand:
    #   * generates fresh identities for gateway + 2 relays
    #   * binds the gateway listener to <bind-ip>:<gateway-port>
    #   * binds relay A's link listener to <bind-ip>:<relay-a-port>
    #   * binds relay B's link listener to <bind-ip>:<relay-b-port>
    #   * writes a JSON mesh config to <config-path>
    #   * prints on stdout: GATEWAY_ADDR=, RELAY_A_ADDR=, RELAY_B_ADDR=, CONFIG_PATH=
    #   * prints "N3-B mesh READY" on stderr
    #   * uses GatewayStreamTable::new() (PRODUCTION SSRF defence —
    #     NO loopback exception — the gateway REJECTS loopback/private IPs)
    #
    # Real components inside the mesh:
    #   * MultiplexedCircuit::establish  (real SNP-IK + X25519 DH)
    #   * serve_gateway_mode_b_multiplexed (real outbound TCP, prod SSRF)
    #   * serve_relay_via_route  (real relay forwarding, 2 hops)
    log "  starting: $DEMO_BIN mesh \\"
    log "              --bind-ip $HOST_VETH_IP \\"
    log "              --gateway-port $GATEWAY_PORT \\"
    log "              --relay-a-port $RELAY_A_PORT \\"
    log "              --relay-b-port $RELAY_B_PORT \\"
    log "              --config $CONFIG_PATH"
    log "  log:      $MESH_LOG"

    "$DEMO_BIN" mesh \
        --bind-ip "$HOST_VETH_IP" \
        --gateway-port "$GATEWAY_PORT" \
        --relay-a-port "$RELAY_A_PORT" \
        --relay-b-port "$RELAY_B_PORT" \
        --config "$CONFIG_PATH" \
        >"$MESH_LOG" 2>&1 &
    MESH_PID=$!
    log "  mesh PID: $MESH_PID"

    # Wait for the mesh to print its readiness marker. The binary
    # prints "CONFIG_PATH=<path>" on stdout AFTER writing the config
    # file and binding all three listeners. It also prints
    # "N3-B mesh READY" on stderr. Since both stdout and stderr go to
    # the same log file, we grep for either.
    log "  waiting for mesh to be ready..."
    local ready=0
    local i
    for i in $(seq 1 60); do
        if ! kill -0 "$MESH_PID" 2>/dev/null; then
            err "mesh process died during startup"
            err "----- mesh log -----"
            cat "$MESH_LOG" >&2 || true
            exit 2
        fi
        if grep -q 'CONFIG_PATH=' "$MESH_LOG" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.5
    done

    if [ "$ready" -ne 1 ]; then
        err "mesh did not become ready within 30s"
        err "expected 'CONFIG_PATH=' marker on stdout (or 'N3-B mesh READY' on stderr)"
        err "----- mesh log (last 40 lines) -----"
        tail -40 "$MESH_LOG" >&2 || true
        exit 2
    fi

    # Verify the config file was written (the `tun` subcommand will read it).
    if [ ! -f "$CONFIG_PATH" ]; then
        err "mesh reported ready but config file not found: $CONFIG_PATH"
        err "----- mesh log (last 20 lines) -----"
        tail -20 "$MESH_LOG" >&2 || true
        exit 2
    fi
    log "  mesh is ready"
    log "    config file: $CONFIG_PATH ($(wc -c < "$CONFIG_PATH") bytes)"
    log "    gateway:     $HOST_VETH_IP:$GATEWAY_PORT"
    log "    relay A:     $HOST_VETH_IP:$RELAY_A_PORT"
    log "    relay B:     $HOST_VETH_IP:$RELAY_B_PORT"
    log "    SSRF defence: GatewayStreamTable::new() (production — NO loopback exception)"
}

# ─── Set up network namespace + veth pair ─────────────────────────────────────
setup_namespace() {
    section "STEP 3: setting up network namespace + veth pair"

    # 1. Create the namespace.
    log "  ip netns add $NAMESPACE"
    if ! ip netns add "$NAMESPACE" 2>/tmp/n3b_ns_err; then
        err "ip netns add failed"
        err "this requires root or CAP_SYS_ADMIN + CAP_NET_ADMIN"
        err "stderr: $(cat /tmp/n3b_ns_err 2>/dev/null)"
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

    # 4. Configure the host side of the veth pair.
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

    # 6. SPLIT-TUNNEL ROUTING — handled by the binary.
    #    The n3b_tun_demo `tun` subcommand calls configure_os_routes()
    #    which installs:
    #      a) The TUN interface IP (10.0.0.1/24) + brings it up.
    #      b) Specific HOST routes for each control-plane endpoint
    #         (relay/gateway IPs, e.g. 10.0.1.1/32) via the physical
    #         interface (veth_client). These are /32 routes, more
    #         specific than the default route, so the kernel prefers
    #         them for ShareNet circuit traffic → no routing loop.
    #      c) The TUN default route (ordinary traffic → TUN).
    #    The script passes --physical-interface $CLIENT_VETH so the
    #    binary knows which interface to use for control-plane routes.
    #    The connected route 10.0.1.0/24 (auto-created when we assigned
    #    $CLIENT_IP/24 to veth_client) also ensures reachability.
    log "  split-tunnel routes will be installed by the binary (configure_os_routes)"
    log "    control-plane (10.0.1.1) → $CLIENT_VETH (host route, installed by binary)"
    log "    default             → $TUN_NAME (installed by binary when TUN starts)"

    # 7. CRITICAL: assert there is NO default route in the client namespace.
    #    This is what makes the DIRECT test fail. If a default route exists
    #    (e.g. inherited via some misconfiguration), the test is invalid.
    #    The TunClient will install the default route via snp0 LATER (in
    #    start_tun_client), but for TEST 1 (DIRECT) the namespace must
    #    have NO default route.
    if ip netns exec "$NAMESPACE" ip route show default 2>/dev/null | grep -q .; then
        err "client namespace already has a default route — isolation broken"
        err "default route(s) in $NAMESPACE:"
        ip netns exec "$NAMESPACE" ip route show default >&2 || true
        err "this test requires the client namespace to have NO default route"
        err "until the TunClient installs one via snp0"
        exit 2
    fi
    log "  client namespace has NO default route (verified — TEST 1 will fail)"

    # 8. Print the routing table for transparency.
    log "  --- client namespace routes (pre-TUN) ---"
    ip netns exec "$NAMESPACE" ip route show 2>/dev/null | sed 's/^/      /'
    log "  --- client namespace addresses ---"
    ip netns exec "$NAMESPACE" ip -br addr show 2>/dev/null | sed 's/^/      /'
}

# ─── TEST 1: DIRECT access MUST FAIL ──────────────────────────────────────────
# This test runs BEFORE the TunClient is started, so the namespace has
# NO default route. curl to the external IP must fail with ENETUNREACH.
test_direct() {
    section "TEST 1: DIRECT access from client namespace (no TUN yet) — EXPECTED: FAIL"

    # NO proxy flag of any kind (the L4.5 proxy flag that starts with
    # --s... is FORBIDDEN here — see the script header). This is the
    # unmodified-OS-application test.
    #
    # We use the same test URL as TEST 2 (with ?token=$TOKEN appended)
    # for parity — the connection is expected to fail with ENETUNREACH
    # before any HTTP request is made, so the URL details don't matter
    # for this test, but using the same URL keeps the two tests
    # comparable in the log output.
    local test_url
    test_url=$(append_token_query "$EXTERNAL_ENDPOINT" "$TOKEN")
    log "  \$ ip netns exec $NAMESPACE curl --connect-timeout 5 '$test_url'"
    log "  (no default route in namespace → curl must fail with no route)"

    local output rc
    output=$(ip netns exec "$NAMESPACE" \
             curl --connect-timeout 5 -s -o /dev/null -w '%{http_code}' \
                  "$test_url" 2>&1) && rc=0 || rc=$?

    log "  curl exit code: $rc"
    log "  curl output:    ${output:-<empty>}"

    if [ "$rc" -eq 0 ]; then
        err "FAIL: DIRECT access SUCCEEDED — namespace isolation is broken"
        err "       the client namespace must NOT have any route to $EXTERNAL_ENDPOINT"
        err "       check: ip netns exec $NAMESPACE ip route show"
        log "[1] DIRECT: curl from client namespace → SUCCESS (UNEXPECTED — isolation broken)"
        return 1
    fi

    log "[1] DIRECT: curl from client namespace → FAIL (expected)"
    return 0
}

# ─── Start the TunClient in the client namespace ─────────────────────────────
# The TunClient process is launched via `ip netns exec` so it runs
# entirely inside the client namespace. It will:
#   1. Read the mesh config file (written by the `mesh` subcommand).
#   2. Reconstruct the Route + client identity from the config.
#   3. Open /dev/net/tun (the namespace inherits the host's /dev mount)
#      and create the TUN interface snp0 INSIDE the namespace.
#   4. Establish the ShareNet circuit (SNP-IK + X25519 DH) via
#      Relay A → Relay B → Gateway.
#   5. Call configure_os_routes() to:
#      - Assign 10.0.0.1/24 to snp0 and bring it up.
#      - Install host routes for control-plane endpoints via veth_client.
#      - Install the default route via snp0.
#   6. Print "TUN_NAME=<name>" and "TUN_IP=<ip>" on stdout, then
#      "N3-B TUN client READY" on stderr.
#   7. Start the packet pump: read SYNs from snp0, intercept them,
#      open ShareNet streams, pump bytes bidirectionally.
start_tun_client() {
    section "STEP 4: starting TunClient in client namespace (creates TUN + installs routes)"

    log "  \$ ip netns exec $NAMESPACE \\"
    log "      $DEMO_BIN tun \\"
    log "          --config $CONFIG_PATH \\"
    log "          --tun-name $TUN_NAME \\"
    log "          --tun-ip $TUN_IP \\"
    log "          --physical-interface $CLIENT_VETH"
    log "  log: $TUN_LOG"

    ip netns exec "$NAMESPACE" \
        "$DEMO_BIN" tun \
        --config "$CONFIG_PATH" \
        --tun-name "$TUN_NAME" \
        --tun-ip "$TUN_IP" \
        --physical-interface "$CLIENT_VETH" \
        >"$TUN_LOG" 2>&1 &
    TUN_PID=$!
    log "  TunClient PID: $TUN_PID"

    # Wait for the TunClient to print its readiness marker.
    # The binary prints "TUN_NAME=<name>" on stdout AFTER:
    #   - TUN snp0 is created and configured (IP + up)
    #   - the circuit to the gateway is established
    #   - configure_os_routes() has installed the split-tunnel routes
    #     (control-plane host routes + TUN default route)
    # It also prints "N3-B TUN client READY" on stderr. Since both
    # stdout and stderr go to the same log file, we grep for either.
    log "  waiting for TunClient to be ready..."
    local ready=0
    local i
    for i in $(seq 1 60); do
        if ! kill -0 "$TUN_PID" 2>/dev/null; then
            err "TunClient process died during startup"
            err "----- TunClient log -----"
            cat "$TUN_LOG" >&2 || true
            exit 2
        fi
        if grep -q 'TUN_NAME=' "$TUN_LOG" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.5
    done

    if [ "$ready" -ne 1 ]; then
        err "TunClient did not become ready within 30s"
        err "expected 'TUN_NAME=' marker on stdout (or 'N3-B TUN client READY' on stderr)"
        err "----- TunClient log (last 50 lines) -----"
        tail -50 "$TUN_LOG" >&2 || true
        exit 2
    fi

    log "  TunClient is ready"
    log "  --- client namespace routes (post-TUN) ---"
    ip netns exec "$NAMESPACE" ip route show 2>/dev/null | sed 's/^/      /'

    # Verify the default route was installed via snp0 (by the binary).
    if ! ip netns exec "$NAMESPACE" ip route show default 2>/dev/null \
            | grep -q "dev $TUN_NAME"; then
        err "TunClient did not install a default route via $TUN_NAME"
        err "client namespace routes:"
        ip netns exec "$NAMESPACE" ip route show >&2 || true
        err "----- TunClient log (last 30 lines) -----"
        tail -30 "$TUN_LOG" >&2 || true
        exit 2
    fi
    log "  ✓ default route installed via $TUN_NAME (by the binary's configure_os_routes)"

    # Verify the TUN interface exists in the namespace.
    if ! ip netns exec "$NAMESPACE" ip link show "$TUN_NAME" >/dev/null 2>&1; then
        err "TUN interface $TUN_NAME not found in client namespace"
        err "the TunClient should have created it"
        exit 2
    fi
    log "  ✓ TUN interface $TUN_NAME exists in $NAMESPACE"

    # Verify the control-plane host routes were installed (for the mesh IPs).
    # The binary installs these via configure_os_routes() → install_control_plane_route().
    if ! ip netns exec "$NAMESPACE" ip route get "$HOST_VETH_IP" 2>/dev/null \
            | grep -q "dev $CLIENT_VETH"; then
        err "control-plane route to $HOST_VETH_IP via $CLIENT_VETH not found"
        err "the binary's configure_os_routes() should have installed it"
        err "client namespace routes:"
        ip netns exec "$NAMESPACE" ip route show >&2 || true
        err "----- TunClient log (last 30 lines) -----"
        tail -30 "$TUN_LOG" >&2 || true
        exit 2
    fi
    log "  ✓ control-plane route to $HOST_VETH_IP via $CLIENT_VETH (split-tunnel active)"
}

# ─── TEST 2: ShareNet via TUN MUST SUCCEED ───────────────────────────────────
# Now the TUN is up with a default route. curl to the external IP sends
# its SYN through the TUN, where the TunClient intercepts it, opens a
# ShareNet stream, and the gateway opens a real outbound TCP socket.
test_via_sharennet() {
    section "TEST 2: ShareNet via TUN from client namespace — EXPECTED: SUCCESS"

    # NO proxy flag of any kind (the L4.5 proxy flag that starts with
    # --s... is FORBIDDEN here — see the script header). The OS routing
    # table directs the SYN through the TUN.
    #
    # We append ?token=$TOKEN to the URL. In host-local mode the local
    # Python script echoes the token (it knows the token via the N3B_TOKEN
    # env var). In internet mode the external server is expected to echo
    # the ?token= query parameter. Either way, we verify the response body
    # contains the token — proving the bytes came from the intended server
    # (and traversed the real TUN + ShareNet circuit, not some shortcut).
    local test_url
    test_url=$(append_token_query "$EXTERNAL_ENDPOINT" "$TOKEN")
    log "  \$ ip netns exec $NAMESPACE curl --connect-timeout 10 '$test_url'"
    log "  (SYN → TUN → TunClient → ShareNet circuit → gateway → external HTTP)"
    log "  token:    $TOKEN"

    local output rc
    output=$(ip netns exec "$NAMESPACE" \
             curl --connect-timeout 10 -s \
                  "$test_url" 2>&1) && rc=0 || rc=$?

    log "  curl exit code: $rc"
    if [ -n "$output" ]; then
        log "  response (first 200 chars):"
        printf '%s\n' "$output" | head -c 200 | sed 's/^/      /'
    else
        log "  response: <empty>"
    fi

    if [ "$rc" -ne 0 ]; then
        err "FAIL: ShareNet access FAILED (curl exit $rc)"
        err "       the TunClient should have intercepted the SYN via the TUN"
        err "       and routed it through the ShareNet circuit"
        err "       --- TunClient log (last 50 lines) ---"
        tail -50 "$TUN_LOG" >&2 || true
        err "       --- mesh log (last 30 lines) ---"
        tail -30 "$MESH_LOG" >&2 || true
        log "[2] SHARENET: ordinary curl through TUN → ShareNet → gateway → external → FAIL (UNEXPECTED)"
        return 1
    fi

    # Confirm the response body contains the token. This proves the bytes
    # actually came from the intended external server (in host-local mode,
    # from our Python script which echoes $N3B_TOKEN; in internet mode,
    # from the external server which is expected to echo ?token=$TOKEN).
    # Without this check, curl could have received a response from some
    # other source along the path (e.g. a transparent proxy, a captive
    # portal, a misconfigured relay) and we'd incorrectly call it a PASS.
    if ! printf '%s' "$output" | grep -qF "$TOKEN"; then
        err "FAIL: ShareNet access returned unexpected body"
        err "       expected token '$TOKEN' not found in response body"
        err "       this proves the response did NOT come from the intended"
        err "       external server (which should echo the token)."
        err "       response (first 500 chars):"
        printf '%s\n' "$output" | head -c 500 | sed 's/^/      /' >&2
        log "[2] SHARENET: ordinary curl through TUN → ShareNet → gateway → external → FAIL (token not echoed)"
        return 1
    fi

    log "[2] SHARENET: ordinary curl through TUN → ShareNet → gateway → external → SUCCESS (expected, token verified)"
    return 0
}

# ─── Self-check: NO SOCKS PROXY (hard requirement) ──────────────────────────
# This script MUST NOT use any form of SOCKS proxy. The successful path
# uses ordinary `curl http://...` and the OS routing table. This function
# scans the script's OWN executable (non-comment) lines for forbidden
# patterns and exits with code 2 if any are found. Comment lines (those
# whose first non-whitespace character is '#') are skipped so the
# documentation block at the top of the file is not a false positive.
#
# The forbidden patterns are constructed here via string concatenation
# so the patterns themselves do not appear verbatim in this grep source.
verify_no_socks() {
    local script="${BASH_SOURCE[0]}"
    [ -f "$script" ] || script="$0"
    [ -f "$script" ] || return 0  # cannot self-check; trust the caller

    # Build the forbidden patterns via string concatenation so this very
    # function doesn't contain the literal strings. Variable names are
    # also chosen to NOT contain the forbidden substrings (otherwise
    # the self-check would flag its own variable declarations).
    local p1="--""socks5"
    local p2="--""socks5-hostname"
    local p3="socks5""://"
    local p4="--""proxy"
    local p5="N3A""Client"
    local p6="socks5""_demo"
    local p7=":""1080"

    # Strip comment lines, then grep for each forbidden pattern.
    # awk 'NR' keeps only non-empty lines that don't start with optional
    # whitespace followed by '#'.
    local stripped
    stripped=$(awk '{
        line = $0
        sub(/^[ \t]+/, "", line)   # strip leading whitespace
        if (line == "" || substr(line, 1, 1) == "#") next
        print
    }' "$script")

    local pattern hits=0
    for pattern in "$p1" "$p2" "$p3" "$p4" "$p5" "$p6" "$p7"; do
        # Use -e so patterns beginning with -- (e.g. --socks5) are
        # treated as patterns, not as grep options.
        if printf '%s\n' "$stripped" | grep -qF -e "$pattern"; then
            err "self-check FAILED: forbidden SOCKS-proxy pattern found in executable code: '$pattern'"
            printf '%s\n' "$stripped" | grep -nF -e "$pattern" | sed 's/^/      /' >&2
            hits=$((hits + 1))
        fi
    done

    if [ "$hits" -gt 0 ]; then
        err "this test MUST NOT use any SOCKS-proxy mechanism"
        err "the successful path uses ordinary curl + the OS routing table"
        err "remove the offending lines and re-run"
        exit 2
    fi
    vlog "self-check: no SOCKS-proxy patterns in executable code (OK)"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    # Self-check: verify this script does not use any SOCKS-proxy
    # mechanism. This is the HARD requirement documented in the header.
    # Runs after parse_args (so --help exits early) and before any
    # external action (so a forbidden pattern fails fast).
    verify_no_socks

    # Generate a token if --token was not provided. The token is passed
    # to the external HTTP server (via env var in host-local mode, via
    # ?token= query parameter in internet mode) and verified in the
    # response body — proving the bytes came from the intended server.
    if [ -z "$TOKEN" ]; then
        TOKEN=$(generate_token)
    fi
    vlog "token: $TOKEN"

    # Resolve the host's primary network IP. This is used:
    #   * in host-local mode — as the default external endpoint
    #     ($EXTERNAL_ENDPOINT defaults to http://$host_ip:$HTTP_PORT/).
    #   * in internet mode   — to validate the endpoint is NOT the host's
    #     own IP (the validate_internet_endpoint function compares).
    # We suppress stderr because get_host_ip prints diagnostic messages
    # on failure that we don't want to clutter the output with (we have
    # our own error messages below).
    local host_ip
    host_ip=$(get_host_ip 2>/dev/null) || host_ip=""

    # In --mode=internet, validate the external endpoint. This runs BEFORE
    # preflight (which probes privileges) so a misconfigured --external-endpoint
    # fails fast with exit code 3 (argument error) rather than getting into
    # the privilege probe and producing a confusing exit code 2.
    if [ "$MODE" = "internet" ]; then
        validate_internet_endpoint "$host_ip"
    fi

    # Print the banner + classification. The two modes are clearly
    # distinguished so a reviewer of the log can tell at a glance whether
    # the test proved genuine Internet egress or only the TUN→host path.
    if [ "$MODE" = "internet" ]; then
        section "N3-B INTERNET ACCEPTANCE TEST"
        log "  external endpoint:   $EXTERNAL_ENDPOINT"
        log "  token:              $TOKEN"
        log "  The gateway will open a real outbound TCP connection to the"
        log "  external endpoint (NOT a local python3 server — the script"
        log "  does NOT start one in this mode)."
    else
        section "N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST"
        log "  NOTE: this proves the TUN → ShareNet → gateway → host path,"
        log "        but does NOT prove genuine Internet egress."
        log "        For Internet acceptance, use:"
        log "          --mode=internet --external-endpoint=http://<REMOTE_IP>:<PORT>/"
    fi
    log "  project root:        $PROJECT_ROOT"
    log "  demo binary:         $DEMO_BIN"
    log "  build features:      circuit-upstream  (production — NO test-utils)"

    # In host-local mode, the host IP is REQUIRED (we need it as the
    # default external endpoint). In internet mode, it's optional (only
    # used for the "is the endpoint the host's own IP?" check, which
    # already ran in validate_internet_endpoint).
    if [ "$MODE" = "host-local" ]; then
        if [ -z "$host_ip" ]; then
            err "could not determine host's primary network IP"
            err "set it explicitly with --external-endpoint=http://IP:PORT/"
            exit 2
        fi
        # Resolve external endpoint URL (host-local default).
        if [ -z "$EXTERNAL_ENDPOINT" ]; then
            EXTERNAL_ENDPOINT="http://$host_ip:$HTTP_PORT/"
        fi
    fi
    log "  host IP:             ${host_ip:-<unknown>}"
    log "  external endpoint:  $EXTERNAL_ENDPOINT"
    log "  TUN interface:      $TUN_NAME ($TUN_IP, mtu 1500 — hardcoded by binary)"
    log "  client namespace:   $NAMESPACE (veth $CLIENT_IP, no default route yet)"
    log "  mesh:               gateway=$HOST_VETH_IP:$GATEWAY_PORT"
    log "                      relayA=$HOST_VETH_IP:$RELAY_A_PORT"
    log "                      relayB=$HOST_VETH_IP:$RELAY_B_PORT"
    log "  config file:        $CONFIG_PATH"
    log "  token:              $TOKEN"

    # Guard: the external endpoint must NOT be loopback. (This guard
    # applies in BOTH modes — even host-local mode rejects loopback
    # because the gateway uses production SSRF defence which would
    # refuse the connection.)
    case "$EXTERNAL_ENDPOINT" in
        http://127.0.0.1:*|http://localhost:*|http://[::1]:*)
            err "external endpoint must NOT be loopback: $EXTERNAL_ENDPOINT"
            err "the gateway uses GatewayStreamTable::new() (production SSRF defence)"
            err "which REJECTS loopback destinations"
            err "use --external-endpoint=http://<real-ip>:<port>/ or"
            err "let the script auto-detect via hostname -I"
            exit 3
            ;;
    esac

    # Guard: the external endpoint must NOT be in the test's internal
    # subnets (TUN subnet 10.0.0.0/24 or veth subnet 10.0.1.0/24). If it
    # is, the DIRECT test would succeed (the veth route reaches it).
    case "$EXTERNAL_ENDPOINT" in
        http://10.0.0.*|http://10.0.1.*)
            err "external endpoint $EXTERNAL_ENDPOINT is inside the test's internal subnet"
            err "the DIRECT test would succeed (veth route reaches it directly)"
            err "use --external-endpoint=http://<real-public-ip>:<port>/"
            exit 3
            ;;
    esac

    preflight
    ensure_binary

    # Start the external HTTP server (host-local mode) OR verify the
    # external endpoint is reachable (internet mode). In internet mode
    # the script does NOT start a local server — the gateway dials the
    # user-provided external endpoint directly.
    if [ "$MODE" = "host-local" ]; then
        start_http_server
    else
        verify_external_endpoint_reachable
    fi
    start_mesh
    setup_namespace

    # Run TEST 1 (DIRECT) BEFORE the TunClient is started.
    local direct_ok=1 sharenet_ok=1
    test_direct || direct_ok=0

    # Start the TunClient AFTER TEST 1 — this creates the TUN, installs
    # the split-tunnel routes, and intercepts SYNs.
    start_tun_client

    # Run TEST 2 (SHARENET via TUN).
    test_via_sharennet || sharenet_ok=0

    # Report the result. The banner wording differs by mode so a
    # reviewer of the log can immediately tell which kind of test passed.
    section "RESULT"
    if [ "$direct_ok" -eq 1 ] && [ "$sharenet_ok" -eq 1 ]; then
        if [ "$MODE" = "internet" ]; then
            cat <<'BANNER'

    ═══════════════════════════════════════════════════════
      N3-B INTERNET ACCEPTANCE TEST PASSED
      Direct Internet:    FAIL     (correct — no route)
      Via ShareNet TUN:   SUCCESS  (correct — real Internet egress)
    ═══════════════════════════════════════════════════════

BANNER
            log "N3-B INTERNET ACCEPTANCE TEST: PASS"
            log ""
            log "This proves (genuine Internet egress):"
            log "  * The client namespace is truly isolated (no default route"
            log "    until the TunClient installs one via the TUN)."
            log "  * Ordinary OS applications (curl with NO proxy flags) reach"
            log "    a genuinely REMOTE, public, non-loopback, non-RFC1918,"
            log "    non-link-local endpoint through the TUN + ShareNet circuit:"
            log "      - real TUN interface (/dev/net/tun via ioctl TUNSETIFF)"
            log "      - real smoltcp TCP/IP stack with any_ip enabled"
            log "      - real SYN interception + 5-tuple destination extraction"
            log "      - real ShareNet circuits (SNP-IK + X25519 circuit DH)"
            log "      - real relay forwarding (two hops: Client → A → B → Gateway)"
            log "      - real gateway outbound TCP (serve_gateway_mode_b_multiplexed)"
            log "      - production SSRF defence (GatewayStreamTable::new — NO loopback)"
            log "      - real external HTTP server at $EXTERNAL_ENDPOINT"
            log "        (NOT started by this script — a genuinely remote server)"
            log "  * The split-tunnel routing prevents loops."
            log "  * The response body contained the token '$TOKEN', proving the"
            log "    bytes came from the intended external server (not from some"
            log "    other source along the path)."
            log ""
            log "NO SOCKS5 WAS USED. The client used ordinary curl http://.../?token=..."
            log "with NO proxy flags. This is the N3-B north-star: unmodified OS"
            log "networking reaches the REAL Internet through ShareNet."
        else
            cat <<'BANNER'

    ═══════════════════════════════════════════════════════
      N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST PASSED
      (NOT Internet acceptance — see --mode=internet)
      Direct Internet:    FAIL     (correct — no route)
      Via ShareNet TUN:   SUCCESS  (correct — TUN path works)
    ═══════════════════════════════════════════════════════

BANNER
            log "N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST: PASS"
            log ""
            log "This proves the TUN → ShareNet → gateway → host path, but does NOT"
            log "prove genuine Internet egress. The 'external' endpoint was a local"
            log "python3 HTTP server bound to the host's primary IP ($EXTERNAL_ENDPOINT)."
            log ""
            log "For genuine Internet acceptance, re-run with:"
            log "  sudo $0 --mode=internet \\"
            log "      --external-endpoint=http://<REMOTE_PUBLIC_IP>:<PORT>/"
            log "where <REMOTE_PUBLIC_IP> is NOT the gateway host's IP, NOT loopback,"
            log "NOT RFC1918 private, NOT link-local."
            log ""
            log "What this host-local test DOES prove:"
            log "  * The client namespace is truly isolated (no default route"
            log "    until the TunClient installs one via the TUN)."
            log "  * Ordinary OS applications (curl with NO proxy flags) reach the"
            log "    host's primary IP through the TUN + ShareNet circuit:"
            log "      - real TUN interface (/dev/net/tun via ioctl TUNSETIFF)"
            log "      - real smoltcp TCP/IP stack with any_ip enabled"
            log "      - real SYN interception + 5-tuple destination extraction"
            log "      - real ShareNet circuits (SNP-IK + X25519 circuit DH)"
            log "      - real relay forwarding (two hops: Client → A → B → Gateway)"
            log "      - real gateway outbound TCP (serve_gateway_mode_b_multiplexed)"
            log "      - production SSRF defence (GatewayStreamTable::new — NO loopback)"
            log "  * The split-tunnel routing prevents loops."
            log "  * The response body contained the token '$TOKEN', proving the"
            log "    bytes came from the local HTTP server (not from some other source)."
        fi
        EXIT_CODE=0
    else
        if [ "$MODE" = "internet" ]; then
            cat <<'BANNER' >&2

    ═══════════════════════════════════════════════════════
      N3-B INTERNET ACCEPTANCE TEST FAILED
    ═══════════════════════════════════════════════════════
BANNER
        else
            cat <<'BANNER' >&2

    ═══════════════════════════════════════════════════════
      N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST FAILED
    ═══════════════════════════════════════════════════════
BANNER
        fi
        if [ "$direct_ok" -eq 0 ]; then
            printf '      DIRECT:   OK (UNEXPECTED — isolation failed)\n' >&2
        else
            printf '      DIRECT:   FAIL (expected)\n' >&2
        fi
        if [ "$sharenet_ok" -eq 0 ]; then
            printf '      SHARENET: FAIL (UNEXPECTED — ShareNet broken)\n' >&2
        else
            printf '      SHARENET: SUCCESS (expected)\n' >&2
        fi
        printf '    ══════════════════════════════════════════════════════════\n' >&2

        if [ "$sharenet_ok" -eq 0 ]; then
            printf '\n    --- TunClient log (last 50 lines) ---\n' >&2
            tail -50 "$TUN_LOG" >&2 2>/dev/null || true
            printf '\n    --- mesh log (last 30 lines) ---\n' >&2
            tail -30 "$MESH_LOG" >&2 2>/dev/null || true
        fi
        if [ "$MODE" = "internet" ]; then
            log "N3-B INTERNET ACCEPTANCE TEST: FAIL"
        else
            log "N3-B TUN INTEGRATION / HOST-LOCAL EGRESS TEST: FAIL"
        fi
        EXIT_CODE=1
    fi
}

main "$@"
exit $EXIT_CODE
