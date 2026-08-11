---
ADR: 0008
Title: Gateway egress DNS-rebinding defence (resolve → validate → pin → connect)
Status: proposed
Tier affected: 1
Date: 2026-08-13
Deciders:
  - Owning agent: Z.ai (reference/ + L7 gateway layer)
  - Human reviewer (REQUIRED — security-critical gateway behaviour):
    PENDING
---

# ADR-0008 — Gateway egress DNS-rebinding defence

> **Scope of `proposed`.** This ADR specifies a security-critical
> gateway behaviour (the egress flow that prevents DNS rebinding /
> SSRF pivot through a ShareNet gateway). It is `proposed`, NOT
> `accepted`, because:
>
> 1. It is a Tier 1 security-critical ADR (gateway egress policy) and
>    per `06-CONFORMANCE-AND-AI-MODEL.md §B6` requires a named human
>    reviewer.
> 2. The real gateway (N5 milestone) does not yet exist. The current
>    `enforceEgressPolicy` in `src/lib/snp/gateway.ts` implements the
>    **hostname-check half** of this flow (the `isPrivateDestination`
>    function, with the explicit JSDoc caveat that it does NOT resolve
>    DNS and the gateway MUST re-check the resolved IP). This ADR
>    specifies the **IP-pin half** — the runtime behaviour the real
>    gateway MUST implement when it lands.
> 3. Until the human reviewer signs this ADR and the real gateway
>    implements the flow, **the sandbox gateway is NOT safe to deploy
>    as an open proxy.** The hostname check alone is bypassable by DNS
>    rebinding (see Context).

## Context

The hardening audit (Blocker F) found that
`src/lib/snp/gateway.ts:isPrivateDestination(host)` checks the
**literal hostname string** against RFC 1918 / loopback / link-local /
multicast / reserved ranges, but **does NOT resolve DNS**. The
function's own JSDoc acknowledges this:

> NOTE: this function checks the LITERAL host string. It does NOT
> resolve DNS. A hostname like "attacker.com" that resolves to
> 127.0.0.1 (DNS rebinding) is NOT caught here. Gateways MUST re-check
> `isPrivateDestination` against the resolved IP address immediately
> before connecting (TOCTOU defence). Documenting this gap here so
> callers know the second check is required.

The consequence: a URL like `http://evil.com` where `evil.com` resolves
to `192.168.1.1` (an RFC 1918 address) **passes the hostname check**
(`isPrivateDestination("evil.com") === false` because `evil.com` is
not a literal IP, not `localhost`, and not `.local`). The gateway would
then connect to `192.168.1.1` — pivoting into its operator's LAN. This
is the classic **DNS rebinding SSRF** attack, and it bypasses the I18
SSRF defence (per `04-THREAT-MODEL.md` T9) entirely.

The audit offered two paths:

- **(A) Run a local DNS resolver that filters private IPs.** Complex,
  and upstream DNS can still rebind between the local resolver's
  response and the connection's actual TCP connect.
- **(B) Specify the gateway egress flow as
  `URL → canonicalize → resolve DNS → validate EVERY resolved address
  against isPrivateDestination → PIN the validated address → connect
  specifically to that address (not re-resolve) → validate redirects
  (re-run the full flow for each redirect) → revalidate as necessary`.**

**This ADR chooses (B).** The key invariant: **the gateway must
connect to the IP it validated, not to a fresh DNS resolution.** This
closes the TOCTOU window between DNS resolution and TCP connection
that DNS rebinding exploits.

### What happens if we do nothing

- The sandbox gateway's `enforceEgressPolicy` continues to check only
  the literal hostname. A `TransitRequest` with `url: "http://evil.com"`
  (where `evil.com → 192.168.1.1`) passes the policy check and would
  be permitted.
- When the real gateway lands (N5), if it implements only the
  hostname check (matching the current `enforceEgressPolicy`), it is
  an SSRF pivot into its operator's LAN. This is exactly the failure
  mode `04-THREAT-MODEL.md` T9 warns about.
- The `14-gateway-private-network-rejection` integration test passes
  (it tests only the hostname-check half with literal IPs) but gives
  false confidence that the SSRF defence is complete.

## Decision

1. **The gateway egress flow is specified as the following 7-step
   pipeline.** Every outbound connection the gateway makes on behalf
   of a client MUST pass through this pipeline. The pipeline is
   applied per HTTP request, including redirected requests.

   ```
   Step 1. URL → canonicalize
            - Parse the URL. Reject non-http(s) schemes.
            - Lowercase the host. Strip any trailing dot.
            - Reject userinfo (no "user:pass@host" — credential
              leakage risk).
            - Reject empty host.
            - Reject hostnames longer than 253 bytes (DNS limit).
            - Reject label longer than 63 bytes (DNS limit).

   Step 2. Resolve DNS
            - Resolve the canonicalized host to a list of IP
              addresses (A and AAAA records).
            - If the resolver returns zero addresses, reject
              (NXDOMAIN).
            - If the resolver returns an address, proceed to Step 3
              with the FULL list (do not pick one yet).

   Step 3. Validate EVERY resolved address
            - For each resolved IP address, call
              `isPrivateDestination(ipLiteral)`.
            - If ANY resolved address is private/loopback/link-local/
              multicast/reserved, REJECT the request. (The gateway
              does not "skip the bad address and try the next one" —
              the existence of a private address in the resolution
              set is itself suspicious and is treated as a hard
              rejection.)

   Step 4. PIN the validated address
            - From the surviving (validated-as-public) addresses,
              pick one (round-robin, lowest-latency, whatever the
              gateway's policy prefers).
            - Record the chosen IP address as the "pinned" address
              for this request. This is the IP the gateway will
              connect to. The hostname-to-IP mapping is FROZEN for
              the lifetime of this request.

   Step 5. Connect specifically to the pinned address
            - Open a TCP (or TLS) connection to the PINNED IP
              address, NOT to a fresh DNS resolution of the hostname.
            - For TLS, send the SNI/Host header using the original
              hostname (so the server's certificate validates
              correctly), but the underlying TCP connection is to
              the pinned IP.
            - This is the DNS-rebinding defence: even if the
              attacker changes the DNS record between Step 2 and
              Step 5, the gateway connects to the IP it validated,
              not to a fresh resolution.

   Step 6. Validate redirects
            - If the upstream server returns a 3xx redirect, the
              gateway re-runs the ENTIRE pipeline (Steps 1–5) for
              the redirect target. The redirect target's URL is
              treated as a fresh request — it gets its own DNS
              resolution, its own validation, its own pin.
            - The redirect count is capped (default: 5) to prevent
              redirect loops. A redirect chain that exceeds the cap
              is rejected.
            - A redirect to a private/loopback/link-local address
              is rejected (same as Step 3).

   Step 7. Revalidate as necessary
            - If the gateway keeps a connection pool / persistent
              connection to the pinned IP, the pin has a TTL (default:
              60 seconds). After the TTL, the gateway re-runs Steps
              2–5 before reusing the connection. This catches the
              case where a long-lived connection's underlying IP has
              been repointed (e.g. by the upstream DNS, or by an
              attacker who gained control of the upstream DNS).
            - If the pin's TTL has expired and the new resolution
              set differs from the original, the gateway opens a NEW
              connection to the newly-pinned IP (it does not migrate
              the existing connection — that would risk connecting
              to an unvalidated IP).
   ```

2. **The key invariant (restated): the gateway connects to the IP it
   validated, not to a fresh DNS resolution.** This is the single
   property that distinguishes the DNS-rebinding-safe flow from the
   naive "resolve and connect" flow. Everything else in the pipeline
   (canonicalization, redirect re-validation, TTL revalidation) is in
   service of this invariant.

3. **The current `enforceEgressPolicy` in
   `src/lib/snp/gateway.ts` is the hostname-check half of this flow
   (Step 1's host-validation portion + the literal-IP check that
   would happen in Step 3 if the URL contained an IP literal).** It
   is NOT modified by this ADR — its existing behaviour (reject
   literal private IPs, reject `localhost`, reject `.local`) is
   correct and is a necessary precondition for the full flow. The
   IP-pin half (Steps 2, 4, 5, 6, 7) is specified here and is
   implemented by the real gateway (N5).

4. **The `isPrivateDestination` JSDoc caveat is updated** to reference
   this ADR by number. The existing caveat ("the gateway MUST
   re-check the resolved IP") was the audit's note that this ADR
   exists to address; the caveat now points at this ADR as the
   specification of the "re-check" flow.

5. **No spec modification.** The spec (`02-PROTOCOL-SPEC.md §8`) is
   not modified by this ADR. The spec already mandates the SSRF
   defence (referencing `04-THREAT-MODEL.md` T9); this ADR specifies
   the runtime behaviour that implements the defence. The spec's
   `§8` is the production target; this ADR is the implementation
   contract.

## Rationale

- **Without this flow, the I18 SSRF defence is bypassable.**
  `04-THREAT-MODEL.md` T9 and the spec's `§8` mandate that a gateway
  MUST NOT be an SSRF pivot into its operator's LAN. The hostname-only
  check fails this mandate whenever an attacker controls a DNS record
  (which is cheap — register a domain, set the A record, done). The
  IP-pin flow closes this hole.

- **The IP-pin is the load-bearing step.** DNS rebinding works by
  changing the DNS record between the victim's validation check and
  the victim's connection. The IP-pin defeats this by removing the
  second DNS lookup entirely — the gateway connects to the IP it
  validated, period. There is no TOCTOU window because there is no
  second resolution.

- **The redirect re-validation is necessary because redirects are a
  rebinding vector.** Without Step 6, an attacker could host a
  redirect at `evil.com` (resolving to a public IP) that 302s to
  `evil2.com` (resolving to `192.168.1.1`). The gateway would follow
  the redirect and connect to the private IP without re-validation.
  Step 6 makes each redirect a fresh pipeline run.

- **The "reject if ANY resolved address is private" rule (Step 3) is
  stricter than "skip the private address and try the next."** This
  is deliberate: a DNS response that includes both a public and a
  private address is itself suspicious (legitimate DNS responses do
  not normally mix public and private addresses for the same
  hostname). The strict rule prevents an attacker from seeding the
  response with a public address to pass the check, then relying on
  the gateway's connection-attribution logic to pick the private
  address.

- **The TTL revalidation (Step 7) catches long-lived-connection
  rebinding.** Without it, an attacker who controls the DNS could
  rebind the hostname after the gateway opens a persistent
  connection. The TTL forces a re-validation before the connection
  is reused. The TTL is short (60s default) because the threat is
  real and the cost of a re-resolution is low.

- **No invariants are relaxed.** I18 (gateway egress policy rejects
  private/loopback/link-local destinations — SSRF) is *strengthened*
  by this ADR: the policy now applies to the resolved IP, not just
  the literal hostname. I20 (verifiers return false on bad input,
  never permissive) is unchanged — the gateway's egress policy
  remains fail-closed.

## Alternatives considered

### (a) Run a local DNS resolver that filters private IPs — rejected

A local resolver (e.g. unbound with a `private-address` config) would
filter private IPs at resolution time, so the gateway never sees them.
This is defense-in-depth and is recommended as a **complement** to the
IP-pin flow, not a replacement:

- **Does not close the TOCTOU window.** The local resolver responds;
  the gateway connects. Between those two events, an upstream DNS
  server can rebind. The IP-pin closes this window; the local
  resolver alone does not.
- **Complexity.** Running a local resolver is an operational burden
  (config, deps, updates). The IP-pin flow is a code change in the
  gateway's connect path — no new infrastructure.
- **Does not help with redirects.** Each redirect is a fresh DNS
  lookup; the local resolver filters each one, but the gateway still
  needs to pin the validated IP for the redirect's connection.

The local resolver is recommended as defense-in-depth in production
deployments but is not the primary defence.

### (b) SOCKS5-style hostname passthrough — rejected

In SOCKS5, the client sends the hostname to the proxy and the proxy
resolves it. This is what ShareNet's gateway already does (the client
sends a URL, the gateway resolves it). The question is what the
gateway does AFTER resolving. SOCKS5-style passthrough does not
specify the IP-pin — it is silent on the rebinding defence. This ADR
specifies the IP-pin; SOCKS5 passthrough is the input format, not the
defence.

### (c) Pin the DNS resolution result with a short TTL (e.g. 5s) and
### re-resolve on every connection — rejected

This is "Step 7 with TTL=5s and no Step 5 pinning." It does not close
the TOCTOU window — it just makes the window smaller. The IP-pin
(Step 5) closes the window entirely for the lifetime of the request.
The TTL revalidation (Step 7) is for connection REUSE, not for the
initial connection.

### (d) Validate only the first resolved IP — rejected

If the resolver returns `[8.8.8.8, 192.168.1.1]` (public, private),
validating only the first IP would pass the check. The gateway would
then connect to `8.8.8.8` (or, worse, if its connection-attribution
logic preferred the second address, to `192.168.1.1`). Step 3's
"reject if ANY address is private" prevents this. A mixed public/
private response is suspicious on its face and is rejected.

## Conformance impact

### No new conformance vectors are added by this ADR

This ADR specifies a **runtime behaviour** (the gateway's egress
flow), not a wire format or a pure-function output. The conformance
vectors are golden-vector JSON files that test pure functions
(`encodeFrame`, `reputationFactor`, `isPrivateDestination`,
`verifyRouteAdvert`, etc.); they cannot test "did the gateway connect
to the IP it validated?" because that requires a real network
connection and a controlled DNS server.

The conformance suite's coverage of the gateway's SSRF defence
remains:

- `14-negative.json:negative-gateway-connect-private-destination` —
  tests that `isPrivateDestination("192.168.1.1")` returns `true`
  (the literal-IP check, which is the hostname-check half of the
  flow). Unchanged by this ADR.
- `11-gateway.json` — tests the gateway advert format, egress
  policy port checks, and `enforceEgressPolicy` on literal
  hostnames. Unchanged by this ADR.

### Integration test extension (recommended, future task)

The integration test `14-gateway-private-network-rejection` (in
`src/lib/snp/integration-tests.ts`) should be EXTENDED in a future
task to test DNS-rebinding scenarios. The extension would:

- Stub the DNS resolver with a controllable mock.
- Test scenario 1: a hostname that resolves to a public IP — the
  gateway connects (success).
- Test scenario 2: a hostname that resolves to a private IP — the
  gateway rejects (Step 3 rejection).
- Test scenario 3: a hostname that rebinds between resolution and
  connection (the mock returns a public IP at resolution, a private
  IP at connect time) — the gateway connects to the public IP it
  validated (Step 5 pinning).
- Test scenario 4: a redirect chain where the redirect target
  resolves to a private IP — the gateway rejects (Step 6
  re-validation).

This extension requires the real gateway (N5) to exist; the current
`enforceEgressPolicy` is the hostname-check half and does not perform
DNS resolution. The extension is therefore a future task, blocked on
N5.

### No vector regeneration

No existing vector changes. The literal-IP check in
`isPrivateDestination` is unchanged; the regenerated hostname-check
vectors in `11-gateway.json` and `14-negative.json` remain valid.

## Migration path

### For the sandbox reference (this codebase)

The current `enforceEgressPolicy` in `src/lib/snp/gateway.ts` is NOT
modified by this ADR. It implements the hostname-check half and is
correct as far as it goes. The IP-pin half (Steps 2, 4, 5, 6, 7) is
specified here and is implemented by the real gateway (N5).

The `isPrivateDestination` JSDoc caveat is updated to reference this
ADR by number. The existing caveat ("the gateway MUST re-check the
resolved IP") now points at this ADR as the specification of the
"re-check" flow.

### For the real gateway (N5 milestone)

When the real gateway is implemented (N5), it MUST implement the
7-step pipeline specified in this ADR's Decision section. The
implementation is in the gateway's connect path — the function that
opens the TCP/TLS connection to the upstream server. The
implementation:

1. Calls `enforceEgressPolicy` (existing) for the hostname check.
2. Resolves DNS (new — requires a DNS resolver dependency).
3. Calls `isPrivateDestination` (existing) for each resolved IP.
4. Pins the validated IP (new — record-keeping in the request
   context).
5. Connects to the pinned IP (new — bypass the platform's default
   `connect(hostname, port)` and use `connect(ip, port)` with SNI
   set to the hostname).
6. Re-runs the pipeline for redirects (new — wrap the HTTP client's
   redirect-following logic).
7. Revalidates on connection reuse (new — TTL on the pinned IP in
   the connection pool).

The implementation MUST be accompanied by:

- An integration test extending `14-gateway-private-network-rejection`
  to cover the DNS-rebinding scenarios listed in the Conformance
  impact section.
- A unit test of the IP-pin logic (mock DNS, mock connect, verify the
  gateway connects to the validated IP).
- A human reviewer's sign-off on this ADR (mandatory before merge to
  production).

### For existing deployments

There are no existing ShareNet 2.0 deployments. The first deployment
(N5+) MUST implement this flow; there is no "old behaviour" to
migrate from.

### Rollback

This ADR can be rolled back by reverting the `isPrivateDestination`
JSDoc reference to this ADR. The actual gateway behaviour is
implemented in N5; rolling back this ADR before N5 has no
implementation consequence (it is a specification, not a code change).
Rolling back AFTER N5 would re-open the DNS-rebinding vulnerability
and is not recommended.

## Consequences

### Positive

- The DNS-rebinding SSRF attack is closed. The gateway connects to
  the IP it validated; the TOCTOU window between resolution and
  connection is eliminated.
- The I18 SSRF defence is complete: the policy applies to the
  resolved IP, not just the literal hostname.
- The audit trail is complete: the gap in `isPrivateDestination`'s
  JSDoc is now filled by a specification (this ADR), not just a
  "MUST re-check" note.
- Blocker F of the hardening audit is closed (at the specification
  level; implementation is N5's responsibility).

### Negative

- **The real gateway (N5) is more complex.** The 7-step pipeline is
  more code than "resolve and connect." The complexity is necessary
  for security; it is not optional.
- **The IP-pin breaks some HTTP client assumptions.** Platform HTTP
  clients (Node's `http`, Rust's `reqwest`, etc.) typically resolve
  the hostname internally and do not expose a "connect to this
  specific IP" API. The gateway's HTTP client must be configured to
  use the pinned IP — typically via a custom `lookup` function
  (Node) or a custom `DNSResolver` (Rust). This is a known
  integration cost.
- **The redirect re-validation may break some legitimate flows.** A
  redirect chain that crosses between public and CDN-internal
  addresses (some CDNs use private IPs internally) would be rejected
  by Step 6. Mitigation: the gateway's policy may whitelist specific
  CDN ranges — but this is a policy decision, not a default.
- **Human review is pending.** This ADR is `proposed` until a named
  human reviewer signs it. The reviewer should specifically evaluate
  the strict "reject if ANY resolved address is private" rule (Step 3)
  — it is correct for security but may be operationally inconvenient
  for hosts that legitimately return mixed-address DNS responses.

### Neutral

- The `isPrivateDestination` function itself is unchanged. Its
  contract ("checks the literal host string") is preserved; this ADR
  specifies the caller's responsibility (run it on the resolved IP,
  not just the hostname).
- The `14-gateway-private-network-rejection` integration test is
  unchanged in this ADR. The future-task extension (DNS-rebinding
  scenarios) is recommended but not required to close Blocker F at
  the specification level.

## Human reviewer

> Required — this is a security-critical gateway behaviour. Per
> `06-CONFORMANCE-AND-AI-MODEL.md §B6`, this ADR is `proposed` until
> a named human reviewer signs it. **Mandatory before N5 gateway
> implementation.**

- **Reviewer name:** <PENDING — required before the N5 gateway
  implementation milestone>
- **Review date:** <PENDING>
- **Review outcome:** <PENDING — approved | approved-with-conditions |
  rejected>
- **Conditions / notes:**
  - The reviewer should specifically evaluate the **"reject if ANY
    resolved address is private" rule (Step 3)**. Is this too strict
    for legitimate mixed-address DNS responses? If so, the reviewer
    should require a documented whitelist mechanism as a condition
    of approval.
  - The reviewer should evaluate the **TTL revalidation (Step 7)**.
    Is 60 seconds the right default? Too short → excessive
    re-resolution; too long → rebind window stays open for reused
    connections.
  - The reviewer should evaluate the **redirect cap (Step 6,
    default 5)**. Is this the right cap? Too low → legitimate
    redirect chains break; too high → redirect-loop DoS.
  - The reviewer should confirm that the **SNI/Host header (Step 5)**
    uses the original hostname, not the pinned IP. (For TLS, the
    certificate validates against the hostname; sending the IP as
    SNI would break certificate validation for most servers.)
  - The reviewer should spot-check the **DNS resolver dependency**
    that N5 will use. Is it a vetted library? Does it support
    DNSSEC? Does it return the full address list (not just the
    first)?

## References

- Spec sections:
  - `02-PROTOCOL-SPEC.md §8` (gateway egress policy — the production
    target this ADR specifies the runtime behaviour for).
  - `04-THREAT-MODEL.md §4` T9 (gateway abuse — the operator's risk;
    "mandatory RFC 1918 / loopback / link-local / multicast blocking
    — without it a gateway is an SSRF pivot into its owner's LAN").
  - `06-CONFORMANCE-AND-AI-MODEL.md §B3` (invariant I18 — gateway
    egress policy rejects private/loopback/link-local destinations;
    SSRF defence. This ADR strengthens I18 by extending the policy
    from the literal hostname to the resolved IP).
  - `06-CONFORMANCE-AND-AI-MODEL.md §B6` (ADR process — Tier 1
    requires named human approval; this ADR's `proposed` status is
    mandatory until that approval).
- Audit findings:
  - `00-AUDIT.md §7` item 14 (gateway admission and abuse policy —
    "a gateway would be running an open proxy attributable to its
    owner's IP, with no controls").
  - Hardening audit Blocker F (the finding this ADR closes):
    `isPrivateDestination` checks the hostname but does NOT resolve
    DNS; a URL like `http://evil.com` (resolving to 192.168.1.1)
    would pass the hostname check but still be an SSRF pivot.
- Invariants:
  - I18 — gateway egress policy rejects private/loopback/link-local
    destinations (SSRF defence). This ADR STRENGTHENS I18 by
    extending the policy from the literal hostname to the resolved
    IP. The hostname check (existing `isPrivateDestination`) is
    unchanged; the IP-pin (specified here) is the new behaviour.
  - I20 — `verify*` returns false on bad input, never permissive.
    The gateway's egress policy remains fail-closed: a private
    resolved IP, a rebind attempt, or a redirect to a private
    address all result in rejection, never in permissive fallback.
- Conformance vectors:
  - `14-negative.json:negative-gateway-connect-private-destination`
    (unchanged — tests the literal-IP hostname check, which is the
    hostname-check half of the flow).
  - `11-gateway.json` (unchanged — tests `enforceEgressPolicy` on
    literal hostnames; the IP-pin half is runtime behaviour not
    covered by golden vectors).
- Integration tests:
  - `14-gateway-private-network-rejection` (in
    `src/lib/snp/integration-tests.ts`) — recommended future-task
    extension to cover DNS-rebinding scenarios (blocked on N5).
- Related ADRs:
  - **ADR-0007** (civic reputation fix — unrelated to this ADR;
    both are Tier 1 hardening-audit closure ADRs filed in the same
    task batch).
  - **Future ADR (likely ADR-0009+)** — vetted Noise_IK library
    integration. ADR-0006 anticipated "ADR-0007" as that ADR's
    number; ADR-0007 was reassigned to the civic reputation fix in
    this batch. The Noise_IK migration ADR will be filed at the
    next free number after this ADR (ADR-0009 or later).
