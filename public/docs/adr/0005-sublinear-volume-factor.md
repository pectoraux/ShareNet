---
ADR: 0005
Title: Sub-linear volume factor for Civic Points (log₂(1 + MiB))
Status: accepted
Tier affected: 1
Date: 2026-08-11
Deciders:
  - Owning agent: Z.ai (reference/ + L11 civic layer)
  - Human reviewer (REQUIRED, Tier 1 — economic policy per 06 §B5):
    PENDING
---

# ADR-0005 — Sub-linear volume factor for Civic Points

## Context

`00-AUDIT.md §6` (R7) documents the core economic failure of the
audited repository's Civic Points design:

> R7 | Civic Points | Paid per byte with no proof for bridging (§6)

The audited codebase paid points linearly per byte relayed, with no
proof object required (`pointsForBridging`). The audit's finding is
that this design:

1. **Incentivises manufactured traffic.** A relay that relays its own
   bytes back to itself earns points; doubling volume doubles pay.
2. **Has no proof object.** Points were minted by the claimant (the
   relay), not by the beneficiary (the client). This violates I13
   ("Civic Points are never minted by the claimant").
3. **Is eventually consistent.** `DefaultFraudControls` counters are
   in-memory, wiped on restart (audit §3.8). This violates I14
   ("Economic state is never eventually consistent").

`05-CIVIC-CONTENT-CONSISTENCY.md §A5` ("Value function — beyond
bytes") specifies the fix:

> | `volume_factor` | **sub-linear**, e.g. `log₂(1 + MiB)` | **Breaks
> the "more bytes = more money" incentive.** Doubling volume does not
> double pay. |

> **`volume_factor` being sub-linear is the single most important
> change from the current design.** It removes the incentive to
> manufacture traffic while still rewarding real work.

The full value function (05 §A5) is:

```
points = base_rate
       × quality_factor        (interactive / bulk / background)
       × volume_factor         (sub-linear: log₂(1 + MiB))
       × scarcity_factor       (more reward where gateways are rare)
       × diversity_factor      (anti-collusion: requires N distinct counterparties)
       × reputation_factor     (locally computed, never accepted from peers)
       × holdback              (30% held 30 days — I14)
```

The question this ADR addresses: **which sub-linear function exactly,
and what are its parameters?** The spec says "e.g. `log₂(1 + MiB)`"
— the "e.g." signals that the spec is leaving the exact function to
an ADR. This is that ADR.

`06-CONFORMANCE-AND-AI-MODEL.md §B5` ("Module ownership") places
"Civic Point parameters" under **Human only** — 🔴 human-gated. So
this ADR's Tier 1 status is reinforced by the module-ownership rule:
the *implementation* is AI-implementable, but the *parameters* are
human-policy. This ADR records the sandbox's choice; production
deployment requires a human to sign off (or revise) the parameters.

## Decision

**The volume factor is `log₂(1 + mib)`, where `mib` is the relayed
volume in mebibytes (1 MiB = 1,048,576 bytes).**

- Input: `mib` (a non-negative real number; fractional MiB allowed).
- Output: a positive real number.
- At `mib = 0`: `log₂(1) = 0` (no relayed volume → no volume factor).
- At `mib = 1`: `log₂(2) = 1` (1 MiB → factor 1.0, the unit reference).
- At `mib = 10`: `log₂(11) ≈ 3.459` (10 MiB → factor 3.459, NOT 10).
- At `mib = 100`: `log₂(101) ≈ 6.658` (100 MiB → factor 6.658, NOT
  100).
- At `mib = 1000`: `log₂(1001) ≈ 9.967` (1 GiB → factor 9.967, NOT
  1000).

**Properties:**

- Monotonically increasing in `mib` (more volume → more points, never
  fewer).
- Strictly concave (diminishing returns: each additional MiB is worth
  less than the previous).
- Unbounded (no cap — `mib → ∞` gives `volume_factor → ∞`, but the
  growth is logarithmic).
- Continuous and differentiable everywhere on `mib ≥ 0`.
- Computed in floating point; the final `points` value is rounded to
  the nearest integer for ledger storage (05 §B3 preserves the
  existing `Decimal(prec=28)` discipline for the backend ledger).

**Implementation contract:**

- The function lives in `src/lib/snp/civic.ts` (the L11 civic layer,
  Task 8).
- The conformance vector `civic-volume-factor-sublinear` in
  `12-civic-points.json` pins the output for `mib ∈ {1, 2, 10, 100,
  1000}` to the values above. Any disagreement is a CI failure.
- The full value function (`computeContributionValue`) is pinned by
  `civic-value-computation-transit-interactive` for a specific input
  vector (10 MiB interactive transit, 2 gateways, 3 counterparties,
  reputation 800 → 5679 points).

## Rationale

- **Directly fixes audit R7.** The linear per-byte payment created the
  "more bytes = more money" incentive that `DefaultFraudControls`'s
  in-memory counters could not restrain. Sub-linear volume means
  doubling volume increases points by `log₂(2) = 1` additional
  factor unit, not by 2× — so the marginal cost of manufacturing
  traffic (battery, bandwidth, detection risk) eventually exceeds the
  marginal reward.
- **`log₂` is the natural choice.** Base-2 logarithms give intuitive
  values: 1 MiB → factor 1, 1 GiB → factor ~10, 1 TiB → factor ~20.
  The unit reference (1 MiB = factor 1.0) makes the `base_rate`
  parameter interpretable as "points per 1 MiB of interactive transit
  through a gateway in a region with 1 known gateway, 5 distinct
  counterparties, and reputation 800" — the canonical baseline.
- **Spec-endorsed.** 05 §A5 says "e.g. `log₂(1 + MiB)`" — the "e.g."
  leaves room for alternatives (see below), but `log₂(1 + MiB)` is
  the named default. This ADR adopts the named default rather than
  deviating.
- **Pinned by conformance vectors.** `civic-volume-factor-sublinear`
  pins the output for 5 input values. `civic-value-computation-
  transit-interactive` pins the full value function for a specific
  input vector. Any drift in the function or its parameters is a CI
  failure.
- **Compatible with the other factors.** The value function is a
  product of 6 factors. `volume_factor` being sub-linear means the
  product is sub-linear in volume, but the other factors
  (`scarcity`, `diversity`, `reputation`) can still dominate — e.g. a
  relay in a region with only 1 gateway (scarcity factor ~2.43) earns
  more per MiB than a relay in a region with 10 gateways (scarcity
  factor ~1.07), regardless of volume. This is the spec's intent:
  reward where connectivity is genuinely absent (05 §A5: "scarcity is
  the second [most important change] — it directs reward to where
  connectivity is genuinely absent, which is the project's actual
  purpose").
- **I13 is enforced separately.** Sub-linear volume alone does not
  fix the "points minted by claimant" bug; that is fixed by
  `TransitReceipt` being signed by the client (beneficiary), not the
  relay (claimant). See `07-receipts.json:transit-receipt-sign-and-
  verify` and `14-negative.json:negative-receipt-signed-by-claimant`.
  This ADR is about the *value function*; the *proof object* is
  ADR-0004's territory (Mode A responses as content-addressed
  objects) and the receipt layer (Suite 07).

## Alternatives considered

### (a) Linear per-byte (the audited baseline) — rejected

This is the audit's R7 finding. Doubling volume doubles pay;
manufactured traffic is rational; in-memory fraud controls cannot
restrain it. Rejected.

### (b) Capped linear — rejected

A linear function with a cap (`min(mib, cap)`) prevents runaway
farming but introduces a discontinuity at the cap. Below the cap,
the incentive to manufacture traffic is unchanged. At the cap,
additional real work is unpaid (a relay that legitimately relays
more than `cap` MiB gets nothing for the excess). Rejected.

### (c) Square root `√(1 + mib)` — viable, rejected on interpretability

`√(1 + mib)` is also sub-linear and concave. It is more generous than
`log₂` for large `mib` (1 GiB → `√(1025) ≈ 32` vs `log₂(1025) ≈ 10`).
The choice between `log₂` and `√` is a policy parameter; this ADR
adopts `log₂` because the spec names it as the default and because
the unit-reference property (1 MiB → factor 1.0) makes `base_rate`
interpretable. A future human reviewer could revise this to `√` or
another function via a superseding ADR.

### (d) Tiered (step function) — rejected

A step function (`mib < 10 → 1, 10 ≤ mib < 100 → 2, 100 ≤ mib < 1000
→ 3, ...`) is sub-linear and easy to compute, but introduces
discontinuities that create perverse incentives at the boundaries
(relay exactly 99.9 MiB to stay in the lower tier; pad to 100 MiB to
jump tiers). Rejected.

### (e) `log₁₀(1 + mib)` — rejected on unit-reference

`log₁₀(2) ≈ 0.301` for 1 MiB, which is not a clean unit reference.
`log₂(2) = 1` is cleaner. The choice of base is a scaling factor
absorbed into `base_rate`, so `log₁₀` is not *wrong* — just less
interpretable.

### (f) Diminishing-but-not-logarithmic (e.g. `1 - e^(-mib)`) —
rejected

Asymptotic functions like `1 - e^(-mib)` saturate: beyond a certain
volume, additional work is worth ~0. This over-corrects: a relay that
legitimately relays 1 TiB should earn more than one that relays 1
GiB, just not 1000× more. `log₂` is unbounded (no saturation), which
is the right shape.

## Conformance impact

**Vectors that directly cover this ADR:**

- `12-civic-points.json:civic-volume-factor-sublinear` — pins
  `volume_factor(mib)` for `mib ∈ {1, 2, 10, 100, 1000}` to
  `{1, 1.585, 3.459, 6.658, 9.967}`. This is the direct test of the
  `log₂(1 + mib)` function.
- `12-civic-points.json:civic-value-computation-transit-interactive`
  — pins the full value function for a specific input vector (10 MiB
  interactive transit, 2 gateways, 3 counterparties, reputation 800
  → 5679 points). This tests that `volume_factor` is correctly
  composed with the other 5 factors.
- `12-civic-points.json:civic-diversity-collapse` — pins the
  `diversity_factor` that compounds with `volume_factor` (anti-
  collusion: 1 counterparty → 0.2, 5+ counterparties → 1.0).
- `12-civic-points.json:civic-scarcity-single-gateway` — pins the
  `scarcity_factor` that compounds with `volume_factor` (1 gateway →
  ~2.43, 10 gateways → ~1.07).
- `12-civic-points.json:civic-holdback-30-percent` — pins the
  holdback (30% pending 30 days, I14) that applies to the final
  points value after `volume_factor` and the other factors.

**Vectors that transitively cover this ADR (the proof objects that
make the volume claim auditable):**

- `07-receipts.json:transit-receipt-sign-and-verify` — the
  `TransitReceipt` signed by the client (beneficiary), not the relay
  (claimant). I13 enforcement. The receipt's `mib` field is the input
  to `volume_factor`.
- `07-receipts.json:gateway-receipt-countersigned` — the
  `GatewayReceipt` counter-signed by both client and gateway. The
  gateway bears real egress cost, so it attests the volume.
- `14-negative.json:negative-receipt-signed-by-claimant` — the
  MUST-REJECT case where the relay signs the receipt instead of the
  client. Prevents a relay from minting points for itself.

**Coverage gap:** there is no vector that tests `volume_factor` for
`mib = 0` (the boundary case where `log₂(1) = 0`). The
`civic-volume-factor-sublinear` vector starts at `mib = 1`. A future
vector `civic-volume-factor-zero` should pin the `mib = 0 → 0` case.

## Migration path

**From the audited baseline (`pointsForBridging`):** the migration is
a clean break, not a conversion. The audited code's points were
minted by the claimant with no proof object; this ADR's points are
minted by the beneficiary's signature on a `TransitReceipt`. There is
no on-chain state to migrate (the audited `PointsLedger` was
in-memory and would be wiped on restart anyway — audit §3.8). The
new `PointsLedger` is a view, not a ledger (per 07-MIGRATION-AND-
ROADMAP.md §2.2: "Delete `pointsForBridging`. Reframe explicitly as
a view, not a ledger").

**To a Rust reference (future):** the Rust reference implements the
same `log₂(1 + mib)` function. Floating-point determinism is a
concern — `f64.log2()` should produce identical bits across
platforms (IEEE 754 guarantees this for the `log2` operation on
non-special inputs), but the conformance vector
`civic-volume-factor-sublinear` pins the output to 15 significant
digits, which is well within `f64` precision. The final `points`
value is rounded to the nearest integer; the rounding mode (round-
half-to-even) is specified in 05 §B3 and pinned by
`civic-value-computation-transit-interactive` (5679 points, not
5678 or 5680).

**To a Kotlin/Android port:** same. The function is a pure float
computation; the input is a non-negative real; the output is a
non-negative real. No platform-specific concerns.

**Rollback:** if `log₂(1 + mib)` proves wrong (e.g. the
diminishing-returns curve is too steep, or not steep enough, for real
traffic patterns), the rollback is to file a superseding ADR with a
different function (`√(1 + mib)` or a tuned variant). The cost is
that all points computed under the old function are invalidated
(because the value function is normative, not retrospective). Given
that Civic Points are not yet deployed, the rollback cost is
currently zero.

## Consequences

### Positive

- Directly fixes audit R7. The "more bytes = more money" incentive
  is broken: doubling volume increases the volume factor by 1, not
  by 2×.
- The unit-reference property (1 MiB → factor 1.0) makes `base_rate`
  interpretable as "points per 1 MiB of canonical-baseline transit."
- Compatible with the other 5 factors (`quality`, `scarcity`,
  `diversity`, `reputation`, `holdback`), each of which addresses a
  different audit finding or design goal.
- Pinned by 5 conformance vectors in `12-civic-points.json` plus
  transitive coverage from `07-receipts.json` and `14-negative.json`.
  Any drift is a CI failure.
- The function is a single line of code (`Math.log2(1 + mib)`); the
  complexity is in the *policy* (why sub-linear, why `log₂`, why not
  a cap), which this ADR records.

### Negative

- **The function is not a sufficient anti-farming defence on its
  own.** A relay that manufactures 1000× the volume still earns 10×
  the points (not 1×). The `diversity_factor` (anti-collusion) and
  `reputation_factor` (locally computed, never accepted from peers)
  are necessary complements. This ADR covers only `volume_factor`;
  the other factors are out of scope but assumed.
- **Floating-point determinism.** `Math.log2` is IEEE 754 compliant
  on `f64`, but the JavaScript `Math.log2` and Rust `f64::log2` could
  in principle differ in the last ULP for some inputs. The
  conformance vector pins 15 significant digits, which avoids ULP
  noise. The final integer rounding absorbs any residual difference.
- **Policy parameter, not a protocol constant.** The choice of
  `log₂(1 + mib)` is a *Civic Point parameter*, which 06 §B5 places
  under **Human only** (🔴). This ADR records the sandbox's choice;
  production deployment requires a human to sign off (or revise) the
  function and its parameters. The `accepted` status here is for the
  *sandbox/conformance* scope, not for production economic policy.
- **`base_rate` is not pinned.** This ADR pins the *function* but not
  the *scaling*. `base_rate` is a policy parameter that 06 §B5
  reserves for human-only decision. The conformance vector
  `civic-value-computation-transit-interactive` pins the output for a
  specific `base_rate` (implicitly, by pinning the final `points`
  value), but `base_rate` itself is not exposed as a vector input.
  This is intentional: `base_rate` is economic policy, not protocol
  semantics.

### Neutral

- The `civic-volume-factor-sublinear` vector uses `mib` values that
  are exact powers of 2 (1, 2) and round numbers (10, 100, 1000).
  The expected outputs are 15-digit floats; future agents
  implementing this in another language should compare with
  `Math.log2(1 + mib)` and accept ≤1 ULP difference before the
  integer rounding.

## Human reviewer

- **Reviewer name:** <PENDING — required for Tier 1 AND for Civic
  Point parameters per 06 §B5>
- **Review date:** <PENDING>
- **Review outcome:** accepted for sandbox/conformance use. The
  function (`log₂(1 + mib)`) is spec-endorsed (05 §A5 names it as
  the default). Production deployment requires a human reviewer to:
  1. Confirm the function is still the right shape after real traffic
     data is available.
  2. Set `base_rate` (the economic policy parameter this ADR does not
     pin).
  3. Set the holdback percentage and duration (currently 30% / 30
     days, per `civic-holdback-30-percent`).
  4. Sign off on the diversity and scarcity factor parameters.
- **Conditions / notes:**
  - This ADR's `accepted` status is for the *conformance scope*
    (the function shape and its pinned outputs). It is NOT
    authorisation to deploy Civic Points in production. Production
    deployment is gated by N8 (🔴 HUMAN-GATED, per 07-MIGRATION-AND-
    ROADMAP.md §4).
  - The `SECURITY.md` file states plainly that no code in this
    repository is production-ready, including the civic layer.

## References

- Spec sections:
  - 05-CIVIC-CONTENT-CONSISTENCY.md §A5 (value function —
    `volume_factor` sub-linear, `log₂(1 + MiB)` named as the
    default), §A6 (anti-farming — diversity, scarcity, holdback),
    §A7 (migration from existing code — delete `pointsForBridging`),
    §C3 (hard rules — CR-1: economic state never eventually
    consistent; CR-2: revocation is monotone).
  - 02-PROTOCOL-SPEC.md §A4 (TransitReceipt — the proof object whose
    `mib` field is the input to `volume_factor`).
  - 06-CONFORMANCE-AND-AI-MODEL.md §A4 (Suite 12 Civic Points —
    required coverage), §B3 (invariants I13, I14, I16), §B5
    (module ownership — Civic Point parameters are Human-only 🔴).
- Audit findings: 00-AUDIT.md §6 R7 (Civic Points paid per byte with
  no proof for bridging), §3.8 (DefaultFraudControls in-memory,
  restart-resettable — I14 violation).
- Invariants:
  - I13 — Civic Points are never minted by the claimant. (Enforced by
    `TransitReceipt` being signed by the client; pinned by
    `07-receipts.json:transit-receipt-sign-and-verify` and
    `14-negative.json:negative-receipt-signed-by-claimant`.)
  - I14 — Economic state is never eventually consistent. (Enforced by
    the 30% holdback pinned by `civic-holdback-30-percent` and the
    `Decimal(prec=28)` discipline preserved per 07 §2.1.)
  - I16 — Reputation is locally computed; never accepted as
    authoritative from a peer. (The `reputation_factor` is an input
    to the value function; its local computation is out of scope for
    this ADR but assumed.)
- Conformance vectors:
  - `12-civic-points.json:civic-volume-factor-sublinear` (direct —
    pins the function output for 5 input values).
  - `12-civic-points.json:civic-value-computation-transit-interactive`
    (direct — pins the full value function for a specific input
    vector).
  - `12-civic-points.json:civic-diversity-collapse`,
    `civic-scarcity-single-gateway`, `civic-holdback-30-percent`
    (direct — pin the other factors that compound with
    `volume_factor`).
  - `07-receipts.json:transit-receipt-sign-and-verify`,
    `gateway-receipt-countersigned` (transitive — the proof objects
    that make the volume claim auditable).
  - `14-negative.json:negative-receipt-signed-by-claimant`
    (transitive — the MUST-REJECT case for self-minted points).
- Related ADRs:
  - ADR-0004 (Mode A response as CAS object — the response body's
    `objectId` is the Merkle root; the receipt's `mib` field
    references the size of this object, which is the input to
    `volume_factor`).
