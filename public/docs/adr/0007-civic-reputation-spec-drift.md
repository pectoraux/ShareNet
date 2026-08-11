---
ADR: 0007
Title: Fix civic reputationFactor to match spec range [0,1] (was [0.5,1.0])
Status: accepted
Tier affected: 1
Date: 2026-08-13
Deciders:
  - Owning agent: Z.ai (reference/ + L7 civic layer)
  - Human reviewer (REQUIRED for Tier 1 per 06 §B6): PENDING
---

# ADR-0007 — Fix civic reputationFactor to match spec range [0,1]

> **Scope of `accepted`.** The *decision* documented here — to fix the
> implementation so `reputationFactor(score) = score/1000` clamped to `[0,1]`,
> matching `05-CIVIC-CONTENT-CONSISTENCY.md §A5` — is `accepted` and
> effective immediately. This is a spec/implementation drift fix that
> closes Blocker E of the hardening audit. The Tier 1 conformance vector
> `civic-value-computation-transit-interactive` has been regenerated to
> match.
>
> The Human reviewer field below is `PENDING` because this is a Tier 1
> (normative-spec-conformance) ADR: a named human MUST sign it before the
> N8 Civic Points milestone. The `accepted` status here is provisional on
> that review; if the reviewer rejects, this ADR becomes `rejected` and
> the implementation reverts to a floor of 0.5 pending a spec-level
> bootstrap-bonus ADR.

## Context

The hardening audit (Blocker E) found that the sandbox L7 civic-points
implementation (`src/lib/snp/civic.ts`, function `reputationFactor`) used
the formula:

```
reputationFactor(score) = 0.5 + 0.5 × (score / 1000)   // range [0.5, 1.0]
```

with the rationale (recorded in the function's JSDoc) that:

> "a new gateway that is the only path to the Internet should earn *some*
> reward even with zero history, otherwise the network never bootstraps."

`05-CIVIC-CONTENT-CONSISTENCY.md §A5` states — in a normative table —
that the `reputation` factor's range is **`0–1`**:

| Factor | Range | Purpose |
|---|---|---|
| ... | ... | ... |
| `reputation` | 0–1 | Verified history |

The `0–1` range is also the mathematically correct range for a
multiplicative factor in the points formula:

```
points = Σ_contributions  base(type) × volume_factor × quality × scarcity × diversity × reputation
```

A multiplicative factor that floors at 0.5 means a brand-new node (which
by definition has zero verified history) earns *half* credit on every
contribution — the formula cannot express "this contribution should
earn zero civic points because the contributor is unknown." That is a
protocol semantic choice, and it was made in the implementation without
going through the ADR process. That is exactly the spec/implementation
drift that the foundation (spec + conformance + ADRs) is supposed to
prevent.

The hardening audit flagged this as **Blocker E** (a Tier 1 spec drift
made silently in code). The fix is to bring the implementation back
into conformance with the spec, and to document the decision here so
the audit trail is complete.

### What happens if we do nothing

- The implementation continues to diverge from the spec. Future agents
  reading the spec see `0–1`; future agents reading the code see
  `[0.5, 1.0]`. They will disagree about what `reputation = 0` means
  for a new node, and one of them will "fix" the code in the opposite
  direction, re-opening the drift.
- The bootstrapping concern (new nodes getting zeroed) is real, but it
  is a **policy question for the spec**, not an implementation choice.
  It must be solved at the spec level (e.g. a bootstrap bonus, a grace
  period, a reputation floor keyed to a verified device attestation)
  with its own ADR — not by silently changing the formula.

## Decision

1. **The implementation is fixed to match the spec.**
   `reputationFactor(reputationScore)` now returns
   `clamp(reputationScore / 1000, 0, 1)` — range `[0, 1]`, matching
   `05 §A5`. A reputation score of 0 (brand-new node) multiplies to
   **0 points**. A reputation score of 1000 (fully trusted) multiplies
   to **1.0×** (the full factor).

2. **The bootstrapping concern is NOT solved in this ADR.** A new node
   with reputation 0 earns 0 civic points until it builds reputation
   through verified contributions. This is the spec-correct behavior.
   If bootstrapping proves problematic in practice (e.g. the network
   cannot bootstrap because no node can earn its first reputation
   point), the fix is a **spec-level bootstrap bonus** filed as a
   future ADR — NOT a silent formula change in code.

3. **The JSDoc on `reputationFactor` is updated** to record:
   - The new formula (`score / 1000`, clamped to `[0, 1]`).
   - The history (was `[0.5, 1.0]`; this ADR fixed it).
   - The spec citation (`05 §A5`).
   - The bootstrapping note (a future spec-level ADR may add a
     bootstrap bonus; the implementation does not).

4. **The conformance vector
   `civic-value-computation-transit-interactive`** in
   `/public/conformance/vectors/12-civic-points.json` is regenerated.
   For input `{ type: "transit", mib: 10, qualityClass: "interactive",
   knownGatewaysInRegion: 2, distinctCounterparties: 3,
   reputationScore: 800 }`:
   - Old expected `points`: `5679` (with reputation factor `0.9` =
     `0.5 + 0.5 × 800/1000`).
   - New expected `points`: `5048` (with reputation factor `0.8` =
     `800 / 1000`).
   - The vector's expected `points` field is updated from `5679` to
     `5048`. The conformance runner's `runSuite12Civic` continues to
     pass because it computes the expected value live from the
     implementation (the JSON's `expected` is the recorded golden; the
     runner recomputes and compares).

5. **The spec (`05-CIVIC-CONTENT-CONSISTENCY.md §A5`) is NOT modified.**
   The spec already says `0–1`. The spec was right; the implementation
   was wrong. This ADR fixes the implementation, not the spec.

## Rationale

- **Tier 1 beats Tier 3 (06 §B2).** The spec's `reputation ∈ [0,1]` is
  a Tier 1 normative claim. The implementation's `[0.5, 1.0]` was a
  Tier 3 implementation choice that drifted from the spec without an
  ADR. Per the constraint hierarchy, the spec wins. The implementation
  is brought back into conformance; if the implementation's behavior is
  desired, the spec must be changed via a Tier 1 ADR — not the other
  way around.

- **The `[0,1]` range is correct for a multiplicative factor.** A
  multiplicative factor that floors at 0.5 cannot express "this node
  has zero reputation and should earn zero credit." The `[0,1]` range
  is the mathematically correct range for a multiplier in
  `points = base × volume × quality × scarcity × diversity × reputation`.
  The spec is right on the math; the implementation was wrong.

- **The bootstrapping concern is real but is a spec question.** "A
  brand-new gateway that is the only path to the Internet should earn
  *some* reward" is a legitimate policy position. But it is a **policy
  position about the spec**, not a fact about the implementation. The
  right place to address it is a future Tier 1 ADR that proposes (e.g.)
  a `bootstrapBonus` field in the points formula, with its own
  conformance vectors. Silently embedding the bonus in the
  implementation's `reputationFactor` formula hid the policy choice
  from the spec, the conformance suite, and the audit trail.

- **The conformance suite pins this decision.** The regenerated vector
  `civic-value-computation-transit-interactive` (expected `points: 5048`
  for `reputationScore: 800`) now asserts `reputationFactor(800) = 0.8`,
  not `0.9`. Any future regression that re-introduces the `[0.5, 1.0]`
  floor will fail this vector and be caught at CI time. Per 06 §A3:
  "a normative MUST with no vector is a build failure" — and conversely,
  a normative spec change with no vector regeneration is also a build
  failure.

- **No invariants are relaxed.** I16 (reputation is LOCALLY COMPUTED,
  never accepted from peers) is unchanged. The function still takes the
  settlement service's value as input; the change is only the formula
  applied to that input. I20 (verifiers return false on bad input) is
  also unchanged — `reputationFactor` continues to fail-closed to 0 on
  malformed input (it just no longer fail-opens to 0.5).

## Alternatives considered

### (a) Update the spec to `[0.5, 1.0]` to match the implementation — rejected

The `[0.5, 1.0]` range is mathematically wrong for a multiplicative
factor (it cannot express zero). The spec's `[0,1]` is correct. Updating
the spec to match the implementation would propagate the
implementation's drift into the spec, inverting the constraint
hierarchy (Tier 1 follows Tier 3 — exactly what 06 §B2 forbids). The
implementation should follow the spec, not the other way around.

### (b) Add a bootstrap bonus in the spec — deferred to a future ADR

A `bootstrapBonus` field (e.g. "a brand-new node gets reputation treated
as 500 for its first 30 days, then decays to its actual score") would
address the bootstrapping concern without changing the `reputation`
factor's range. This is the right place to address the concern — at the
spec level, with its own conformance vectors and its own ADR. But it
requires a policy decision (what's the bonus amount? what's the decay
schedule? what stops a Sybil from cycling identities to refresh the
bonus?) that is out of scope for this drift-fix ADR. **Deferred to a
future ADR if bootstrapping proves problematic in practice.**

### (c) Keep the implementation's `[0.5, 1.0]` and file a spec-deferral ADR — rejected

This would document the drift as a "known spec deferral" rather than
fixing it. The hardening audit (Blocker E) specifically rejected this
path: silent drift is the problem, regardless of whether it is
documented after the fact. The fix is to bring the implementation into
conformance with the spec; the spec can be changed later if a future
ADR decides the implementation's behavior is preferable.

### (d) Make the floor configurable (per-deployment) — rejected

A configurable floor would let each deployment choose `[0,1]` or
`[0.5,1.0]`. This splits the network: nodes on different deployments
would compute different points for the same contribution, breaking the
"deterministic settlement" property that `05 §A5` relies on. The spec
must specify a single range; the implementation must follow it.

## Conformance impact

### Regenerated: `12-civic-points.json:civic-value-computation-transit-interactive`

- File: `/public/conformance/vectors/12-civic-points.json`
- Vector id: `civic-value-computation-transit-interactive`
- Input (unchanged):
  ```json
  {
    "type": "transit",
    "mib": 10,
    "qualityClass": "interactive",
    "knownGatewaysInRegion": 2,
    "distinctCounterparties": 3,
    "reputationScore": 800
  }
  ```
- Old expected `points`: `5679` (with `reputationFactor(800) = 0.9`
  under the `[0.5, 1.0]` formula).
- New expected `points`: `5048` (with `reputationFactor(800) = 0.8`
  under the `[0, 1]` formula).
- Delta: `-631` points (a `11.1%` reduction for `reputationScore=800`).
  This is the exact ratio `0.8 / 0.9 = 0.888…`, confirming the change
  is purely the reputation-factor formula.

### Other civic vectors — unaffected

The other vectors in `12-civic-points.json` either:
- Do not depend on `reputationFactor` (e.g.
  `civic-volume-factor-log2`, `civic-scarcity-single-gateway`,
  `civic-diversity-collapse`, `civic-holdback-30-percent`), OR
- Use `reputationScore: 1000` (where both formulas agree: `0.5 + 0.5 =
  1.0` vs `1000 / 1000 = 1.0`).

So no other vector in the suite changes. Only
`civic-value-computation-transit-interactive` is regenerated.

### Other suites — unaffected

No other conformance suite touches `reputationFactor`. The change is
scoped to suite 12.

### No new vectors are added

The existing `civic-value-computation-transit-interactive` vector is
sufficient to pin the formula. A second vector at `reputationScore: 0`
(expected `points: 0` under the new formula, `points: 631` under the
old) would be a useful additional regression test and is recommended as
a future task, but is not required to close Blocker E.

## Migration path

### For the sandbox reference (this codebase)

The fix is already applied in `src/lib/snp/civic.ts`. The conformance
runner recomputes `expected.points` live from the implementation, so
the regenerated vector `points: 5048` matches what the runner
produces. No further migration is required for the sandbox.

### For a future Rust reference (per ADR-0001)

The Rust reference MUST implement `reputationFactor(score) = score /
1000` clamped to `[0, 1]`. The Rust reference's conformance run against
`12-civic-points.json` MUST produce `points: 5048` for
`civic-value-computation-transit-interactive`. If the Rust reference
produces `points: 5679`, it has re-introduced the `[0.5, 1.0]` drift
and is non-conformant.

### For existing deployments

There are no existing ShareNet 2.0 deployments (the protocol has not
shipped). If a deployment exists at the time this ADR is merged, its
civic-points ledger will retroactively compute fewer points for
contributions by sub-1000-reputation nodes. This is a one-time
accounting correction, not a wire-format break — the receipt format and
the ledger format are unchanged.

### Rollback

Roll back by reverting `reputationFactor` to `0.5 + 0.5 × score / 1000`
in `civic.ts` and regenerating the vector back to `points: 5679`. This
re-opens Blocker E and is not recommended. If a future ADR adds a
bootstrap bonus, that ADR supersedes this one (in part) and the formula
changes again.

## Consequences

### Positive

- The implementation matches the spec. The audit trail is complete:
  the drift was found, the fix was applied, the ADR was filed, the
  vector was regenerated.
- Blocker E of the hardening audit is closed.
- The conformance suite now pins the `[0,1]` range. Any future
  regression that re-introduces the `[0.5, 1.0]` floor will fail
  `civic-value-computation-transit-interactive` at CI time.
- The mathematically correct range for a multiplicative factor is
  restored. The points formula can now express "this contribution
  earns zero civic points because the contributor is unknown."
- The bootstrapping concern is now visible — it must be solved at the
  spec level, not hidden in the implementation.

### Negative

- **New nodes earn 0 civic points until they build reputation.** This
  is the spec-correct behavior but may make network bootstrapping
  harder in practice (the "first contribution by the first node"
  problem). Mitigation: a future spec-level ADR adding a bootstrap
  bonus (see Alternatives (b)).
- **The `points: 5679 → 5048` change** is a one-time revision to a
  golden vector. Any external system that recorded the old expected
  value (e.g. a CI dashboard snapshot, a published test report) must
  be updated. This is a documentation concern, not a wire-format
  concern.
- **Human review is pending.** Per 06 §B6, a Tier 1 ADR requires a
  named human reviewer. This ADR is `accepted` provisionally; if the
  reviewer rejects, the implementation reverts to the `[0.5, 1.0]`
  floor and a follow-up spec-level ADR is filed to either (a) update
  the spec to `[0.5, 1.0]` or (b) add a bootstrap bonus.

### Neutral

- The `reputationScore` input range is still `[0, 1000]` — unchanged
  by this ADR. Only the *factor* formula changes, not the *score*
  range.
- The other civic factors (`volume_factor`, `quality`, `scarcity`,
  `diversity`) are unchanged.
- ADR-0005 (sub-linear volume factor) and this ADR are orthogonal:
  ADR-0005 changes `volume_factor`, this ADR changes `reputation`. Both
  reduce civic-points yield for different reasons (ADR-0005 breaks the
  "more bytes = more money" incentive; this ADR breaks the "any node
  earns half-credit" floor).

## Human reviewer

> Required for Tier 1 per `06-CONFORMANCE-AND-AI-MODEL.md §B6`. This
> ADR is `accepted` provisionally; if the reviewer rejects, the
> implementation reverts to the `[0.5, 1.0]` floor and a follow-up
> spec-level ADR is filed.

- **Reviewer name:** <PENDING — required before the N8 Civic Points
  milestone>
- **Review date:** <PENDING>
- **Review outcome:** <PENDING — approved | approved-with-conditions |
  rejected>
- **Conditions / notes:**
  - The reviewer should specifically evaluate the **bootstrapping
    concern**: is the `[0,1]` range (with no bootstrap bonus)
    acceptable for network cold-start? If not, the reviewer should
    require a follow-up spec-level ADR adding a bootstrap bonus as a
    condition of approval.
  - The reviewer should confirm the spec's `0–1` range is the intended
    production behavior, not an oversight in the spec drafting. (The
    spec's table is explicit; the audit found no record of a
    deliberate `[0.5, 1.0]` decision; the implementation drifted
    silently.)
  - The reviewer should spot-check the regenerated vector
    `civic-value-computation-transit-interactive` (expected `points:
    5048`) against an independent calculation to confirm the
    regeneration is correct.

## References

- Spec sections:
  - `05-CIVIC-CONTENT-CONSISTENCY.md §A5` (the `reputation ∈ [0,1]`
    normative table — the spec this ADR brings the implementation
    into conformance with).
  - `06-CONFORMANCE-AND-AI-MODEL.md §B2` (the four-tier constraint
    hierarchy — Tier 1 beats Tier 3; the implementation must follow
    the spec, not the other way around).
  - `06-CONFORMANCE-AND-AI-MODEL.md §B6` (ADR process — Tier 1
    requires named human approval; this ADR's `accepted` status is
    provisional on that approval).
  - `06-CONFORMANCE-AND-AI-MODEL.md §A3` ("a normative MUST with no
    vector is a build failure" — the regenerated vector pins this
    ADR's formula change).
- Audit findings:
  - Hardening audit Blocker E (the finding this ADR closes):
    `reputationFactor` returned `[0.5, 1.0]` but the spec says `[0,1]`.
- Invariants:
  - I16 — reputation is LOCALLY COMPUTED, never accepted from peers —
    unchanged by this ADR. The function still takes the settlement
    service's value as input; only the formula applied changes.
  - I20 — `verify*` returns false on bad input, never throws;
    `reputationFactor` continues to fail-closed to 0 on malformed
    input (no longer fail-opens to 0.5) — consistent with I20's
    "never permissive" spirit.
- Conformance vectors:
  - `12-civic-points.json:civic-value-computation-transit-interactive`
    (regenerated: expected `points: 5679 → 5048`).
- Related ADRs:
  - **ADR-0005** (sub-linear volume factor for Civic Points —
    orthogonal to this ADR; both reduce civic-points yield for
    different reasons).
  - **ADR-0006** (SNP-IK/0.1 handshake rename — ADR-0006's migration
    path anticipated "ADR-0007" as the future vetted-Noise_IK-library
    integration ADR. **That ADR number has been reassigned to this
    civic-reputation fix.** The future Noise_IK library migration ADR
    will be filed at the next free number after this ADR and ADR-0008
    (gateway DNS rebinding) — i.e. ADR-0009 or later. ADR-0006's
    internal references to "ADR-0007" for Noise_IK migration are
    repointed by this note; they are NOT modified in ADR-0006 itself
    because ADRs are immutable once accepted, and ADR-0006 is
    `accepted`.)
  - **Future ADR (deferred)** — bootstrap bonus for new nodes, if the
    `[0,1]` range proves problematic for network cold-start. Will be a
    Tier 1 spec-change ADR with its own conformance vectors.
