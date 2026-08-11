---
ADR: NNNN
Title: <short noun-phrase, imperative mood>
Status: proposed | accepted | rejected | superseded
Tier affected: 0 | 1 | 2 | 3
Date: YYYY-MM-DD
Deciders: <named humans required for Tier 0/1; list agent owner + reviewer(s) for Tier 2>
---

# ADR-NNNN — <Title>

<!--
  ADR process: 06-CONFORMANCE-AND-AI-MODEL.md §B6.
  File path convention: docs/adr/NNNN-title-kebab-case.md
  Tier definitions (06 §B2):
    TIER 0  GOLDEN VECTORS          machine-checked. Disagreement = you are wrong.
    TIER 1  NORMATIVE SPEC          MUST/SHALL. Change requires ADR + version bump.
    TIER 2  API CONTRACTS           interface signatures. Change requires ADR.
    TIER 3  IMPLEMENTATION          free choice. Language, structure, style.
  Tier 0 and Tier 1 ADRs REQUIRE named human approval before merging.
  Tier 2 requires the owning agent plus one reviewer.
  Tier 3 changes do NOT require an ADR — pick freely and document in code.
-->

## Context

Why is this decision needed *now*? What problem, constraint, audit finding,
or interop failure forces a choice? Reference the spec section(s) and any
audit finding by ID (e.g. 00-AUDIT.md §3.1, R7). State what happens if we
do nothing.

Keep this section concrete and bounded. If the context is "we discovered X
during conformance vector generation," say so and link the vector file.

## Decision

What is being decided? State the change in one paragraph, in imperative
mood: "We adopt X. We reject Y." Include the exact field, constant, or
interface signature being changed when applicable.

## Rationale

Why this option over the alternatives? Tie the rationale back to:

- The four-tier constraint hierarchy (06 §B2) — which tier does this
  decision sit in, and which tier beats it?
- The invariants (06 §B3) — which I-numbers does this uphold or relax?
- The forbidden changes (06 §B4) — confirm this ADR does not authorise
  any of them (or, if it does, that human approval has been obtained).
- The conformance suite (06 §A4) — which suites/vectors pin this
  decision so an implementation cannot silently drift.

## Alternatives considered

For each alternative, give:
1. The option.
2. Why it was rejected.
3. What would have to change for it to become viable.

Be honest about close calls. If two alternatives were nearly equal, say so
and name the deciding factor.

## Conformance impact

Which conformance vectors (Suite 01–14) change, are added, or are
invalidated by this decision? Reference each vector by `id` from
`/home/z/my-project/public/conformance/vectors/`. If a vector must be
regenerated, name the file and the expected delta. If no vector is
affected, say so explicitly and explain why (e.g. "the change is
implementation-only; the wire format is unchanged").

Per 06 §A3: **a normative MUST with no vector is a build failure.** This
section is the contract between the ADR and CI.

## Migration path

How do existing implementations adapt? Cover:

- What breaks (which signatures, which `ObjectId`s, which routes).
- The upgrade sequence (which module ships first, which ADR depends on it).
- The interop story (do old and new implementations coexist during
  rollout, or is a flag day required?).
- Rollback plan (under what conditions is this ADR reversed, and what
  does reversal cost?).

If this ADR cannot be rolled back without a protocol version bump, say
so plainly.

## Consequences

### Positive

What becomes easier, safer, or more correct? What audit findings are
closed? What invariants are newly enforceable?

### Negative

What becomes harder? What new attack surface, performance cost, or
operational burden is introduced? What technical debt does this create
and where is it tracked?

### Neutral

Side-effects that are neither good nor bad but should be noted (e.g.
"all `ObjectId`s change; existing test data must be regenerated").

## Human reviewer

> Required for Tier 0 and Tier 1 ADRs per 06 §B6. Optional for Tier 2
> (owning agent + one reviewer suffices). Forbidden to omit for Tier 0/1.

- **Reviewer name:** <human>
- **Review date:** YYYY-MM-DD
- **Review outcome:** approved | approved-with-conditions | rejected
- **Conditions / notes:** <if approved-with-conditions, list them; the
  ADR is not "accepted" until all conditions are satisfied and this line
  is updated with the final approval date>

If the reviewer field is blank for a Tier 0/1 ADR, the ADR is
`proposed`, NOT `accepted`. CI MUST reject `accepted` Tier 0/1 ADRs
without a named reviewer.

## References

- Spec sections: <e.g. 02-PROTOCOL-SPEC.md §1, §3.2>
- Audit findings: <e.g. 00-AUDIT.md §3.1, R7>
- Invariants: <e.g. I1, I4, I15>
- Conformance vectors: <e.g. 01-cbor.json:cbor-map-ordering-length-first>
- Related ADRs: <e.g. supersedes ADR-0007, referenced by ADR-0012>
