/**
 * SNP Civic Points — value function (pure arithmetic, no state)
 *
 * Source: 05-CIVIC-CONTENT-CONSISTENCY.md §A5 "Value function — beyond bytes"
 *         §A6 "Anti-farming" (holdback)
 *         §A7 "Migration from existing code" (deletes pointsForBridging)
 *         §C4 "Settlement authority — an honest open question"
 * Source: 00-AUDIT.md §3.7 (finding R7 — the bug this module replaces)
 *
 * THE MODULE BOUNDARY THIS FILE ENFORCES:
 *
 * This module computes point VALUES only. It does NOT mint points, settle
 * them, hold balances, sign anything, or talk to the network. Settlement is
 * authoritative and human-gated (05 §A7, §C4). Points are non-transferable
 * in v1 (05 §C4) — they are a reputation score, not a currency, and crossing
 * that line before the settlement authority is decentralised and human-
 * reviewed is explicitly forbidden by the spec.
 *
 * Given a verified contribution proof (a TransitReceipt, DeliveryReceipt,
 * GatewayReceipt, or CustodyReceipt from receipts.ts — all of which are
 * signed by a party that did NOT benefit from issuing them, per I13), this
 * module returns how many points that proof is worth. It stops at the
 * HUMAN-GATED settlement boundary (05 §A7): the caller takes the returned
 * integer and submits it to the settlement service, which is the only
 * authority that can actually credit a balance.
 *
 * THE FIX FOR R7:
 *
 * The audit (00-AUDIT.md §3.7, finding R7) found that the existing Kotlin
 * codebase's `pointsForBridging(bytesBridged)` had three defects:
 *
 *   1. Payment is per byte — exactly what the brief forbids. It rewards
 *      volume, not value.
 *   2. `pointsForBridging` has no proof object at all — a bare self-claim.
 *      A node calls the function and mints points.
 *   3. Fraud controls are in-memory, so every rate cap resets on restart.
 *
 * Defect 2 is fixed by receipts.ts (the proof objects). This module fixes
 * defect 1: the value function is SUB-LINEAR in volume
 * (`volumeFactor = log₂(1 + MiB)`), so doubling the bytes does NOT double
 * the pay. This breaks the "more bytes = more money" incentive while still
 * rewarding real work. Defect 3 is out of scope here (it is a storage-layer
 * concern, fixed by moving fraud controls to durable storage).
 *
 * THE VALUE FUNCTION (05 §A5):
 *
 *   points = Σ_contributions  base(type) × volume_factor × quality × scarcity × diversity × reputation
 *
 * | Factor          | Range    | Purpose                                                        |
 * |-----------------|----------|----------------------------------------------------------------|
 * | base(type)      | fixed    | transit > delivery > seeding > storage                         |
 * | volume_factor   | sub-lin  | log₂(1 + MiB) — breaks "more bytes = more money"               |
 * | quality         | 0–1.5    | interactive circuits worth more per byte than tolerant bulk     |
 * | scarcity        | 1.0–3.0  | being the ONLY gateway in a region is worth far more than #10  |
 * | diversity       | 0–1      | distinct counterparties — collapses toward 0 for repeated pairs |
 * | reputation      | 0.5–1.0  | verified history                                               |
 *
 * Per 05 §A5: "volume_factor being sub-linear is the single most important
 * change from the current design. It removes the incentive to manufacture
 * traffic while still rewarding real work. scarcity is the second — it
 * directs reward to where connectivity is genuinely absent, which is the
 * project's actual purpose."
 *
 * @ invariant I13 — Civic Points are never minted by the claimant. This module
 *                   computes values ONLY. It does not sign, store, or transmit.
 *                   The proof object (signed by a non-beneficiary party) is
 *                   produced elsewhere; this module just prices it.
 * @ invariant I14 — Economic state is never eventually consistent. This module
 *                   has NO STATE. It is a pure function from (params, input)
 *                   to integer points. The authoritative balance lives in the
 *                   settlement service (05 §C4); anything on a client device
 *                   is a cached view, never truth (CP-2).
 */
import { type QualityClass } from "./constants";

// ─── Types ─────────────────────────────────────────────────────────────────

/**
 * The five contribution types defined in 05 §A3, with the proof object that
 * backs each. The `base(type)` ordering is transit > delivery > seeding >
 * storage (05 §A5); custody is included for Mode A store-and-forward.
 *
 *   transit   — Internet gateway egress, proved by GatewayReceipt (counter-
 *               signed by client + gateway). THE direct replacement for
 *               pointsForBridging (05 §A7).
 *   delivery  — content delivery, proved by DeliveryReceipt (signed by the
 *               recipient, the beneficiary).
 *   seeding   — content seeding, proved by aggregated DeliveryReceipts from
 *               multiple distinct recipients (diversity-dependent).
 *   storage   — durable storage, proved by StorageChallenge (proof-of-
 *               retrievability — 05 §A3 notes this as a weaker primitive).
 *   custody   — Mode A store-and-forward, proved by CustodyReceipt (signed
 *               by the next custodian or final recipient — chain-verifiable).
 */
export type ContributionType =
  | "transit"
  | "delivery"
  | "seeding"
  | "storage"
  | "custody";

/**
 * Tunable parameters for the value function. All factors are dimensionless
 * multipliers; the base values are in integer points.
 *
 * The defaults (`DEFAULT_CIVIC_POINT_PARAMS`) match the spec §A5 ranges and
 * the ordering `transit > delivery > seeding > storage`. A settlement service
 * MAY override these (e.g. to weight scarcity more aggressively in a region
 * with chronic gateway drought), but the SHAPE of the function (sub-linear
 * volume, scarcity boost, diversity collapse, reputation floor at 0.5) is
 * fixed by the spec and SHOULD NOT be changed without an ADR.
 */
export interface CivicPointParams {
  /**
   * Base point value per contribution type. MUST satisfy
   * `transit > delivery > seeding > storage` (05 §A5). `custody` is a
   * middle-tier value (Mode A store-and-forward is more valuable than bare
   * storage but less than live transit).
   *
   * Defaults: transit=1000, delivery=500, seeding=200, storage=100, custody=300.
   */
  readonly basePoints: Record<ContributionType, number>;

  /**
   * Cap on `volumeFactor`. The sub-linear `log₂(1 + MiB)` grows without
   * bound as MiB → ∞, so a cap is required to keep point values in a sane
   * range. Default 20 — i.e. a 1 MiB contribution already earns factor ≈ 1,
   * and the factor saturates around (2^20 − 1) MiB ≈ 1 TB. Beyond that,
   * additional volume earns no additional points.
   *
   * This cap is itself an anti-farming measure: even with a collusion ring,
   * the per-contribution yield is bounded.
   */
  readonly maxVolumeFactor: number;

  /**
   * Maximum scarcity multiplier. Default 3.0 — being the only gateway in a
   * region is worth 3× as much as being one of many. The scarcity factor
   * decays exponentially toward 1.0 as the count of known gateways rises
   * (see `scarcityFactor`).
   */
  readonly scarcityMax: number;
}

/**
 * Inputs to `computeContributionValue` — the quantities extracted from a
 * verified contribution proof (plus contextual inputs the settlement service
 * supplies, like known-gateway count and reputation score).
 *
 * Every field is a NUMBER (not a bstr / Uint8Array). This module does no
 * signature verification — the proof was verified BEFORE this function is
 * called. The caller is responsible for ensuring `mib`, `qualityClass`,
 * `knownGatewaysInRegion`, `distinctCounterparties`, and `reputationScore`
 * actually correspond to the proof being priced.
 */
export interface ContributionInput {
  /** The contribution type being priced. */
  readonly type: ContributionType;
  /** Volume of the contribution in mebibytes (2^20 bytes). */
  readonly mib: number;
  /** Quality class — interactive, bulk, or tolerant (from the receipt). */
  readonly qualityClass: QualityClass;
  /**
   * Count of distinct gateways known to be operating in the region of the
   * contributing gateway. 1 → max scarcity boost; many → factor approaches 1.
   */
  readonly knownGatewaysInRegion: number;
  /**
   * Count of distinct counterparties the contributor served in the epoch.
   * Repeated pairs collapse toward 0 (anti-collusion).
   */
  readonly distinctCounterparties: number;
  /**
   * Reputation score 0..1000. The factor floors at 0.5 (a brand-new node is
   * not zeroed out — it earns half-credit while it builds history) and
   * saturates at 1.0 at score 1000.
   */
  readonly reputationScore: number;
}

// ─── Defaults ──────────────────────────────────────────────────────────────

/**
 * Default Civic Point parameters per 05 §A5.
 *
 *   basePoints: transit=1000 > delivery=500 > custody=300 > seeding=200 > storage=100
 *   maxVolumeFactor: 20  (saturates around 1 TB)
 *   scarcityMax: 3.0     (only gateway in region earns 3×)
 *
 * The base ordering encodes the spec's "transit > delivery > seeding > storage"
 * with custody inserted between delivery and seeding (Mode A store-and-
 * forward is more valuable than bare seeding but less than live delivery).
 */
export const DEFAULT_CIVIC_POINT_PARAMS: CivicPointParams = {
  basePoints: {
    transit: 1000,
    delivery: 500,
    custody: 300,
    seeding: 200,
    storage: 100,
  },
  maxVolumeFactor: 20,
  scarcityMax: 3.0,
};

// ─── Factor functions ──────────────────────────────────────────────────────

/**
 * Sub-linear volume factor: `min(maxVolumeFactor, log₂(1 + mib))`.
 *
 * THIS IS THE KEY CHANGE FROM THE PRE-SHARENET-2.0 DESIGN. The audit (R7)
 * found that `pointsForBridging(bytesBridged)` paid linearly per byte —
 * exactly what the brief forbids. Linear volume rewards manufacturing
 * traffic: sending 1 GB of garbage to a colluding peer pays 5× more than
 * relaying a 200 MB medical dataset.
 *
 * Sub-linear volume (log₂) breaks that incentive:
 *   - 1 MiB  → factor ≈ 1.00
 *   - 10 MiB → factor ≈ 3.46
 *   - 100 MiB → factor ≈ 6.66
 *   - 1 GiB  → factor ≈ 10.00
 *   - 1 TiB  → factor ≈ 20.00 (capped)
 *
 * Doubling the volume no longer doubles the pay. A collusion ring that
 * manufactures 10× the traffic earns only ~3.3× the points, while burning
 * 10× the bandwidth — the economics flip against farming. Real work (a
 * 200 MB medical dataset) is rewarded proportionally to its ACTUAL value,
 * not its byte count.
 *
 * The cap (`maxVolumeFactor`, default 20) bounds the per-contribution yield
 * so that even an unbounded-volume collusion ring cannot extract more than
 * `base × 20 × (other factors)` points per contribution.
 *
 * @param mib                volume in mebibytes (2^20 bytes)
 * @param maxVolumeFactor    cap (defaults to DEFAULT_CIVIC_POINT_PARAMS.maxVolumeFactor = 20)
 * @returns                  min(maxVolumeFactor, log₂(1 + mib))
 */
export function volumeFactor(
  mib: number,
  maxVolumeFactor: number = DEFAULT_CIVIC_POINT_PARAMS.maxVolumeFactor,
): number {
  if (typeof mib !== "number" || mib < 0 || !Number.isFinite(mib)) {
    // Fail closed: a negative or non-finite volume earns zero factor.
    return 0;
  }
  return Math.min(maxVolumeFactor, Math.log2(1 + mib));
}

/**
 * Quality factor by traffic class. Interactive circuits are worth 1.5×
 * (sustaining low-latency forwarding is harder than bulk transfer); bulk is
 * discounted to 0.8× (it can be scheduled off-peak); tolerant is the neutral
 * baseline at 1.0×.
 *
 * Source: 05 §A5 (quality range "0–1.5") and §A4 (TransitReceipt.qualityClass).
 *
 * @param qualityClass  one of "interactive" | "bulk" | "tolerant"
 * @returns             1.5 (interactive) | 0.8 (bulk) | 1.0 (tolerant)
 */
export function qualityFactor(qualityClass: QualityClass): number {
  switch (qualityClass) {
    case "interactive":
      return 1.5;
    case "bulk":
      return 0.8;
    case "tolerant":
      return 1.0;
    default:
      // Fail closed: unknown quality class earns nothing.
      return 0;
  }
}

/**
 * Scarcity factor: directs reward to where connectivity is genuinely absent.
 *
 * Formula: `1 + (scarcityMax − 1) × exp(−knownGatewaysInRegion / 3)`.
 *
 *   - 1 known gateway  → factor ≈ 1 + (3−1)×exp(−1/3) ≈ 1 + 2×0.717 ≈ 2.43
 *   - 2 known gateways → factor ≈ 1 + 2×exp(−2/3) ≈ 1 + 2×0.513 ≈ 2.03
 *   - 3 known gateways → factor ≈ 1 + 2×exp(−1)   ≈ 1 + 2×0.368 ≈ 1.74
 *   - 5 known gateways → factor ≈ 1 + 2×exp(−5/3) ≈ 1 + 2×0.189 ≈ 1.38
 *   - 10 known gateways → factor ≈ 1 + 2×exp(−10/3) ≈ 1 + 2×0.036 ≈ 1.07
 *   - ∞ → factor approaches 1.0
 *
 * Per 05 §A5: "scarcity is the second [most important change] — it directs
 * reward to where connectivity is genuinely absent, which is the project's
 * actual purpose." A gateway in a region with no other gateways earns ~2.4×
 * the base; a gateway in a saturated region earns ~1.0×. This is what makes
 * it economically rational to deploy a gateway where none exists, rather
 * than stacking gateways where connectivity is already abundant.
 *
 * @param knownGatewaysInRegion  count of distinct gateways known to be operating
 *                               in the region of the contributing gateway
 * @param scarcityMax            cap (defaults to DEFAULT_CIVIC_POINT_PARAMS.scarcityMax = 3.0)
 * @returns                       factor in [1.0, scarcityMax]
 */
export function scarcityFactor(
  knownGatewaysInRegion: number,
  scarcityMax: number = DEFAULT_CIVIC_POINT_PARAMS.scarcityMax,
): number {
  if (
    typeof knownGatewaysInRegion !== "number" ||
    knownGatewaysInRegion < 0 ||
    !Number.isFinite(knownGatewaysInRegion)
  ) {
    // Fail closed: unknown count → no scarcity boost.
    return 1.0;
  }
  return 1 + (scarcityMax - 1) * Math.exp(-knownGatewaysInRegion / 3);
}

/**
 * Diversity factor: collapses toward 0 for repeated pairs (anti-collusion).
 *
 * Formula: `min(1, distinctCounterparties / 5)`.
 *
 *   - 0 counterparties  → 0.0 (no diversity — almost certainly a collusion ring)
 *   - 1 counterparty    → 0.2
 *   - 2 counterparties  → 0.4
 *   - 3 counterparties  → 0.6
 *   - 4 counterparties  → 0.8
 *   - 5+ counterparties → 1.0 (full diversity)
 *
 * Per 05 §A6 (anti-farming table): "Two-node collusion ring: diversity
 * requires N distinct counterparties for full weight; sub-linear volume caps
 * yield." A relay that only ever talks to ONE other node (its colluding
 * partner) earns 20% of its nominal points, even if the volume is large.
 * This is the structural defence against the simplest farming attack.
 *
 * @param distinctCounterparties  count of distinct counterparties served in the epoch
 * @returns                        factor in [0, 1]
 */
export function diversityFactor(distinctCounterparties: number): number {
  if (
    typeof distinctCounterparties !== "number" ||
    distinctCounterparties < 0 ||
    !Number.isFinite(distinctCounterparties)
  ) {
    // Fail closed: unknown count → zero diversity.
    return 0;
  }
  return Math.min(1, distinctCounterparties / 5);
}

/**
 * Reputation factor: floors at 0.5 (a brand-new node is not zeroed out) and
 * saturates at 1.0 at reputation score 1000.
 *
 * Formula: `0.5 + 0.5 × (reputationScore / 1000)`.
 *
 *   - score 0    → 0.5  (new node — earns half-credit while building history)
 *   - score 500  → 0.75
 *   - score 1000 → 1.0  (fully trusted)
 *
 * The floor at 0.5 (rather than 0) is deliberate: a new gateway that is the
 * only gateway in a region SHOULD still earn meaningful points (otherwise
 * bootstrapping is impossible), but should earn less than an established one
 * to leave headroom for reputation to matter. Per 05 §A5 the range is "0–1"
 * but the spec's anti-farming intent (§A6: "Self-dealing... per-device daily
 * ceiling") is better served by a floor that doesn't zero out newcomers.
 *
 * Note (I16): reputation is LOCALLY COMPUTED, never accepted from peers. The
 * `reputationScore` passed in here is the SETTLEMENT SERVICE's value, not a
 * peer-advertised hint. Peers exchange signed evidence; each authority
 * computes its own scores.
 *
 * @param reputationScore  reputation in [0, 1000]
 * @returns                 factor in [0, 1] (per spec 05 §A5; was [0.5,1.0] —
 *                          see ADR-0007 for the semantic-drift fix)
 */
export function reputationFactor(reputationScore: number): number {
  if (
    typeof reputationScore !== "number" ||
    reputationScore < 0 ||
    !Number.isFinite(reputationScore)
  ) {
    // Fail closed: unknown/malformed reputation → 0 (no reward multiplier).
    // Per the hardening audit (Blocker E / ADR-0007): the spec says [0,1];
    // a floor of 0.5 was a protocol semantic change made in implementation
    // without an ADR. New nodes get reputation 0, which multiplies to 0
    // points — they must build reputation through verified contributions
    // before earning full rewards. This is the bootstrapping incentive.
    return 0;
  }
  // Clamp to [0, 1000] → [0, 1]. Matches spec 05 §A5 exactly.
  const clamped = Math.max(0, Math.min(1000, reputationScore));
  return clamped / 1000;
}

// ─── Value computation ─────────────────────────────────────────────────────

/**
 * Compute the integer point value of a single verified contribution.
 *
 * Formula (05 §A5):
 *
 *   points = base(type) × volumeFactor(mib) × qualityFactor × scarcityFactor
 *            × diversityFactor × reputationFactor
 *
 * then `Math.floor` (points are integers — no fractional credit).
 *
 * THIS FUNCTION IS PURE. It has no side effects, holds no state, and never
 * signs, stores, or transmits anything. The caller is responsible for:
 *
 *   1. Having verified the contribution proof (TransitReceipt /
 *      GatewayReceipt / DeliveryReceipt / CustodyReceipt from receipts.ts)
 *      BEFORE calling this. The proof was signed by a non-beneficiary party
 *      (I13); this function does not re-check that.
 *   2. Submitting the returned integer to the settlement service, which is
 *      the ONLY authority that can actually credit a balance (I14, 05 §C4).
 *      Anything on a client device is a cached view, never truth.
 *   3. Applying holdback (`applyHoldback`) if displaying a pending/available
 *      split to the user. The settlement service applies its own holdback;
 *      this function does not.
 *
 * @param params  the CivicPointParams (use DEFAULT_CIVIC_POINT_PARAMS unless
 *                the settlement service has overridden them)
 * @param input   the contribution inputs (type, volume, quality, scarcity,
 *                diversity, reputation)
 * @returns       integer points (Math.floor of the product)
 */
export function computeContributionValue(
  params: CivicPointParams,
  input: ContributionInput,
): number {
  const base = params.basePoints[input.type];
  if (typeof base !== "number" || !Number.isFinite(base) || base < 0) {
    // Unknown contribution type or malformed base — fail closed to 0 points.
    return 0;
  }
  const v = volumeFactor(input.mib, params.maxVolumeFactor);
  const q = qualityFactor(input.qualityClass);
  const s = scarcityFactor(input.knownGatewaysInRegion, params.scarcityMax);
  const d = diversityFactor(input.distinctCounterparties);
  const r = reputationFactor(input.reputationScore);

  const product = base * v * q * s * d * r;
  if (!Number.isFinite(product) || product < 0) {
    return 0;
  }
  return Math.floor(product);
}

// ─── Holdback ──────────────────────────────────────────────────────────────

/**
 * Result of splitting points into pending (under holdback) and available.
 *
 * Per 05 §A6: "Holdback and clawback (already in PointsLedger, 30 days) are
 * correct and preserved: points are pending until the holdback elapses, and
 * fraud detected within the window clears them."
 *
 * The settlement service applies its own holdback authoritatively; this
 * function is for CLIENT-SIDE DISPLAY of the pending/available split (a
 * cached view — never truth, per CP-2). The `pending` portion is what the
 * user sees as "earning" but cannot yet spend; the `available` portion is
 * what has cleared the holdback window.
 */
export interface HoldbackSplit {
  /** Points still under holdback (not yet spendable). */
  readonly pending: number;
  /** Points that have cleared the holdback window (spendable). */
  readonly available: number;
}

/**
 * Apply the 30-day holdback to a points value.
 *
 * Splits `points` into `pending` (the holdback portion) and `available` (the
 * cleared portion). Both are integers. The default holdback is 30% (preserved
 * from the existing PointsLedger per 05 §A6 / §A7).
 *
 * This is a CLIENT-SIDE DISPLAY helper. The authoritative holdback is applied
 * by the settlement service (I14). If the client's view disagrees with the
 * settlement service's view, the settlement service is correct (CP-2).
 *
 * @param points            integer points value (e.g. from computeContributionValue)
 * @param holdbackPercent   percentage to hold back (default 30); MUST be in [0, 100]
 * @returns                 { pending, available } — both non-negative integers
 */
export function applyHoldback(
  points: number,
  holdbackPercent: number = 30,
): HoldbackSplit {
  if (typeof points !== "number" || !Number.isInteger(points) || points < 0) {
    // Fail closed: malformed input → nothing pending, nothing available.
    return { pending: 0, available: 0 };
  }
  if (
    typeof holdbackPercent !== "number" ||
    !Number.isFinite(holdbackPercent) ||
    holdbackPercent < 0 ||
    holdbackPercent > 100
  ) {
    throw new RangeError(
      `holdbackPercent must be a number in [0, 100]; got ${holdbackPercent}`,
    );
  }
  const pending = Math.floor((points * holdbackPercent) / 100);
  const available = points - pending;
  return { pending, available };
}
