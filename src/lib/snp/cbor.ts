/**
 * SNP-CBOR — Canonical CBOR per RFC 8949 §4.2.1
 *
 * Source: 02-PROTOCOL-SPEC.md §1 "Encoding rules (SNP-CBOR)"
 *
 * This is the single most load-bearing file in the conformance foundation.
 * The audit (00-AUDIT.md §3.2) found that the existing Kotlin implementation
 * sorts map keys with `map.keys.sorted()` (lexicographic on the raw string),
 * while the Python implementation sorts by the fully-encoded key bytes
 * (length-first for text strings). These produce DIFFERENT byte strings,
 * which means signatures made on one platform cannot verify on the other.
 *
 * SNP-CBOR rules enforced here (all MUST, not SHOULD):
 *  1. Map keys sorted by bytewise lexicographic order of FULLY ENCODED key
 *     (including major-type/length head). For text-string keys this is
 *     length-first, then UTF-8 bytes.
 *  2. Integers use shortest-form encoding. Definite lengths only.
 *     No indefinite-length items.
 *  3. No floats, no tags, no undefined. Simple values limited to
 *     false (0xF4), true (0xF5), null (0xF6).
 *  4. Duplicate map keys MUST be rejected on decode.
 *  5. Decoders MUST reject non-canonical input (wrong key order,
 *     non-shortest ints) — canonical-only, no leniency.
 *  6. Byte strings are major type 2; text strings major type 3.
 *  7. Trailing bytes after a complete item MUST be rejected.
 *
 * @ invariant I1 — All signed structures use SNP-CBOR with length-first key ordering
 */

// ─── CBOR major types ──────────────────────────────────────────────────────
const MT_UNSIGNED = 0x00; // major type 0 — unsigned int
const MT_NEGATIVE = 0x20; // major type 1 — negative int
const MT_BYTESTRING = 0x40; // major type 2 — byte string
const MT_TEXTSTRING = 0x60; // major type 3 — text string
const MT_ARRAY = 0x80; // major type 4 — array
const MT_MAP = 0xa0; // major type 5 — map
const MT_SIMPLE = 0xe0; // major type 7 — simple/float/break

// Simple values (RFC 8949 §3.3)
const SIMPLE_FALSE = 0xf4;
const SIMPLE_TRUE = 0xf5;
const SIMPLE_NULL = 0xf6;

// ─── Public types ──────────────────────────────────────────────────────────
export type CborValue =
  | null
  | boolean
  | number // must be safe integer
  | bigint
  | Uint8Array // bstr
  | string // tstr
  | CborValue[] // array
  | Map<string | Uint8Array, CborValue>; // map

export interface CborEncodeOptions {
  /**
   * If true (default), the encoder enforces canonical rules on input:
   * map keys must already be in canonical order, or it sorts them.
   * Setting this to false produces non-conformant output and is only
   * used internally by negative-test generators.
   */
  enforceCanonical?: boolean;
}

export class CborError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "NON_CANONICAL"
      | "DUPLICATE_KEY"
      | "TRAILING_BYTES"
      | "UNSUPPORTED"
      | "DECODE_ERROR"
      | "MALFORMED",
  ) {
    super(message);
    this.name = "CborError";
  }
}

// ─── Encoding ──────────────────────────────────────────────────────────────

/** Encode a CborValue to canonical CBOR bytes. */
export function encode(value: CborValue, opts: CborEncodeOptions = {}): Uint8Array {
  const chunks: Uint8Array[] = [];
  encodeInto(value, chunks, opts);
  return concat(chunks);
}

function encodeInto(
  value: CborValue,
  out: Uint8Array[],
  opts: CborEncodeOptions,
): void {
  if (value === null) {
    out.push(u8(SIMPLE_NULL));
    return;
  }
  if (value === false) {
    out.push(u8(SIMPLE_FALSE));
    return;
  }
  if (value === true) {
    out.push(u8(SIMPLE_TRUE));
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new CborError(
        `SNP-CBOR forbids floats; got non-integer number ${value}`,
        "UNSUPPORTED",
      );
    }
    encodeInteger(value, out);
    return;
  }
  if (typeof value === "bigint") {
    encodeBigint(value, out);
    return;
  }
  if (typeof value === "string") {
    encodeTextString(value, out);
    return;
  }
  if (value instanceof Uint8Array) {
    encodeByteString(value, out);
    return;
  }
  if (Array.isArray(value)) {
    encodeArray(value, out, opts);
    return;
  }
  if (value instanceof Map) {
    encodeMap(value, out, opts);
    return;
  }
  throw new CborError(
    `SNP-CBOR cannot encode value of type ${typeof value}`,
    "UNSUPPORTED",
  );
}

function encodeInteger(n: number, out: Uint8Array[]): void {
  if (n < 0) {
    // negative int: major type 1, argument = -1 - n
    writeHead(MT_NEGATIVE, BigInt(-1) - BigInt(n), out);
  } else {
    writeHead(MT_UNSIGNED, BigInt(n), out);
  }
}

function encodeBigint(n: bigint, out: Uint8Array[]): void {
  if (n < 0n) {
    writeHead(MT_NEGATIVE, -1n - n, out);
  } else {
    writeHead(MT_UNSIGNED, n, out);
  }
}

function encodeTextString(s: string, out: Uint8Array[]): void {
  const bytes = new TextEncoder().encode(s);
  writeHead(MT_TEXTSTRING, BigInt(bytes.length), out);
  out.push(bytes);
}

function encodeByteString(b: Uint8Array, out: Uint8Array[]): void {
  writeHead(MT_BYTESTRING, BigInt(b.length), out);
  out.push(b);
}

function encodeArray(arr: CborValue[], out: Uint8Array[], opts: CborEncodeOptions): void {
  writeHead(MT_ARRAY, BigInt(arr.length), out);
  for (const item of arr) encodeInto(item, out, opts);
}

function encodeMap(
  map: Map<string | Uint8Array, CborValue>,
  out: Uint8Array[],
  opts: CborEncodeOptions,
): void {
  // CRITICAL: sort by the fully-encoded key bytes (length-first for text
  // strings, because the length head is part of the encoded key).
  // This is the fix for audit finding 00-AUDIT.md §3.2.
  const encodedKeys: { key: Uint8Array; value: CborValue }[] = [];
  for (const [k, v] of map.entries()) {
    const keyBuf: Uint8Array[] = [];
    if (typeof k === "string") {
      encodeTextString(k, keyBuf);
    } else if (k instanceof Uint8Array) {
      encodeByteString(k, keyBuf);
    } else {
      throw new CborError(
        `Map keys must be string or Uint8Array; got ${typeof k}`,
        "UNSUPPORTED",
      );
    }
    encodedKeys.push({ key: concat(keyBuf), value: v });
  }
  // Bytewise lexicographic order on the FULLY ENCODED key (head + body).
  encodedKeys.sort((a, b) => compareBytes(a.key, b.key));

  // Reject duplicate keys (should not happen after sorting if input was sane,
  // but defends against pathological inputs).
  for (let i = 1; i < encodedKeys.length; i++) {
    if (compareBytes(encodedKeys[i - 1].key, encodedKeys[i].key) === 0) {
      throw new CborError(
        "Duplicate map key after canonical sort",
        "DUPLICATE_KEY",
      );
    }
  }

  writeHead(MT_MAP, BigInt(encodedKeys.length), out);
  for (const { key, value } of encodedKeys) {
    out.push(key);
    encodeInto(value, out, opts);
  }
}

/** Write a CBOR head: major type + argument using shortest-form encoding. */
function writeHead(majorType: number, arg: bigint, out: Uint8Array[]): void {
  if (arg < 24) {
    out.push(u8(majorType | Number(arg)));
  } else if (arg <= 0xff) {
    out.push(u8(majorType | 24));
    out.push(u8(Number(arg)));
  } else if (arg <= 0xffff) {
    out.push(u8(majorType | 25));
    out.push(u16(Number(arg)));
  } else if (arg <= 0xffffffff) {
    out.push(u8(majorType | 26));
    out.push(u32(Number(arg)));
  } else {
    out.push(u8(majorType | 27));
    out.push(u64(arg));
  }
}

// ─── Decoding ──────────────────────────────────────────────────────────────

export interface CborDecodeResult {
  value: CborValue;
  /** Number of bytes consumed (the full input length must equal this unless allowTrailing is set). */
  consumed: number;
}

/**
 * Decode canonical CBOR bytes. Throws CborError on non-canonical input,
 * duplicate keys, or trailing bytes.
 */
export function decode(bytes: Uint8Array): CborValue {
  const result = decodeAt(bytes, 0);
  if (result.consumed !== bytes.length) {
    throw new CborError(
      `Trailing bytes after CBOR item: consumed ${result.consumed} of ${bytes.length}`,
      "TRAILING_BYTES",
    );
  }
  return result.value;
}

/** Decode without enforcing the no-trailing-bytes rule (used by negative tests). */
export function decodeAllowTrailing(bytes: Uint8Array): CborDecodeResult {
  return decodeAt(bytes, 0);
}

function decodeAt(bytes: Uint8Array, offset: number): CborDecodeResult {
  if (offset >= bytes.length) {
    throw new CborError("Unexpected end of input", "DECODE_ERROR");
  }
  const firstByte = bytes[offset];
  const majorType = firstByte & 0xe0;
  const ai = firstByte & 0x1f;

  // Short-form argument (ai < 24): the value is the ai itself.
  // Long-form argument (24..27): 1/2/4/8 byte big-endian follows.
  // 31: break — only valid for indefinite-length, which SNP-CBOR forbids.
  // 28..30: reserved — forbidden.
  let arg: bigint;
  let consumed = 1;
  if (ai < 24) {
    arg = BigInt(ai);
  } else if (ai === 24) {
    consumed += 1;
    arg = BigInt(readU8(bytes, offset + 1));
  } else if (ai === 25) {
    consumed += 2;
    arg = BigInt(readU16(bytes, offset + 1));
  } else if (ai === 26) {
    consumed += 4;
    arg = BigInt(readU32(bytes, offset + 1));
  } else if (ai === 27) {
    consumed += 8;
    arg = readU64(bytes, offset + 1);
  } else if (ai === 31) {
    throw new CborError(
      "Indefinite-length encoding is forbidden in SNP-CBOR (RFC 8949 §4.2.1)",
      "NON_CANONICAL",
    );
  } else {
    throw new CborError(
      `Reserved additional information value ${ai}`,
      "NON_CANONICAL",
    );
  }

  switch (majorType) {
    case MT_UNSIGNED:
      // Verify shortest-form (audit finding: must reject non-shortest ints).
      verifyShortestForm(ai, arg, firstByte);
      return { value: asIntValue(arg), consumed };

    case MT_NEGATIVE: {
      verifyShortestForm(ai, arg, firstByte);
      const negative = -1n - arg;
      return { value: asIntValue(negative), consumed };
    }

    case MT_BYTESTRING: {
      const len = asSafeNumber(arg, "byte string length");
      const end = offset + consumed + len;
      if (end > bytes.length) {
        throw new CborError("Byte string runs past end of input", "DECODE_ERROR");
      }
      const value = bytes.slice(offset + consumed, end);
      return { value, consumed: consumed + len };
    }

    case MT_TEXTSTRING: {
      const len = asSafeNumber(arg, "text string length");
      const end = offset + consumed + len;
      if (end > bytes.length) {
        throw new CborError("Text string runs past end of input", "DECODE_ERROR");
      }
      const value = new TextDecoder().decode(bytes.slice(offset + consumed, end));
      return { value, consumed: consumed + len };
    }

    case MT_ARRAY: {
      const len = asSafeNumber(arg, "array length");
      let pos = offset + consumed;
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) {
        const r = decodeAt(bytes, pos);
        arr.push(r.value);
        pos += r.consumed;
      }
      return { value: arr, consumed: pos - offset };
    }

    case MT_MAP: {
      const len = asSafeNumber(arg, "map length");
      let pos = offset + consumed;
      const map = new Map<string | Uint8Array, CborValue>();
      let prevKeyEncoded: Uint8Array | null = null;
      for (let i = 0; i < len; i++) {
        // Decode key first, capturing its encoded form for canonical-order check.
        const keyStart = pos;
        const keyResult = decodeAt(bytes, keyStart);
        const keyEncoded = bytes.slice(keyStart, keyStart + keyResult.consumed);
        pos = keyStart + keyResult.consumed;

        // Verify canonical ordering: this key must be strictly greater than the previous.
        if (prevKeyEncoded !== null) {
          const cmp = compareBytes(prevKeyEncoded, keyEncoded);
          if (cmp === 0) {
            throw new CborError(
              "Duplicate map key in CBOR input",
              "DUPLICATE_KEY",
            );
          }
          if (cmp > 0) {
            throw new CborError(
              "Map keys are not in canonical (length-first) order",
              "NON_CANONICAL",
            );
          }
        }
        prevKeyEncoded = keyEncoded;

        const valResult = decodeAt(bytes, pos);
        pos += valResult.consumed;

        // Use the decoded key. If it's a string, use string; if bstr, use Uint8Array.
        const keyValue =
          typeof keyResult.value === "string"
            ? keyResult.value
            : keyResult.value instanceof Uint8Array
              ? keyResult.value
              : null;
        if (keyValue === null) {
          throw new CborError(
            "Map keys must be text or byte strings in SNP-CBOR",
            "UNSUPPORTED",
          );
        }
        map.set(keyValue, valResult.value);
      }
      return { value: map, consumed: pos - offset };
    }

    case MT_SIMPLE: {
      // Allowed simple values: false (20), true (21), null (22).
      // 23 (undefined) is forbidden. Anything else with major type 7 is
      // either a float (forbidden) or an unknown simple (forbidden).
      if (ai !== 20 && ai !== 21 && ai !== 22) {
        // Could be a float (ai=25/26/27) — all forbidden.
        throw new CborError(
          `Simple value ${ai} / floats / undefined are forbidden in SNP-CBOR`,
          "UNSUPPORTED",
        );
      }
      // For these three, ai is already < 24 so the head was a single byte
      // and there's nothing more to read.
      if (ai >= 24) {
        // unreachable — ai was < 24 for the short-form path
        throw new CborError("Unreachable simple-value path", "MALFORMED");
      }
      // Re-derive ai from the first byte (since arg = BigInt(ai) only for ai<24).
      const simpleAi = firstByte & 0x1f;
      if (simpleAi === 20) return { value: false, consumed };
      if (simpleAi === 21) return { value: true, consumed };
      if (simpleAi === 22) return { value: null, consumed };
      throw new CborError(`Forbidden simple value ${simpleAi}`, "UNSUPPORTED");
    }

    default:
      throw new CborError(
        `Unknown CBOR major type ${majorType >> 5}`,
        "UNSUPPORTED",
      );
  }
}

/** Verify that the integer was encoded in shortest form (RFC 8949 §3.1). */
function verifyShortestForm(ai: number, arg: bigint, firstByte: number): void {
  // ai < 24: always shortest.
  if (ai < 24) return;
  // ai === 24: 1-byte form. Arg must require 1 byte (i.e., >= 24).
  if (ai === 24) {
    if (arg < 24n)      throw new CborError(
        `Non-shortest integer encoding: value ${arg} fit in ai<24 but used 1-byte form`,
        "NON_CANONICAL",
      );
    return;
  }
  if (ai === 25) {
    if (arg < 256n)
      throw new CborError(
        `Non-shortest integer encoding: value ${arg} fit in 1 byte but used 2-byte form`,
        "NON_CANONICAL",
      );
    return;
  }
  if (ai === 26) {
    if (arg < 65536n)
      throw new CborError(
        `Non-shortest integer encoding: value ${arg} fit in 2 bytes but used 4-byte form`,
        "NON_CANONICAL",
      );
    return;
  }
  if (ai === 27) {
    if (arg < 4294967296n)
      throw new CborError(
        `Non-shortest integer encoding: value ${arg} fit in 4 bytes but used 8-byte form`,
        "NON_CANONICAL",
      );
    return;
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Convert a decoded CBOR integer (always read as bigint) to the appropriate
 * JS type. Values within the safe-integer range become `number`; larger
 * values remain `bigint`. Both are valid members of CborValue.
 */
function asIntValue(n: bigint): number | bigint {
  if (n > Number.MAX_SAFE_INTEGER || n < Number.MIN_SAFE_INTEGER) {
    return n;
  }
  return Number(n);
}

/** Like asIntValue but returns a JS number, throwing if the value is too large. */
function asSafeNumber(n: bigint, ctx: string): number {
  if (n > Number.MAX_SAFE_INTEGER || n < Number.MIN_SAFE_INTEGER) {
    throw new CborError(
      `${ctx} ${n} exceeds JavaScript safe-integer range`,
      "UNSUPPORTED",
    );
  }
  return Number(n);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function u8(n: number): Uint8Array {
  return new Uint8Array([n & 0xff]);
}
function u16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
function u32(n: number): Uint8Array {
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ]);
}
function u64(n: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}
function readU8(b: Uint8Array, o: number): number {
  if (o + 1 > b.length) throw new CborError("Unexpected EOF reading u8", "DECODE_ERROR");
  return b[o];
}
function readU16(b: Uint8Array, o: number): number {
  if (o + 2 > b.length) throw new CborError("Unexpected EOF reading u16", "DECODE_ERROR");
  return (b[o] << 8) | b[o + 1];
}
function readU32(b: Uint8Array, o: number): number {
  if (o + 4 > b.length) throw new CborError("Unexpected EOF reading u32", "DECODE_ERROR");
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
function readU64(b: Uint8Array, o: number): bigint {
  if (o + 8 > b.length) throw new CborError("Unexpected EOF reading u64", "DECODE_ERROR");
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[o + i]);
  return v;
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

// ─── Convenience: build a canonical map from a plain object ────────────────
/**
 * Build a CborValue map from a plain object. Keys must be strings or
 * Uint8Arrays. The map is stored in a JS Map; canonical ordering is
 * applied at encode time. This is the idiomatic way to build a CBOR map
 * for SNP structures.
 */
export function cborMap(
  entries: Array<[string | Uint8Array, CborValue]>,
): Map<string | Uint8Array, CborValue> {
  const m = new Map<string | Uint8Array, CborValue>();
  for (const [k, v] of entries) m.set(k, v);
  return m;
}

/** Convert a CborValue map to a plain JS object (string keys only) for inspection. */
export function mapToObject(m: Map<string | Uint8Array, CborValue>): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  for (const [k, v] of m.entries()) {
    if (typeof k === "string") {
      obj[k] = v instanceof Map ? mapToObject(v) : v;
    }
  }
  return obj;
}
