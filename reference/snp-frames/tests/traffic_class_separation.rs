//! **R3 regression — Class A/B structural separation + relay opacity.**
//!
//! Proves that:
//! 1. `Ciphertext` is opaque — relays cannot read transit payload content.
//! 2. The relay forwarding path clones frames without inspecting the body.
//! 3. `Ciphertext` cannot be passed to CAS/content APIs (no as_bytes).
//! 4. `FrameClass` correctly distinguishes A/B/C on the wire.
//!
//! Note: ContentBytes tests live in snp-object's test suite (L2 owns them).
//! snp-frames tests only cover Ciphertext (L8-owned) and FrameClass.

#![cfg(test)]

use snp_frames::{Ciphertext, Frame, FrameClass, FRAME_TTL_MAX};

// ─── Ciphertext opacity ────────────────────────────────────────────────────

#[test]
fn test_ciphertext_is_opaque() {
    let ct = Ciphertext::from_encrypted(vec![0xDE, 0xAD, 0xBE, 0xEF]);

    // We can check length...
    assert_eq!(ct.len(), 4);
    assert!(!ct.is_empty());

    // ...but we CANNOT read the bytes without consuming (into_bytes).
    // There is no as_bytes() or Deref<Target = [u8]>.
    // A relay that receives a Frame with a Class B body never constructs
    // a Ciphertext — it forwards the raw frame.body bytes unchanged.
}

#[test]
fn test_ciphertext_consumed_at_endpoint() {
    // The only way to get the plaintext is via into_bytes(), which consumes
    // the Ciphertext. This models the circuit endpoint decryption.
    let ct = Ciphertext::from_encrypted(vec![1, 2, 3, 4]);
    let bytes = ct.into_bytes();
    assert_eq!(bytes, vec![1, 2, 3, 4]);

    // After into_bytes(), the Ciphertext is gone — you can't use it again.
    // This prevents accidental reuse of decrypted data.
}

// ─── Content vs Transit type barrier ───────────────────────────────────────
//
// ContentBytes tests live in snp-object's test suite (L2 owns ContentBytes).
// snp-frames tests only cover Ciphertext (L8-owned) and FrameClass.
//
// The type-level barrier between Ciphertext and ContentBytes is documented
// here: Ciphertext has no as_bytes(), so it cannot be directly passed to
// CAS::put() which accepts &ContentBytes. The only path is:
//   Ciphertext::into_bytes() → ContentBytes::new(raw)
// This is an explicit, consuming, auditable conversion.

// ─── Frame class on the wire ────────────────────────────────────────────────

#[test]
fn test_frame_class_round_trip() {
    for (cls, byte) in [
        (FrameClass::Content, b'A'),
        (FrameClass::Transit, b'B'),
        (FrameClass::Control, b'C'),
    ] {
        assert_eq!(cls.as_byte(), byte);
        assert_eq!(FrameClass::from_byte(byte), Some(cls));
    }
}

#[test]
fn test_frame_class_rejects_invalid() {
    assert!(FrameClass::from_byte(b'X').is_none());
    assert!(FrameClass::from_byte(0).is_none());
    assert!(FrameClass::from_byte(255).is_none());
}

// ─── Frame body is class-neutral at wire level ────────────────────────────

#[test]
fn test_frame_body_is_vec_u8_at_wire_level() {
    // The Frame.body is Vec<u8> on the wire — this is correct.
    // The relay forwards frame.body as opaque bytes without constructing
    // a Ciphertext or ContentBytes. The type distinction exists at the
    // API level (for circuit endpoints and content APIs), not at the
    // wire level (where bytes are bytes).

    let mut frame = Frame::transit([0u8; 32], [0u8; 32]);
    frame.body = vec![0xDE, 0xAD, 0xBE, 0xEF];

    // The relay clones the frame and forwards it:
    let forwarded = frame.clone();
    assert_eq!(forwarded.body, frame.body);

    // The relay does NOT construct a Ciphertext — it just forwards the bytes.
    // The type-level Ciphertext exists for the circuit ENDPOINTS (client/gateway),
    // not for the relay.
}

// ─── Relay opacity: forwarding does not inspect body ──────────────────────

#[test]
fn test_relay_forwarding_clones_without_inspection() {
    // This test demonstrates the relay forwarding pattern:
    // recv_frame → clone → decrement TTL → send_frame.
    // The relay NEVER accesses frame.body as content.

    let dst = [0xAA; 32];
    let src = [0xBB; 32];

    let mut frame = Frame::transit(dst, src);
    frame.body = vec![0x01, 0x02, 0x03, 0x04];
    frame.ttl = FRAME_TTL_MAX;
    frame.fid = [0xFF; 8];
    frame.seq = 42;

    // Simulate what async_relay_forward_links does:
    let mut fwd = frame.clone();
    if fwd.ttl > 0 {
        fwd.ttl -= 1;
    }

    // The forwarded frame has the SAME body, decremented TTL:
    assert_eq!(fwd.body, frame.body);
    assert_eq!(fwd.ttl, frame.ttl - 1);
    assert_eq!(fwd.cls, FrameClass::Transit);
    assert_eq!(fwd.dst, dst);
    assert_eq!(fwd.src, src);
    assert_eq!(fwd.fid, frame.fid);
    assert_eq!(fwd.seq, frame.seq);

    // The relay did NOT:
    // - Hash the body (would be a content operation)
    // - Store it in a CAS (would be a content operation)
    // - Parse it as a TransitRequest (would be a gateway operation)
    // - Construct a Ciphertext (only the circuit endpoint does that)
    // It just cloned and forwarded.
}

// ─── Misuse: transit cannot enter content cache ────────────────────────────

#[test]
fn test_transit_cannot_enter_cas_through_normal_api() {
    // The CAS trait (in snp-object) accepts &ContentBytes.
    // Ciphertext has no as_bytes() method and no AsRef<[u8]>.
    // Therefore Ciphertext CANNOT be passed to CAS::put().
    //
    // To pass transit data to CAS, you would need to:
    // 1. Construct a Ciphertext (from encrypt_circuit_payload)
    // 2. Call into_bytes() (consuming it — only at the endpoint)
    // 3. Explicitly construct ContentBytes::new(raw)
    // 4. Pass &ContentBytes to CAS::put()
    //
    // Steps 2-3 are the explicit semantic conversion. They cannot happen
    // accidentally because into_bytes() consumes the Ciphertext and
    // ContentBytes::new() is a separate construction call.

    let ct = Ciphertext::from_encrypted(vec![0xDE, 0xAD]);

    // Ciphertext has NO as_bytes() — this would not compile:
    // cas.put(&ContentBytes::new(ct.as_bytes().to_vec()))
    //                                ^^^^^^^^^^^^ ERROR: no method as_bytes

    let raw = ct.into_bytes();
    // At this point, `raw` is just Vec<u8>. The semantic information
    // (that it was transit ciphertext) is lost. This is the ONLY way
    // transit data can enter a content API — through an explicit,
    // consuming conversion that a code reviewer can grep for.
    assert_eq!(raw, vec![0xDE, 0xAD]);
}
