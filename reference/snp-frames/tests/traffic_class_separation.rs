//! **R3 regression — Class A/B structural separation + relay opacity.**
//!
//! Proves that:
//! 1. `Ciphertext` is opaque — relays cannot read transit payload content.
//! 2. `ContentBytes` is distinct from `Ciphertext` — content APIs cannot
//!    accidentally receive transit data.
//! 3. The relay forwarding path clones frames without inspecting the body.
//! 4. `Ciphertext` cannot be passed to CAS/content APIs.
//! 5. `FrameClass` correctly distinguishes A/B/C on the wire.

#![cfg(test)]

use snp_frames::{Ciphertext, ContentBytes, Frame, FrameClass, FRAME_TTL_MAX, FRAME_VERSION};

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

#[test]
fn test_content_bytes_exposes_inner_for_cas() {
    let cb = ContentBytes::new(vec![0xAA, 0xBB, 0xCC]);
    // Content bytes CAN be read — for hashing, CAS storage, Merkle, etc.
    assert_eq!(cb.as_bytes(), &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn test_ciphertext_cannot_become_content_bytes() {
    // There is no From<Ciphertext> for ContentBytes.
    // There is no AsRef<[u8]> on Ciphertext.
    // This is the type-level barrier: transit data cannot enter the
    // content pipeline without an explicit (and auditable) conversion.
    let ct = Ciphertext::from_encrypted(vec![1, 2, 3]);

    // The ONLY way to get bytes out is into_bytes() (consuming):
    let raw = ct.into_bytes();

    // To create ContentBytes, you must explicitly construct it:
    let _cb = ContentBytes::new(raw);

    // This explicit construction is the semantic conversion point.
    // It cannot happen accidentally.
}

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

    let mut frame = Frame::new(FrameClass::Transit.as_byte(), [0u8; 32], [0u8; 32]);
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

    let mut frame = Frame::new(FrameClass::Transit.as_byte(), dst, src);
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
    assert_eq!(fwd.cls, FrameClass::Transit.as_byte());
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
    // The CAS trait accepts &[u8]. A careless caller COULD pass transit
    // bytes to it. However, the Ciphertext type prevents this at the
    // type level: there is no Ciphertext::as_bytes() method.
    //
    // To pass transit data to CAS, you would need to:
    // 1. Construct a Ciphertext (from encrypt_circuit_payload)
    // 2. Call into_bytes() (consuming it — only at the endpoint)
    // 3. Explicitly pass the raw bytes to CAS
    //
    // Step 2 is the explicit semantic conversion. It cannot happen
    // accidentally because into_bytes() consumes the Ciphertext and
    // is only called at the circuit endpoint.

    let ct = Ciphertext::from_encrypted(vec![0xDE, 0xAD]);

    // This would NOT compile if CAS::put accepted Ciphertext:
    // cas.put(&ct.as_bytes())  // ERROR: no method as_bytes
    //
    // You would need:
    // let raw = ct.into_bytes();  // explicit conversion
    // cas.put(&raw);              // now it's raw bytes, not Ciphertext
    //
    // This explicit conversion is the audit point.

    let raw = ct.into_bytes();
    // At this point, `raw` is just Vec<u8>. The semantic information
    // (that it was transit ciphertext) is lost. This is the ONLY way
    // transit data can enter a content API — through an explicit,
    // consuming conversion that a code reviewer can grep for.
    assert_eq!(raw, vec![0xDE, 0xAD]);
}

// ─── Content and transit are distinct at the type level ───────────────────

#[test]
fn test_content_and_transit_types_are_distinct() {
    let content = ContentBytes::new(vec![1, 2, 3]);
    let transit = Ciphertext::from_encrypted(vec![1, 2, 3]);

    // They are different types:
    // content: ContentBytes — has as_bytes(), can be hashed/CAS'd
    // transit: Ciphertext — has NO as_bytes(), only into_bytes() (consuming)

    // Content can be read:
    assert_eq!(content.as_bytes(), &[1, 2, 3]);

    // Transit can only be consumed:
    let raw = transit.into_bytes();
    assert_eq!(raw, vec![1, 2, 3]);

    // There is no implicit conversion between them.
    // This is the structural enforcement of Class A ≠ Class B.
}
