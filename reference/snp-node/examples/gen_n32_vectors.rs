//! N3.2 — Cross-Platform Conformance Vector Generator
//!
//! Generates frozen vectors for the N2.5-N3.1 protocol objects:
//! - evidence-model: EvidenceLevel classifications
//! - capability-model: NodeCapability string mappings (already in 16-capability-authority.json)
//! - gateway-service: GatewayPolicy/CapacityClaim/Measurement evidence levels
//! - contribution: ContributionProof + CivicPoint computation
//! - circuit-lifecycle: CircuitLifecycleState transitions
//!
//! These vectors are consumed by the cross-platform conformance runner
//! (Rust, Kotlin, Python, Swift) to verify byte-for-byte agreement.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, sha256, SecretKey};
use snp_node::node::capability::*;
use snp_node::node::evidence::*;
use snp_node::node::gateway_service::*;
use snp_node::node::gateway_service_manager::*;
use snp_node::node::contribution::*;
use snp_node::node::circuit_lifecycle::*;
use snp_node::node::identity::Capability;
use std::fs;

fn main() {
    let mut vectors: Vec<serde_json::Value> = Vec::new();

    // ── Suite: evidence-model ──
    // EvidenceLevel classifications (language-independent).
    let evidence_levels = vec![
        ("Authenticated", true, false),
        ("Observed", true, false),
        ("Reported", false, true),
        ("Derived", false, false),
        ("Inferred", false, true),
    ];
    for (name, is_routing, is_untrusted) in evidence_levels {
        vectors.push(serde_json::json!({
            "id": format!("evidence-level-{name}"),
            "suite": "evidence-model",
            "description": format!("EvidenceLevel::{name} classification"),
            "protocol_version": "3.2",
            "input": { "evidence_level": name },
            "expected": {
                "is_routing_evidence": is_routing,
                "is_untrusted": is_untrusted,
                "display_string": name.to_lowercase(),
            },
        }));
    }

    // ── Suite: gateway-service ──
    // GatewayPolicy evidence level.
    vectors.push(serde_json::json!({
        "id": "gateway-policy-evidence-level",
        "suite": "gateway-service",
        "description": "GatewayPolicy evidence level is Authenticated",
        "protocol_version": "3.2",
        "input": {},
        "expected": {
            "policy_evidence_level": "Authenticated",
            "capacity_evidence_level": "Reported",
            "measurement_evidence_level": "Observed",
        },
    }));

    // GatewayPolicy destination matching.
    let dest_tests = vec![
        ("wildcard-allows-all", vec![], "example.com", true),
        ("glob-suffix-match", vec!["*.example.com"], "www.example.com", true),
        ("glob-suffix-no-match", vec!["*.example.com"], "evil.com", false),
        ("exact-match", vec!["example.com"], "example.com", true),
        ("exact-no-match", vec!["example.com"], "evil.com", false),
    ];
    for (id, allowed, dest, expected) in dest_tests {
        let policy = GatewayPolicy {
            allowed_destinations: allowed.iter().map(|s| s.to_string()).collect(),
            allowed_protocols: vec![],
            charging_only: false,
            wifi_only: false,
            trusted_peers: vec![],
        };
        let result = policy.destination_allowed(dest);
        assert_eq!(result, expected, "destination_allowed test {id} failed");
        vectors.push(serde_json::json!({
            "id": format!("gateway-policy-dest-{id}"),
            "suite": "gateway-service",
            "description": format!("GatewayPolicy.destination_allowed(\"{dest}\") with allowed={allowed:?}"),
            "protocol_version": "3.2",
            "input": {
                "allowed_destinations": allowed,
                "destination": dest,
            },
            "expected": {
                "allowed": expected,
            },
        }));
    }

    // GatewayCapacityClaim quota check.
    vectors.push(serde_json::json!({
        "id": "gateway-capacity-claim-evidence",
        "suite": "gateway-service",
        "description": "GatewayCapacityClaim is a ReportedMetric (untrusted)",
        "protocol_version": "3.2",
        "input": {},
        "expected": {
            "evidence_level": "Reported",
            "is_untrusted": true,
        },
    }));

    // ── Suite: contribution ──
    // ContributionProof + CivicPoint computation.
    let gov_secret: SecretKey = sha256(b"n32-contribution-gov");
    let issuer_secret: SecretKey = sha256(b"n32-contribution-issuer");
    let issuer_pk = derive_public_key(&issuer_secret);
    let issuer_id = snp_crypto::domain_hash(b"SNP/0.1 node\0", &issuer_pk);
    let subject_pk = derive_public_key(&sha256(b"n32-contribution-subject"));
    let subject_id = snp_crypto::domain_hash(b"SNP/0.1 node\0", &subject_pk);
    let t0: u64 = 1_700_000_000;

    // Create a TransitReceipt for the contribution test.
    let gateway_sk = sha256(b"n32-gateway-sk");
    let gateway_pk = derive_public_key(&gateway_sk);
    let gateway_id = snp_crypto::derive_node_id(&gateway_pk);

    let mut receipt = TransitReceipt {
        req_id: [0x42; 16],
        client_node_id: subject_id,
        gateway_node_id: gateway_id,
        bytes_transferred: 1_048_576, // 1 MiB
        http_status: 200,
        object_id: sha256(&vec![0xAA; 1024]),
        served_at: t0,
        duration_ms: 100,
        gateway_signature: [0u8; 64],
    };
    receipt.sign(&gateway_sk);

    // Build a ContributionProof.
    let proof = ContributionProof::build(gateway_id, &gateway_sk, vec![receipt.clone()], t0).unwrap();
    let proof_verifies = proof.verify(&gateway_pk);
    let all_receipts_verify = proof.verify_all_receipts(&gateway_pk);

    vectors.push(serde_json::json!({
        "id": "contribution-proof-v1",
        "suite": "contribution",
        "description": "Frozen ContributionProof: 1 receipt, 1 MiB, 1 client",
        "protocol_version": "3.2",
        "input": {
            "contributor_node_id_hex": hex::encode(gateway_id),
            "receipts_count": 1,
            "total_bytes": 1_048_576,
            "distinct_clients": 1,
        },
        "expected": {
            "proof_verifies": proof_verifies,
            "all_receipts_verify": all_receipts_verify,
            "evidence_level": "Authenticated",
            "total_bytes": 1_048_576,
            "distinct_clients": 1,
        },
    }));

    // CivicPoint computation: 1 MiB, 1 client → 20 points (base_rate=100 × log₂(2) × 0.2).
    let mut ledger = CivicPointLedger::new(100.0);
    let credited = ledger.credit(&proof, &gateway_pk);
    vectors.push(serde_json::json!({
        "id": "civic-points-1mib-1client",
        "suite": "contribution",
        "description": "Civic Points: 1 MiB, 1 client → 20 points (100 × log₂(2) × 0.2)",
        "protocol_version": "3.2",
        "input": {
            "base_rate": 100.0,
            "bytes": 1_048_576,
            "distinct_clients": 1,
        },
        "expected": {
            "credited_points": credited,
            "formula": "base_rate × log₂(1 + MiB) × diversity_factor",
            "log2_factor": 1.0,
            "diversity_factor": 0.2,
            "raw_points": 20.0,
        },
    }));

    // ── Suite: circuit-lifecycle ──
    // CircuitLifecycleState transitions.
    let transitions = vec![
        ("setup-to-active", "Setup", "Active", true),
        ("active-to-rotating-to-active", "Active", "Active", true), // via rotation
        ("active-to-expired", "Active", "Expired", true),
        ("active-to-torndown", "Active", "TornDown", true),
        ("setup-to-expired", "Setup", "Expired", false), // invalid: must activate first
        ("torndown-to-active", "TornDown", "Active", false), // invalid: no re-activation
        ("expired-to-active", "Expired", "Active", false), // invalid: no re-activation
    ];
    for (id, from, to, valid) in transitions {
        vectors.push(serde_json::json!({
            "id": format!("circuit-transition-{id}"),
            "suite": "circuit-lifecycle",
            "description": format!("CircuitLifecycleState transition: {from} → {to}"),
            "protocol_version": "3.2",
            "input": {
                "from_state": from,
                "to_state": to,
            },
            "expected": {
                "valid_transition": valid,
            },
        }));
    }

    // ── Suite: capability-model (additional N2.5-T2 vectors) ──
    // NodeCapability → ProtocolCapability bridge.
    let bridge_tests: Vec<(&str, Option<u8>)> = vec![
        ("Client", None),
        ("Relay", Some(0u8)),        // → MeshRelay
        ("Gateway", Some(5u8)),      // → InternetGateway
        ("MeshRelay", Some(0u8)),
        ("InternetGateway", Some(5u8)),
        ("ContentSeed", Some(3u8)),
        ("Storage", Some(4u8)),
        ("Discovery", Some(1u8)),
        ("Sync", Some(2u8)),
        ("Compute", Some(6u8)),
        ("CryptoRelay", Some(0u8)),  // → MeshRelay
        ("CryptoGateway", Some(5u8)), // → InternetGateway
        ("PaymentRelay", None),
    ];
    for (variant, expected_byte) in bridge_tests {
        let cap = Capability::from_str(&variant.to_lowercase().replace('_', "-")).unwrap_or_else(|| {
            // Try with dashes already in the variant name.
            let dashed = variant.chars().enumerate().map(|(i, c)| {
                if i > 0 && c.is_uppercase() {
                    format!("-{c}")
                } else {
                    c.to_string()
                }
            }).collect::<String>().to_lowercase();
            Capability::from_str(&dashed).unwrap_or_else(|| panic!("cannot parse {variant}"))
        });
        let bridge = cap.to_protocol_capability();
        let bridge_byte = bridge.map(|p| p.to_byte());
        vectors.push(serde_json::json!({
            "id": format!("capability-bridge-{variant}"),
            "suite": "capability-model",
            "description": format!("Capability::{variant} → ProtocolCapability bridge"),
            "protocol_version": "3.2",
            "input": { "capability_variant": variant },
            "expected": {
                "protocol_capability_byte": bridge_byte,
                "has_protocol_counterpart": bridge.is_some(),
            },
        }));
    }

    // ── Write output ──
    let output = serde_json::json!({
        "protocol_version": "3.2",
        "frozen_at_commit": "d766b60",
        "generated_by": "snp-node gen_n32_vectors",
        "suites": {
            "evidence-model": "EvidenceLevel classifications (language-independent)",
            "gateway-service": "GatewayPolicy + CapacityClaim + Measurement evidence levels + destination matching",
            "contribution": "ContributionProof + CivicPoint computation (sub-linear + diversity-weighted)",
            "circuit-lifecycle": "CircuitLifecycleState transitions (valid + invalid)",
            "capability-model": "NodeCapability → ProtocolCapability bridge mappings",
        },
        "vectors": vectors,
    });

    let out_dir = "../public/conformance/vectors";
    fs::create_dir_all(out_dir).expect("create vectors dir");
    let json = serde_json::to_string_pretty(&output).unwrap();
    fs::write(format!("{out_dir}/17-cross-platform-n2x.json"), &json).unwrap();
    eprintln!("Wrote {out_dir}/17-cross-platform-n2x.json ({} vectors)", vectors.len());
}
