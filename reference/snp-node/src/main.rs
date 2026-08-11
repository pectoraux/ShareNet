//! snp-node — the ShareNet reference daemon
//!
//! Ties together all SNP crates into a running node. Supports:
//! - `snp-node run` — start the node daemon
//! - `snp-node conformance` — run the conformance suite
//! - `snp-node keygen` — generate a new node identity
//! - `snp-node discover` — scan for peers
//!
//! SKELETON — not yet implemented. Use the TypeScript reference at
//! `/src/lib/snp/` for the working implementation (ADR-0001), and the
//! conformance dashboard at `/src/app/page.tsx` (served at
//! http://localhost:3000) for vector-level visibility until this daemon is
//! complete.

fn main() {
    println!("snp-node — ShareNet reference daemon");
    println!("SKELETON — not yet implemented");
    println!();
    println!("Use the TypeScript reference at /src/lib/snp/ for now.");
    println!("Conformance dashboard: http://localhost:3000");
    println!();
    println!("Subcommands (skeleton — see reference/snp-node/src/lib.rs):");
    println!("  snp-node run           Start the daemon");
    println!("  snp-node conformance   Run the conformance suite");
    println!("  snp-node keygen        Generate a new node identity");
    println!("  snp-node discover      Scan for peers");
    println!();
    println!("Build:    cargo build --workspace");
    println!("Test:     cargo test --workspace");
    println!("Vectors:  /public/conformance/vectors/*.json");
}
