//! End-to-end: create a ledger, append, seal under Ed25519, verify publicly.
//!
//!     cargo run --example append_and_seal
//!
//! Writes into a temp directory and prints the paths so you can inspect
//! the artifacts afterwards.
use sovereign_ledger::anchor::Ed25519FileAnchor;
use sovereign_ledger::seal;
use sovereign_ledger::SovereignLedger;
use std::io::BufReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let ledger_path = dir.path().join("audit.jsonl");
    let anchor_path = dir.path().join("anchor.key");

    // An Ed25519 anchor makes seals *publicly* verifiable — the private
    // seed stays in this file, the ledger carries only the public key.
    let anchor = Ed25519FileAnchor::generate(&anchor_path)?;
    println!("anchor public key: {}", anchor.public_key_hex());

    let mut ledger = SovereignLedger::new(&ledger_path, Some(b"demo-seed"))?;
    for i in 0..5 {
        ledger.append("demo", &format!("{{\"event\": {i}}}"))?;
    }
    ledger.seal(&anchor)?;
    for i in 5..8 {
        ledger.append("demo", &format!("{{\"event\": {i}}}"))?;
    }
    ledger.sync()?;

    // Full keyed verification — every entry, including the unsealed tail.
    ledger.verify()?;
    println!("keyed verification: {} entries valid", ledger.len());

    // Public verification — no seeds, just the file bytes.
    let report = seal::verify_public(BufReader::new(std::fs::File::open(&ledger_path)?))?;
    println!(
        "public verification: {} sealed entries, {} unsealed (next seal covers them)",
        report.sealed_entries, report.unsealed_entries
    );

    println!("artifacts kept in {}", dir.path().display());
    std::mem::forget(dir); // keep the temp dir for inspection
    Ok(())
}
