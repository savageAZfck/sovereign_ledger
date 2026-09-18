//! Public verification — no key material, sealed segments only.
//!
//!     cargo run --example verify_public -- sealed.jsonl
//!
//! This is the "don't trust, verify" path: entry MACs are recomputed
//! under keys the seals themselves reveal, Merkle roots and chain tips
//! are checked, and anchor signatures are verified against the public
//! keys embedded in the ledger. Works on bytes — no secrets needed.
use sovereign_ledger::seal;
use std::io::BufReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: verify_public <ledger.jsonl>");
        std::process::exit(2);
    });

    let file = std::fs::File::open(&path)?;
    let report = seal::verify_public(BufReader::new(file))?;

    if report.segments == 0 {
        eprintln!("no seal records found — nothing is publicly verifiable yet");
        std::process::exit(1);
    }
    println!(
        "public verification passed: {} sealed entries in {} segments",
        report.sealed_entries, report.segments
    );
    if report.unsealed_entries > 0 {
        println!(
            "note: {} trailing entries are linkage-checked but unsealed",
            report.unsealed_entries
        );
    }
    println!(
        "anchor: {} ({})",
        report.scheme.as_deref().unwrap_or("unknown"),
        report.public_key.as_deref().unwrap_or("?")
    );
    Ok(())
}
