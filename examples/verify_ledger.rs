//! Full keyed verification of a ledger file.
//!
//!     cargo run --example verify_ledger -- audit.jsonl seed0 [seed1 ...]
//!
//! Keyed verification authenticates every entry — including the unsealed
//! tail — and fails closed on the first bad line.
use sovereign_ledger::SovereignLedger;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: verify_ledger <ledger.jsonl> [seed ...]");
        std::process::exit(2);
    });
    let seeds: Vec<String> = args.collect();
    let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_bytes()).collect();

    let ledger = SovereignLedger::open_with_seeds(&path, &refs)?;
    ledger.verify()?;

    println!(
        "chain valid: {} entries, tip {}",
        ledger.len(),
        hex::encode(ledger.last_hash())
    );
    Ok(())
}
