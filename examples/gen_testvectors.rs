//! Regenerate the conformance test vectors in `testvectors/`.
//!
//!     cargo run --example gen_testvectors -- [output-dir]
//!
//! Emits known-good ledgers plus deliberately corrupted copies and an
//! `expected.json` describing the required verifier outcome for each.
//! Timestamps differ between runs — vectors are regenerated artifacts,
//! not stable byte fixtures; the *semantics* are what's pinned.
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use sovereign_ledger::anchor::Ed25519FileAnchor;
use sovereign_ledger::SovereignLedger;
use std::fs;
use std::path::Path;

const SEED0: &str = "vector-seed-0";
const SEED1: &str = "vector-seed-1";
/// Deterministic Ed25519 anchor seed (32 bytes, 0x00..0x1f) so the vector
/// anchor identity is stable across regenerations.
const ANCHOR_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// Local reimplementation of the crate's key schedule + MAC — needed to
// craft vectors whose *content* is wrong but whose crypto is valid
// (e.g. a seq gap: every MAC checks, so only a verifier that enforces
// canonical seq ordering rejects it).
fn base_key(seed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SOVEREIGN_LEDGER:");
    h.update(seed);
    h.finalize().into()
}
fn segment_key(base: &[u8; 32], s: u64) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(base).unwrap();
    m.update(b"sovereign-segment-v1");
    m.update(&s.to_le_bytes());
    m.finalize().into_bytes().into()
}
fn entry_mac(prev: &[u8; 32], e: &serde_json::Value, key: &[u8; 32]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(b"SL2");
    m.update(prev);
    m.update(&e["seq"].as_u64().unwrap().to_le_bytes());
    m.update(&e["ts"].as_u64().unwrap().to_le_bytes());
    let et = e["event_type"].as_str().unwrap();
    m.update(&(et.len() as u32).to_le_bytes());
    m.update(et.as_bytes());
    let body = e["body"].as_str().unwrap();
    m.update(&(body.len() as u64).to_le_bytes());
    m.update(body.as_bytes());
    m.finalize().into_bytes().into()
}

fn tamper(path: &Path, out_name: &str, dir: &Path, f: impl Fn(&mut Vec<String>)) {
    let text = fs::read_to_string(path).unwrap();
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    f(&mut lines);
    fs::write(dir.join(out_name), lines.join("\n") + "\n").unwrap();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "testvectors".to_string());
    let dir = Path::new(&dir);
    fs::create_dir_all(dir)?;

    // Regeneration must be idempotent: opening an existing ledger
    // *appends* to it (and rotated ledgers would demand their full
    // keyring), so always start from a clean file.
    let fresh = |name: &str| -> std::path::PathBuf {
        let p = dir.join(name);
        let _ = fs::remove_file(&p);
        p
    };

    // --- valid-basic.jsonl: keyed chain, no seals ----------------------
    {
        let p = fresh("valid-basic.jsonl");
        let mut l = SovereignLedger::open_with_seeds(&p, &[SEED0.as_bytes()])?;
        for i in 0..6 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.sync()?;
    }

    // --- valid-rotated.jsonl: key rotation mid-chain -------------------
    {
        let p = fresh("valid-rotated.jsonl");
        let mut l = SovereignLedger::open_with_seeds(&p, &[SEED0.as_bytes()])?;
        for i in 0..3 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.rotate_key(SEED1.as_bytes())?;
        for i in 3..6 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.sync()?;
    }

    // --- valid-sealed.jsonl: two sealed segments + unsealed tail -------
    let anchor_key_path = dir.join("anchor-seed.bin");
    fs::write(&anchor_key_path, hex::decode(ANCHOR_SEED_HEX)?)?;
    let anchor = Ed25519FileAnchor::from_file(&anchor_key_path)?;
    let anchor_pub = anchor.public_key_hex();
    {
        let p = fresh("valid-sealed.jsonl");
        let mut l = SovereignLedger::open_with_seeds(&p, &[SEED0.as_bytes()])?;
        for i in 0..4 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.seal(&anchor)?;
        for i in 4..8 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.seal(&anchor)?;
        for i in 8..10 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.sync()?;
    }

    // --- valid-rotated-sealed.jsonl: mid-segment key rotation ----------
    // Exercises a multi-epoch `revealed` map in the seal record.
    {
        let p = fresh("valid-rotated-sealed.jsonl");
        let mut l = SovereignLedger::open_with_seeds(&p, &[SEED0.as_bytes()])?;
        for i in 0..3 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.rotate_key(SEED1.as_bytes())?;
        for i in 3..6 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.seal(&anchor)?;
        for i in 6..8 {
            l.append("audit", &format!("{{\"n\": {i}}}"))?;
        }
        l.sync()?;
    }

    // --- corrupted copies ----------------------------------------------
    let sealed = dir.join("valid-sealed.jsonl");

    // Edit a mid-ledger entry body: entry MAC no longer matches.
    tamper(&sealed, "broken-tampered-body.jsonl", dir, |lines| {
        let mut e: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        e["body"] = json!("{\"n\": 999}");
        lines[1] = serde_json::to_string(&e).unwrap();
    });

    // Swap two adjacent entries: prev_hash linkage breaks.
    tamper(&sealed, "broken-swapped-lines.jsonl", dir, |lines| {
        lines.swap(1, 2);
    });

    // Cut the last line mid-JSON: parse failure.
    tamper(&sealed, "broken-truncated.jsonl", dir, |lines| {
        let last = lines.pop().unwrap();
        lines.push(last[..last.len() / 2].to_string());
    });

    // Edit the first seal's body inside the sealed region: the seal entry
    // itself fails authentication when its own segment is verified.
    tamper(&sealed, "broken-seal-body.jsonl", dir, |lines| {
        let idx = lines
            .iter()
            .position(|l| l.contains("sovereign:seal"))
            .expect("seal line");
        let mut e: serde_json::Value = serde_json::from_str(&lines[idx]).unwrap();
        let mut body: serde_json::Value =
            serde_json::from_str(e["body"].as_str().unwrap()).unwrap();
        body["tip_hash"] = json!("00");
        e["body"] = json!(body.to_string());
        lines[idx] = serde_json::to_string(&e).unwrap();
    });

    // Inject an unauthenticated field into an entry: the field set is
    // canonical, so a conforming parser rejects the line outright even
    // though every MAC still checks.
    tamper(&sealed, "broken-extra-field.jsonl", dir, |lines| {
        let mut e: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        e["comment"] = json!("unauthenticated");
        lines[1] = serde_json::to_string(&e).unwrap();
    });

    // Crafted ledger with a seq gap but *valid* MACs throughout: only a
    // verifier that enforces canonical sequence ordering rejects it.
    {
        let base = base_key(SEED0.as_bytes());
        let key = segment_key(&base, 0);
        let mut prev = [0u8; 32];
        let mut out = Vec::new();
        for (i, seq) in [1u64, 2, 3, 10].iter().enumerate() {
            let mut e = json!({
                "v": 3, "seq": seq, "ts": 1_750_000_000u64 + i as u64,
                "event_type": "audit", "body": "{\"forged\": true}",
                "epoch": 0, "prev_hash": hex::encode(prev), "hash": "",
            });
            let h = entry_mac(&prev, &e, &key);
            e["hash"] = json!(hex::encode(h));
            prev = h;
            out.push(serde_json::to_string(&e).unwrap());
        }
        fs::write(dir.join("broken-seq-gap.jsonl"), out.join("\n") + "\n").unwrap();
    }

    let expected = json!({
        "version": 1,
        "seeds": [SEED0, SEED1],
        "anchor_public_key": anchor_pub,
        "vectors": [
            {"file": "valid-basic.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "ok"},
             "public": {"expect": "no_seals"}},
            {"file": "valid-rotated.jsonl",
             "keyed": {"seeds": [SEED0, SEED1], "expect": "ok"},
             "public": {"expect": "no_seals"}},
            {"file": "valid-sealed.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "ok"},
             "public": {"expect": "ok", "segments": 2}},
            {"file": "valid-rotated-sealed.jsonl",
             "keyed": {"seeds": [SEED0, SEED1], "expect": "ok"},
             "public": {"expect": "ok", "segments": 1}},
            {"file": "broken-tampered-body.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "broken hash chain"},
             "public": {"expect": "error"}},
            {"file": "broken-swapped-lines.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "broken hash chain"},
             "public": {"expect": "error"}},
            {"file": "broken-truncated.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "invalid ledger line"},
             "public": {"expect": "error"}},
            {"file": "broken-seal-body.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "broken hash chain"},
             "public": {"expect": "tip_hash does not match"}},
            {"file": "broken-extra-field.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "invalid ledger line"},
             "public": {"expect": "invalid ledger line"}},
            {"file": "broken-seq-gap.jsonl",
             "keyed": {"seeds": [SEED0], "expect": "broken hash chain"},
             "public": {"expect": "broken hash chain"}},
        ]
    });
    fs::write(
        dir.join("expected.json"),
        serde_json::to_string_pretty(&expected)? + "\n",
    )?;
    println!("vectors written to {}", dir.display());
    Ok(())
}
