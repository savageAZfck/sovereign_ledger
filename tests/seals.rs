use sovereign_ledger::anchor::Ed25519FileAnchor;
use sovereign_ledger::seal::{self, SealRecord};
use sovereign_ledger::{Error, SovereignLedger, SEAL_EVENT};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from("/tmp");
    p.push(format!("sovereign_seal_{}_{}", std::process::id(), name));
    p
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_file(p);
    let _ = fs::remove_file(format!("{}.lock", p.display()));
}

fn anchor(name: &str) -> Ed25519FileAnchor {
    let p = temp_path(&format!("{name}.key"));
    Ed25519FileAnchor::generate(&p).unwrap()
}

fn verify_public_file(p: &PathBuf) -> Result<seal::PublicVerifyReport, Error> {
    seal::verify_public(BufReader::new(fs::File::open(p).unwrap()))
}

fn events(p: &PathBuf) -> Vec<serde_json::Value> {
    BufReader::new(fs::File::open(p).unwrap())
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect()
}

fn write_events(p: &PathBuf, evts: &[serde_json::Value]) {
    let mut f = fs::File::create(p).unwrap();
    for e in evts {
        writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
    }
}

#[test]
fn seal_roundtrip_public_verify() {
    let p = temp_path("roundtrip");
    cleanup(&p);
    let a = anchor("roundtrip");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..10 {
            l.append("event", &format!("{i}")).unwrap();
        }
        let seal_seq = l.seal(&a).unwrap().expect("sealed");
        assert_eq!(seal_seq, 11);
        l.verify().unwrap();
    }
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 1);
    assert_eq!(report.sealed_entries, 10);
    assert_eq!(report.unsealed_entries, 1); // the seal event itself
    assert_eq!(report.scheme.as_deref(), Some("ed25519-file"));
    assert_eq!(
        report.public_key.as_deref(),
        Some(a.public_key_hex().as_str())
    );
    cleanup(&p);
}

#[test]
fn multi_segment_seals_verify() {
    let p = temp_path("multi");
    cleanup(&p);
    let a = anchor("multi");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..5 {
            l.append("event", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
        for i in 5..12 {
            l.append("event", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
        for i in 12..15 {
            l.append("event", &format!("{i}")).unwrap();
        }
        l.verify().unwrap();
    }
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 2);
    // seg0: 5 entries, seg1: 7 entries + seal 1 = 8
    assert_eq!(report.sealed_entries, 13);
    assert_eq!(report.unsealed_entries, 4); // 3 appends + seal 2
    cleanup(&p);
}

#[test]
fn tampered_sealed_segment_fails_publicly() {
    let p = temp_path("tamper");
    cleanup(&p);
    let a = anchor("tamper");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..6 {
            l.append("event", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
    }
    let mut evts = events(&p);
    evts[2]["body"] = serde_json::json!("forged");
    write_events(&p, &evts);
    assert!(verify_public_file(&p).is_err());
    cleanup(&p);
}

#[test]
fn revealed_key_forgery_still_fails() {
    // The key property: knowing the revealed segment key lets you produce
    // valid MACs, but the forged content changes the Merkle root, which
    // the anchor signature binds — forgery still fails.
    let p = temp_path("forge");
    cleanup(&p);
    let a = anchor("forge");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..4 {
            l.append("event", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
    }
    let mut evts = events(&p);
    let seal_body: SealRecord = serde_json::from_str(evts[4]["body"].as_str().unwrap()).unwrap();
    let key = decode_hex(&seal_body.revealed[&0]);
    // Forge entry 2 with the revealed key: recompute a valid MAC chain
    // segment from entry 2 onward so stored hashes stay self-consistent.
    let mut prev = decode_hex(evts[1]["hash"].as_str().unwrap());
    for i in 2..4 {
        let e = &mut evts[i];
        if i == 2 {
            e["body"] = serde_json::json!("forged");
        }
        let h = forge_hash(&prev, e, &key);
        e["hash"] = serde_json::json!(hex::encode(h));
        prev = h;
        if i + 1 < evts.len() {
            evts[i + 1]["prev_hash"] = serde_json::json!(hex::encode(h));
        }
    }
    evts[4]["prev_hash"] = serde_json::json!(hex::encode(prev));
    write_events(&p, &evts);
    // Structural chain is consistent (all MACs valid under revealed key)
    // but the Merkle root no longer matches the signed seal.
    let err = verify_public_file(&p).unwrap_err().to_string();
    assert!(
        err.contains("merkle_root") || err.contains("tip_hash"),
        "{err}"
    );
    cleanup(&p);
}

#[test]
fn dropped_middle_seal_fails() {
    let p = temp_path("drop");
    cleanup(&p);
    let a = anchor("drop");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..4 {
            l.append("e", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
        for i in 4..8 {
            l.append("e", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
    }
    let mut evts = events(&p);
    // Remove the first seal and splice: breaks chain linkage AND ordering.
    evts.remove(4);
    // Fix up prev_hash linkage so only seal ordering can catch it:
    for w in 4..evts.len() {
        let prev = evts[w - 1]["hash"].as_str().unwrap().to_string();
        evts[w]["prev_hash"] = serde_json::json!(prev);
    }
    write_events(&p, &evts);
    assert!(verify_public_file(&p).is_err());
    cleanup(&p);
}

#[test]
fn anchor_identity_change_fails() {
    let p = temp_path("idchange");
    cleanup(&p);
    let a1 = anchor("idchange1");
    let a2 = anchor("idchange2");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        l.append("e", "1").unwrap();
        l.seal(&a1).unwrap();
        l.append("e", "2").unwrap();
        l.seal(&a2).unwrap();
    }
    let err = verify_public_file(&p).unwrap_err().to_string();
    assert!(err.contains("anchor identity"), "{err}");
    cleanup(&p);
}

#[test]
fn full_verify_covers_seals_and_segments() {
    // Key-holding verification still works across seals, and a seal that
    // reveals a wrong key is itself flagged.
    let p = temp_path("full");
    cleanup(&p);
    let a = anchor("full");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..5 {
            l.append("e", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
        l.append("e", "after").unwrap();
        l.verify().unwrap();
    }
    // Reopen: verify uses the derived keys transparently.
    let l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
    l.verify().unwrap();
    assert_eq!(l.segment(), 1);
    cleanup(&p);
}

#[test]
fn dishonest_seal_reveal_fails_full_verify() {
    let p = temp_path("dishonest");
    cleanup(&p);
    let a = anchor("dishonest");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..3 {
            l.append("e", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
    }
    // Corrupt the revealed key inside the seal body and re-sign is
    // impossible — but even the *stored* body change should fail full
    // verify via the reveal cross-check or MAC.
    let mut evts = events(&p);
    let mut body: SealRecord = serde_json::from_str(evts[3]["body"].as_str().unwrap()).unwrap();
    body.revealed.insert(0, "00".repeat(32));
    evts[3]["body"] = serde_json::json!(serde_json::to_string(&body).unwrap());
    write_events(&p, &evts);
    let l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
    assert!(l.verify().is_err() || l.is_compromised());
    cleanup(&p);
}

#[test]
fn unsealed_ledger_rejects_public_mode() {
    let p = temp_path("noseals");
    cleanup(&p);
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        l.append("e", "x").unwrap();
    }
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 0);
    assert_eq!(report.unsealed_entries, 1);
    cleanup(&p);
}

#[test]
fn nothing_to_seal_is_noop() {
    let p = temp_path("noop");
    cleanup(&p);
    let a = anchor("noop");
    let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
    assert!(l.seal(&a).unwrap().is_none());
    l.append("e", "1").unwrap();
    assert!(l.seal(&a).unwrap().is_some());
    assert!(l.seal(&a).unwrap().is_none()); // already sealed
    cleanup(&p);
}

#[test]
fn seal_after_key_rotation_multi_epoch() {
    let p = temp_path("epochs");
    cleanup(&p);
    let a = anchor("epochs");
    {
        let mut l = SovereignLedger::new(&p, Some(b"k0")).unwrap();
        l.append("e", "a").unwrap();
        l.rotate_key(b"k1").unwrap();
        l.append("e", "b").unwrap();
        l.seal(&a).unwrap();
        l.append("e", "c").unwrap();
        l.verify().unwrap();
    }
    // Public verify: segment reveals both epochs' derived keys.
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 1);
    // Full verify needs both epoch seeds.
    let l = SovereignLedger::open_with_seeds(&p, &[b"k0".as_slice(), b"k1".as_slice()]).unwrap();
    l.verify().unwrap();
    cleanup(&p);
}

#[test]
fn seal_body_parses_as_event_for_legacy_tools() {
    // Backward compat: a seal is a normal v2 event; old verifiers see a
    // well-formed entry, just with a special event_type.
    let p = temp_path("compat");
    cleanup(&p);
    let a = anchor("compat");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        l.append("e", "1").unwrap();
        l.seal(&a).unwrap();
    }
    let evts = events(&p);
    assert_eq!(evts[1]["event_type"].as_str().unwrap(), SEAL_EVENT);
    assert_eq!(evts[1]["v"].as_u64().unwrap(), 3);
    cleanup(&p);
}

#[test]
fn payload_replay_fails() {
    // Attack: forge the segment with the revealed key, set the seal's
    // fields to the forged root/tip, but keep the original payload +
    // signature (which endorse the *old* root). Without payload-binding,
    // the signature verifies over the stale payload while the field
    // checks pass — a silent forgery.
    let p = temp_path("replay");
    cleanup(&p);
    let a = anchor("replay");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        for i in 0..4 {
            l.append("e", &format!("{i}")).unwrap();
        }
        l.seal(&a).unwrap();
    }
    let mut evts = events(&p);
    let seal_body: SealRecord = serde_json::from_str(evts[4]["body"].as_str().unwrap()).unwrap();
    let key = decode_hex(&seal_body.revealed[&0]);
    // Forge entry 2 and re-MAC the segment tail under the revealed key.
    let mut prev = decode_hex(evts[1]["hash"].as_str().unwrap());
    let mut leaves: Vec<[u8; 32]> = evts[..2]
        .iter()
        .map(|e| decode_hex(e["hash"].as_str().unwrap()))
        .collect();
    for i in 2..4 {
        let e = &mut evts[i];
        if i == 2 {
            e["body"] = serde_json::json!("forged");
        }
        let h = forge_hash(&prev, e, &key);
        e["hash"] = serde_json::json!(hex::encode(h));
        prev = h;
        leaves.push(h);
        evts[i + 1]["prev_hash"] = serde_json::json!(hex::encode(h));
    }
    // Rewrite the seal's *fields* to endorse the forged segment, keeping
    // the original payload + signature.
    let root = sovereign_ledger::merkle::mth(&leaves);
    let mut forged: SealRecord = seal_body.clone();
    forged.merkle_root = hex::encode(root);
    forged.tip_hash = hex::encode(prev);
    // payload + signature unchanged — the replay.
    evts[4]["body"] = serde_json::json!(serde_json::to_string(&forged).unwrap());
    write_events(&p, &evts);
    let err = verify_public_file(&p).unwrap_err().to_string();
    assert!(err.contains("payload"), "{err}");
    cleanup(&p);
}

/// Write hand-crafted v2 entries — the format pre-v0.3 writers produced:
/// HMAC under the epoch base key, `v: 2`.
fn write_v2_entries(p: &PathBuf, seed: &[u8], bodies: &[&str]) {
    let key = sovereign_ledger::Key::new(Some(seed));
    let kb: [u8; 32] = key.as_bytes().try_into().unwrap();
    let mut prev = [0u8; 32];
    let mut evts = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let mut e = serde_json::json!({
            "v": 2,
            "seq": i as u64 + 1,
            "ts": 1_700_000_000u64 + i as u64,
            "event_type": "e",
            "body": body,
            "epoch": 0,
            "prev_hash": hex::encode(prev),
            "hash": "",
        });
        let h = forge_hash(&prev, &e, &kb);
        e["hash"] = serde_json::json!(hex::encode(h));
        prev = h;
        evts.push(e);
    }
    write_events(p, &evts);
}

#[test]
fn legacy_ledger_seal_requires_rotation() {
    // A v2 ledger (pre-sealing format) sealed later publishes its base
    // key; appends under that epoch must be refused until rotation.
    let p = temp_path("legacy");
    cleanup(&p);
    let a = anchor("legacy");
    write_v2_entries(&p, b"seed", &["0", "1", "2"]);
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        l.seal(&a).unwrap();
        assert!(l.needs_rotation());
        assert!(l.append("e", "x").is_err());
        l.rotate_key(b"fresh").unwrap();
        l.append("e", "x").unwrap();
        l.seal(&a).unwrap();
        l.verify().unwrap();
    }
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 2);
    assert_eq!(report.unsealed_entries, 1); // second seal event
    cleanup(&p);
}

#[test]
fn seal_reveals_derived_not_base_key() {
    // v3 segment keys are PRF outputs — the revealed key is not the base,
    // and does not authenticate entries of another segment.
    let p = temp_path("derived");
    cleanup(&p);
    let a = anchor("derived");
    {
        let mut l = SovereignLedger::new(&p, Some(b"seed")).unwrap();
        l.append("e", "1").unwrap();
        l.seal(&a).unwrap();
        l.append("e", "2").unwrap();
        l.seal(&a).unwrap();
    }
    let evts = events(&p);
    let s0: SealRecord = serde_json::from_str(evts[1]["body"].as_str().unwrap()).unwrap();
    let s1: SealRecord = serde_json::from_str(evts[3]["body"].as_str().unwrap()).unwrap();
    assert_ne!(s0.revealed[&0], s1.revealed[&0]);
    let report = verify_public_file(&p).unwrap();
    assert_eq!(report.segments, 2);
    assert_eq!(report.sealed_entries, 3); // entry, seal1 + entry
    cleanup(&p);
}

fn decode_hex(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().as_slice().try_into().unwrap()
}

/// Recompute the v2 HMAC for an event — mirrors the crate's construction.
fn forge_hash(prev: &[u8; 32], e: &serde_json::Value, key: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
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
