use sovereign_ledger::SovereignLedger;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

fn temp_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from("/tmp");
    p.push(format!("sovereign_stress_{}_{}", std::process::id(), name));
    p
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_file(p);
    let _ = fs::remove_file(format!("{}.lock", p.display()));
}

fn write_lines(path: &PathBuf, lines: &[String]) {
    let mut f = fs::File::create(path).unwrap();
    for l in lines {
        writeln!(f, "{l}").unwrap();
    }
}

fn read_lines(path: &PathBuf) -> Vec<String> {
    BufReader::new(fs::File::open(path).unwrap())
        .lines()
        .map(|l| l.unwrap())
        .collect()
}

fn make_ledger(path: &PathBuf, n: u64) {
    let mut ledger = SovereignLedger::new(path, Some(b"stress")).unwrap();
    for i in 0..n {
        ledger.append("event", &format!("{i}")).unwrap();
    }
    ledger.sync().unwrap();
}

#[test]
fn stress_100k_appends_and_verify() {
    let path = temp_path("100k.jsonl");
    cleanup(&path);

    let mut ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    let start = Instant::now();
    for i in 0..100_000u64 {
        ledger.append("query", &format!("prompt {i}")).unwrap();
    }
    let append_elapsed = start.elapsed();

    let start = Instant::now();
    ledger.verify().unwrap();
    let verify_elapsed = start.elapsed();

    let dump = ledger.dump().unwrap();
    assert_eq!(dump.len(), 100_000);
    assert_eq!(dump.last().unwrap().seq, 100_000);

    println!(
        "100k appends: {:?} ({:.0} appends/sec); verify: {:?}",
        append_elapsed,
        100_000.0 / append_elapsed.as_secs_f64(),
        verify_elapsed
    );

    cleanup(&path);
}

#[test]
fn concurrent_process_appends_serialize() {
    let path = temp_path("concurrent.jsonl");
    cleanup(&path);
    let bin = env!("CARGO_BIN_EXE_sovereign_ledger");

    // Spawn 16 processes appending simultaneously. The blocking flock must
    // serialize them — every append should succeed and the chain must verify.
    let children: Vec<_> = (0..16)
        .map(|i| {
            Command::new(bin)
                .arg(&path)
                .arg("append")
                .arg("worker")
                .arg(format!("worker-{i}"))
                .env("SOVEREIGN_LEDGER_KEY", "concurrent-seed")
                .spawn()
                .unwrap()
        })
        .collect();

    for (i, child) in children.into_iter().enumerate() {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "worker {i} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let ledger = SovereignLedger::new(&path, Some(b"concurrent-seed")).unwrap();
    assert!(!ledger.is_compromised());
    ledger.verify().unwrap();
    let dump = ledger.dump().unwrap();
    assert_eq!(dump.len(), 16);
    // Sequences must be unique and dense — no two processes claimed the same seq.
    let seqs: std::collections::BTreeSet<u64> = dump.iter().map(|e| e.seq).collect();
    assert_eq!(seqs.len(), 16);

    cleanup(&path);
}

#[test]
fn lock_blocks_until_released() {
    let path = temp_path("lockwait.jsonl");
    cleanup(&path);
    let bin = env!("CARGO_BIN_EXE_sovereign_ledger");

    // Hold the lock in this process.
    let mut parent = SovereignLedger::new(&path, Some(b"lock-seed")).unwrap();
    parent.append("held", "first").unwrap();

    // Child append must block on the lock, then succeed once we drop the handle.
    let child = Command::new(bin)
        .arg(&path)
        .arg("append")
        .arg("child")
        .arg("second")
        .env("SOVEREIGN_LEDGER_KEY", "lock-seed")
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500));
    // The child should still be waiting on the lock; the file has 1 entry.
    assert_eq!(read_lines(&path).len(), 1);
    drop(parent);

    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let ledger = SovereignLedger::new(&path, Some(b"lock-seed")).unwrap();
    ledger.verify().unwrap();
    assert_eq!(ledger.dump().unwrap().len(), 2);
    cleanup(&path);
}

#[test]
fn truncated_final_line_fails_closed() {
    let path = temp_path("truncated.jsonl");
    cleanup(&path);
    make_ledger(&path, 10);

    // Simulate a crash mid-write: chop the last line in half.
    let len = fs::metadata(&path).unwrap().len();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len - 20)
        .unwrap();

    assert!(SovereignLedger::new(&path, Some(b"stress")).is_err());
    cleanup(&path);
}

#[test]
fn tamper_variants_all_detected() {
    let base = temp_path("tamper_base.jsonl");
    cleanup(&base);
    make_ledger(&base, 10);
    let lines = read_lines(&base);

    // (a) delete a middle line
    let p = temp_path("tamper_delete.jsonl");
    let mut v = lines.clone();
    v.remove(5);
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    // (b) reorder two lines
    let p = temp_path("tamper_reorder.jsonl");
    let mut v = lines.clone();
    v.swap(4, 5);
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    // (c) duplicate a line
    let p = temp_path("tamper_dup.jsonl");
    let mut v = lines.clone();
    v.insert(5, v[5].clone());
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    // (d) edit the body of a middle line (valid JSON, wrong hash)
    let p = temp_path("tamper_body.jsonl");
    let mut v = lines.clone();
    let mut e: serde_json::Value = serde_json::from_str(&v[5]).unwrap();
    e["body"] = serde_json::Value::String("TAMPERED".into());
    v[5] = serde_json::to_string(&e).unwrap();
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    // (e) edit the stored hash of a middle line
    let p = temp_path("tamper_hash.jsonl");
    let mut v = lines.clone();
    let mut e: serde_json::Value = serde_json::from_str(&v[5]).unwrap();
    e["hash"] = serde_json::Value::String("0".repeat(64));
    v[5] = serde_json::to_string(&e).unwrap();
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    // (f) edit prev_hash linkage of a middle line
    let p = temp_path("tamper_prev.jsonl");
    let mut v = lines.clone();
    let mut e: serde_json::Value = serde_json::from_str(&v[5]).unwrap();
    e["prev_hash"] = serde_json::Value::String("f".repeat(64));
    v[5] = serde_json::to_string(&e).unwrap();
    write_lines(&p, &v);
    let l = SovereignLedger::new(&p, Some(b"stress")).unwrap();
    assert!(l.is_compromised() || l.verify().is_err());
    cleanup(&p);

    cleanup(&base);
}

#[test]
fn tamper_detection() {
    let path = temp_path("tamper.jsonl");
    cleanup(&path);
    make_ledger(&path, 100);

    let mut tampered = read_lines(&path);
    let mut parsed: serde_json::Value = serde_json::from_str(&tampered[50]).unwrap();
    parsed["body"] = serde_json::Value::String("TAMPERED".to_string());
    tampered[50] = serde_json::to_string(&parsed).unwrap();
    write_lines(&path, &tampered);

    let ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    assert!(ledger.is_compromised());
    assert!(ledger.verify().is_err());
    cleanup(&path);
}

#[test]
fn readonly_enforcement() {
    let path = temp_path("ro.jsonl");
    cleanup(&path);

    let mut ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    ledger.append("a", "1").unwrap();
    ledger.mark_readonly();
    assert!(ledger.is_readonly());
    assert!(ledger.append("b", "2").is_err());

    cleanup(&path);
}

#[test]
fn key_mismatch() {
    let path = temp_path("key.jsonl");
    cleanup(&path);

    {
        let mut ledger = SovereignLedger::new(&path, Some(b"seed-one")).unwrap();
        ledger.append("event", "data").unwrap();
    }

    let ledger = SovereignLedger::new(&path, Some(b"seed-two")).unwrap();
    assert!(ledger.is_compromised());
    assert!(ledger.verify().is_err());

    cleanup(&path);
}

#[test]
fn large_bodies() {
    let path = temp_path("large.jsonl");
    cleanup(&path);

    let mut ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    let big = "x".repeat(500_000);
    let start = Instant::now();
    ledger.append("big", &big).unwrap();
    ledger.append("big", &big).unwrap();
    ledger.append("big", &big).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(ledger.dump().unwrap().len(), 3);
    ledger.verify().unwrap();

    println!("3 x 500KB bodies: {elapsed:?}");

    cleanup(&path);
}

#[test]
fn malformed_line_is_rejected() {
    let path = temp_path("bad.jsonl");
    cleanup(&path);
    make_ledger(&path, 1);

    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(f, "this is not json").unwrap();
    drop(f);

    assert!(SovereignLedger::new(&path, Some(b"stress")).is_err());
    cleanup(&path);
}

#[test]
fn reopen_appends() {
    let path = temp_path("reopen.jsonl");
    cleanup(&path);

    {
        let mut ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
        for i in 0..10 {
            ledger.append("batch1", &format!("{i}")).unwrap();
        }
    }
    {
        let mut ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
        for i in 0..10 {
            ledger.append("batch2", &format!("{i}")).unwrap();
        }
        assert_eq!(ledger.dump().unwrap().len(), 20);
        ledger.verify().unwrap();
    }

    cleanup(&path);
}

#[test]
fn empty_and_single_entry() {
    let path = temp_path("empty.jsonl");
    cleanup(&path);

    // Empty file: trivially valid.
    let ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    ledger.verify().unwrap();
    assert_eq!(ledger.dump().unwrap().len(), 0);
    drop(ledger);

    // Single entry verifies and chains to the zero genesis.
    make_ledger(&path, 1);
    let ledger = SovereignLedger::new(&path, Some(b"stress")).unwrap();
    ledger.verify().unwrap();
    let dump = ledger.dump().unwrap();
    assert_eq!(dump.len(), 1);
    assert_eq!(dump[0].prev_hash, "0".repeat(64));
    cleanup(&path);
}
