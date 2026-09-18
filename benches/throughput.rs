//! Throughput benchmarks: append, keyed verify, and public verify.
//!
//! Run with `cargo bench`. Numbers are printed as receipts — post them
//! with the hardware they were measured on, not as absolute claims.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sovereign_ledger::anchor::Ed25519FileAnchor;
use sovereign_ledger::SovereignLedger;
use std::io::BufReader;
use tempfile::TempDir;

fn ledger_with_entries(dir: &TempDir, name: &str, n: usize, seal_every: usize) -> String {
    let path = dir.path().join(name);
    let path_str = path.to_string_lossy().to_string();
    let anchor_dir = dir.path().join(format!("{name}.anchor"));
    let anchor = Ed25519FileAnchor::generate(&anchor_dir).unwrap();
    {
        let mut l = SovereignLedger::new(&path, Some(b"bench-seed")).unwrap();
        for i in 0..n {
            l.append("bench", &format!("{{\"i\": {i}}}")).unwrap();
            if seal_every > 0 && (i + 1) % seal_every == 0 {
                l.seal(&anchor).unwrap();
            }
        }
        l.sync().unwrap();
    }
    path_str
}

fn bench_append(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("append.jsonl");
    let mut l = SovereignLedger::new(&path, Some(b"bench-seed")).unwrap();
    c.bench_function("append", |b| {
        b.iter(|| l.append("bench", "{}").unwrap());
    });
}

fn bench_verify(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    for n in [1_000usize, 10_000] {
        let path = ledger_with_entries(&dir, &format!("verify_{n}.jsonl"), n, 0);
        let l = SovereignLedger::new(&path, Some(b"bench-seed")).unwrap();
        c.bench_with_input(BenchmarkId::new("keyed_verify", n), &l, |b, l| {
            b.iter(|| l.verify().unwrap())
        });
    }
}

fn bench_verify_public(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    for n in [1_000usize, 10_000] {
        let path = ledger_with_entries(&dir, &format!("public_{n}.jsonl"), n, 500);
        let data = std::fs::read(&path).unwrap();
        c.bench_with_input(BenchmarkId::new("public_verify", n), &data, |b, data| {
            b.iter(|| {
                sovereign_ledger::seal::verify_public(BufReader::new(data.as_slice())).unwrap()
            })
        });
    }
}

criterion_group!(benches, bench_append, bench_verify, bench_verify_public);
criterion_main!(benches);
