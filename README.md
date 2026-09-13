# sovereign_ledger

A standalone, hardened, hash-chained audit ledger for local-first and
sovereign systems. Every entry is authenticated with HMAC-SHA256 and bound
to the one before it; an RFC 6962 Merkle tree over the entry hashes gives
inclusion and consistency proofs; an anchor interface seals the tip under
an external key — including a Secure Enclave identity on macOS.

Derived from the audit core of Bad Apple and battle-tested against its
production ledger history (three legacy on-disk formats, ~7k live entries).

## What it guarantees

- **Tamper evidence.** Each event's hash covers the previous hash, sequence
  number, timestamp, event type, body, and the epoch key. Modifying any
  field, deleting or duplicating a line, reordering entries, truncating a
  tail record, or swapping the key is detected on open and on `verify()`.
- **Fail closed.** A malformed line, bad `prev_hash`, truncated tail, hash
  mismatch, or missing epoch key aborts or marks the ledger compromised.
  Nothing is silently skipped or auto-repaired.
- **Compromise is sticky.** Once a broken chain is observed, the handle
  refuses further appends. There is no silent recovery path.
- **Serialization under concurrency.** Opening a ledger takes a blocking
  exclusive `flock` on a sibling `<ledger>.lock` file, held for the
  handle's lifetime. Concurrent processes serialize instead of
  interleaving; a crashed process releases the lock automatically.
- **Owner-only files.** Ledger, lock, and checkpoint files are created
  `0600`; an existing ledger opened with looser permissions is tightened.
- **Key hygiene.** Keys live in `mlock`'d heap (best-effort) and are
  zeroized on drop. `rotate_key` moves to a new key epoch without breaking
  verification of the existing history.
- **No sequence wrap.** Sequence arithmetic is checked; overflow errors.

## What it does not guarantee

- **History before you started keying.** A chain entry proves internal
  consistency; only entries written under a key prove authenticity.
  Unkeyed historical data cannot be retroactively authenticated — anchor
  it and bound the window going forward.
- **Resistance to an attacker holding your seeds.** Keyed chains stop
  silent edits; they do not stop someone with the keyring from rewriting
  and re-signing. That is what anchors are for.
- **Replication or rotation.** One append-only file per ledger. Archival
  and multi-node sync are intentionally out of scope.
- **Sub-second ordering.** `ts` is seconds; ordering is carried by `seq`.

## Format

```text
v1 (legacy, verify-only):
  event.hash = SHA256(prev_hash || seq || ts || event_type || body || key)

v2 (current):
  event.hash = HMAC-SHA256(key,
      "SL2" || prev_hash || seq:u64le || ts:u64le
            || len(event_type):u32le || event_type
            || len(body):u64le || body)
```

- JSONL on disk — one event per line, append-only.
- `v` is the format version (absent ⇒ 1); `epoch` selects the keyring slot.
- Keys derive as `SHA256("SOVEREIGN_LEDGER:" || seed)`, or random.
- Genesis `prev_hash` is 32 zero bytes.
- Merkle leaves are the raw 32-byte entry hashes; tree hash follows
  RFC 6962 (`SHA256(0x00 || leaf)`, `SHA256(0x01 || left || right)`).

## Library

```rust
use sovereign_ledger::SovereignLedger;

let mut ledger = SovereignLedger::new("audit.jsonl", Some(b"seed"))?;
ledger.append("query", "user asked for the time")?;
ledger.sync()?;
ledger.verify()?;

// Stream without materializing the file:
for event in ledger.iter()? {
    let event = event?;
}

// Rotate to a new key epoch (verifiers then need both seeds):
ledger.rotate_key(b"new-seed")?;

// Proofs:
let root = ledger.merkle_root()?;
let inc = ledger.prove_inclusion(42)?;      // seq → Merkle inclusion proof
let con = ledger.prove_consistency(1000)?;  // old tree ⊑ current tree
```

Multi-epoch open: `SovereignLedger::open_with_seeds(path, &[seed0, seed1])`.

## Anchors

```rust
use sovereign_ledger::anchor::{Anchor, IdentityAgentAnchor, FileKeyAnchor, Tip};

// Hardware: Bad Apple's Secure Enclave identity agent over its unix socket.
let anchor = IdentityAgentAnchor::default_socket();

// Software fallback: a standalone HMAC key file (symmetric — whoever can
// verify can also forge; fine for offline/test, not a hardware anchor).
let anchor = FileKeyAnchor::from_file("anchor.key")?;

let checkpoint = anchor.attest(&tip)?;
anchor.verify(&checkpoint)?;   // enclave path calls back into the agent
```

Checkpoints store the verbatim signed payload plus the Merkle root, and
read back checkpoints written by older tooling.

## CLI

```sh
export SOVEREIGN_LEDGER_KEY="seed"                # epoch 0
# or: --keys-file keys.txt  (one seed per line, line number = epoch)

sovereign_ledger audit.jsonl init
sovereign_ledger audit.jsonl append query "hello"
echo body | sovereign_ledger audit.jsonl append query -
sovereign_ledger audit.jsonl verify [--json]
sovereign_ledger audit.jsonl tail -n 20 [-f]
sovereign_ledger audit.jsonl export --format cef    # SIEM-ready
sovereign_ledger audit.jsonl import --from badapple --source ledger.jsonl
sovereign_ledger audit.jsonl rotate-key --keys-file keys.txt
sovereign_ledger audit.jsonl root                   # tip + merkle root
sovereign_ledger audit.jsonl prove 42               # inclusion proof
sovereign_ledger audit.jsonl prove-consistency --old-size 1000
sovereign_ledger audit.jsonl anchor [--agent sock | --key-file k | --gen-key-file k]
sovereign_ledger audit.jsonl anchor-verify --checkpoint c.json [--key-file k]
```

`import` verifies the source in its native format first (Bad Apple's three
legacy schemas, `journalctl -o json`, or raw JSONL), then rebuilds under
the sovereign chain atomically — a partial import never masquerades as
complete.

## Durability

Appends hit the filesystem cache by default — call `sync()` at batch
boundaries, or `set_durable(true)` / `append --durable` to fsync every
entry. Use durable mode where crash-loss of the last entry matters.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The stress suite covers a 100k-entry append/verify pass, 16-process
concurrent appends, lock blocking, truncated tails, six tamper variants,
v1↔v2 mixed chains, key-epoch rotation, Merkle proof roundtrips, and
anchor signing. `fuzz/` has libFuzzer targets for the parser and the
proof verifiers (`cargo fuzz run parse_event`, `cargo fuzz run
verify_proofs`); CI runs both as smoke tests.

## Install

- Build from source: `cargo build --release` → `target/release/sovereign_ledger`
- Releases: unsigned universal macOS binaries with SHA256SUMS on the
  GitHub Releases page (`xattr -d com.apple.quarantine` after download).
- Homebrew: `brew install savageAZfck/tap/sovereign-ledger`

## License

Proprietary — (c) 2026 Adam Clark.
Contact savagetism@icloud.com for licensing or partnership.
