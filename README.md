# sovereign_ledger

A standalone, hardened, hash-chained audit ledger for local-first and
sovereign systems. Every entry is cryptographically bound to the one before
it and keyed by a memory-pinned secret, so silent edits, deletions,
reordering, truncation, and replay are all detectable.

Derived from the audit core of Bad Apple and battle-tested against its
production ledger history (three legacy on-disk formats, ~7k live entries).

## What it guarantees

- **Tamper evidence.** Each event's hash covers the previous hash, sequence
  number, timestamp, event type, body, and the ledger key. Modifying any
  field, deleting or duplicating a line, or reordering entries breaks the
  chain and is detected on open and on `verify()`.
- **Fail closed.** A malformed line, bad `prev_hash`, truncated tail record,
  or hash mismatch either aborts the open or marks the ledger compromised.
  Nothing is silently skipped or auto-repaired.
- **Compromise is sticky.** Once a broken chain is observed, the handle is
  flagged `compromised` and refuses further appends. There is no silent
  recovery path.
- **Serialization under concurrency.** Opening a ledger takes a blocking
  exclusive `flock` on a sibling `<ledger>.lock` file, held for the
  handle's lifetime. Concurrent processes serialize instead of interleaving
  records or racing on sequence state. A crashed process releases the lock
  automatically, so it can never wedge the ledger.
- **Owner-only files.** Ledger and lock files are created `0600`; an
  existing ledger opened with looser permissions is tightened on open.
- **Key hygiene.** The 32-byte key lives in a `mlock`'d heap allocation
  (best-effort, where the OS permits) and is zeroized on drop.
- **No sequence wrap.** Sequence arithmetic is checked; overflow is an
  error, not a wraparound.

## What it does not guarantee

- **History before you started keying.** A chain entry proves internal
  consistency; only entries written under a key prove authenticity. If a
  ledger's early history was written unkeyed, no tool can retroactively
  authenticate it — anchor it with an external signature (e.g. a Secure
  Enclave checkpoint) and bound the window going forward.
- **Resistance to an attacker who has the key file.** `prev_hash` chains
  stop silent edits; they do not stop someone holding your key seed from
  rewriting and re-signing. Pair the ledger with a hardware-anchored
  checkpoint cadence for that threat.
- **Replication or rotation.** This crate writes one append-only file. Log
  rotation, archival, and multi-node sync are intentionally out of scope.
- **Sub-second ordering.** Timestamps are seconds since epoch; ordering is
  carried by `seq`, not `ts`.

## Design

```text
event.hash = SHA256(prev_hash || seq || ts || event_type || body || key)
```

- JSONL on disk — one event per line, append-only.
- Genesis `prev_hash` is 32 zero bytes.
- The key is derived as `SHA256("SOVEREIGN_LEDGER:" || seed)`, or random
  when no seed is given. Verification requires the same seed.
- `mlock`/`munlock` are best-effort: on locked-memory-limited systems the
  key still gets zeroized on drop.

## Usage

Library:

```rust
use sovereign_ledger::SovereignLedger;

let mut ledger = SovereignLedger::new("/var/lib/myapp/audit.jsonl", Some(b"seed"))?;
ledger.append("query", "user asked for the time")?;
ledger.sync()?;          // force to stable storage
ledger.verify()?;        // re-read and check the whole chain
```

CLI:

```sh
export SOVEREIGN_LEDGER_KEY="your-seed"
sovereign_ledger /var/lib/myapp/audit.jsonl init
sovereign_ledger /var/lib/myapp/audit.jsonl append query "hello"
sovereign_ledger /var/lib/myapp/audit.jsonl verify
sovereign_ledger /var/lib/myapp/audit.jsonl tail 20
```

## Durability

Appends hit the filesystem cache by default for throughput — call `sync()`
at batch boundaries, or `set_durable(true)` to fsync every append. For
hard-stop durability across power loss, use `set_durable(true)`; for
high-volume logging, batch and `sync()`.

## Verification cadence

Pair this ledger with periodic external checkpoints — for example, sign the
tip hash with a hardware key (Bad Apple does this via a Secure Enclave
identity agent on a daily launchd schedule). The ledger makes tampering
detectable; a checkpoint bounds *when* it could have happened.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The stress suite covers a 100k-entry append/verify pass, 16-process
concurrent appends, lock blocking/release, truncated tail records, and six
tamper variants (deletion, reorder, duplication, body/hash/prev_hash
mutation).

## License

Proprietary — (c) 2026 Adam Clark.
Contact savagetism@icloud.com for licensing or partnership.
