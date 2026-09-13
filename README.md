# sovereign_ledger

A standalone, hardened, hash-chained audit ledger for local-first and
sovereign systems. Every entry is authenticated with HMAC-SHA256 and bound
to the one before it; an RFC 6962 Merkle tree over the entry hashes gives
inclusion and consistency proofs; an anchor interface seals the tip under
an external key — including a Secure Enclave identity on macOS.

**v0.3: sealing + public verification.** `seal` closes a segment: it
publishes that segment's derived key and binds the segment's Merkle root
under an anchor signature. `verify --public` then verifies the whole sealed
history with **no secret material** — a third party can audit the file with
only the public key. See `THREAT_MODEL.md` for the security model and
`AUDITING.md` for the verifier's guide.

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
  and re-signing. Sealed segments are immune — their integrity rests on
  the anchor signature, not key secrecy. Unsealed tails are not.
- **The unsealed tail.** Entries after the last seal are linkage-checked
  but not publicly verifiable. Seal on a schedule; tail integrity until
  then is carried by the live key.
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
- **Segments**: v3 entries in segment `s` authenticate under
  `HMAC(base_key, "sovereign-segment-v1" || s:u64le)` — an independent PRF
  output per segment, so a revealed key exposes nothing about the open
  segment's key. Pre-v3 entries in segment 0 authenticate under the epoch
  base directly; sealing such a segment publishes the base, after which
  appends under that epoch require `rotate_key`. A `sovereign:seal` event
  (itself a normal v3 entry) opens the next segment. Seal bodies carry
  `{segment, start_seq, end_seq, tip_hash, merkle_root,
  revealed:{epoch→key}, prev_seal, scheme, public_key, signature,
  payload}`.

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
use sovereign_ledger::anchor::{Anchor, Ed25519FileAnchor, FileKeyAnchor, IdentityAgentAnchor, Tip};

// Hardware: Bad Apple's Secure Enclave identity agent over its unix socket.
let anchor = IdentityAgentAnchor::default_socket();

// Asymmetric software anchor: Ed25519 seed file. Publicly verifiable —
// preferred standalone anchor.
let anchor = Ed25519FileAnchor::from_file("anchor.seed")?;

// Symmetric fallback: HMAC key file (whoever can verify can also forge).
let anchor = FileKeyAnchor::from_file("anchor.key")?;

let checkpoint = anchor.attest(&tip)?;
anchor.verify(&checkpoint)?;   // enclave path calls back into the agent
```

Checkpoints store the verbatim signed payload plus the Merkle root, and
read back checkpoints written by older tooling.

## Sealing

```rust
use sovereign_ledger::seal;

// Close the current segment; the seal is the first entry of the next.
ledger.seal(&anchor)?;   // anchor must impl SealSigner

// Any reader can now verify sealed history with no keys:
let report = seal::verify_public(reader)?;   // sealed vs unsealed counts
```

Seal on a schedule (cron/launchd) — each seal turns the live segment into
a publicly verifiable artifact and advances the segment key.

## CLI

```sh
export SOVEREIGN_LEDGER_KEY="seed"                # epoch 0
# or: --keys-file keys.txt  (one seed per line, line number = epoch)

sovereign_ledger audit.jsonl init
sovereign_ledger audit.jsonl append query "hello"
echo body | sovereign_ledger audit.jsonl append query -
sovereign_ledger audit.jsonl verify [--json]
sovereign_ledger audit.jsonl verify --public   # no keys; sealed segments
sovereign_ledger audit.jsonl seal [--agent sock | --ed25519-key-file k | --ed25519-gen-key-file k]
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
- Releases: universal macOS binaries with SHA256SUMS on the GitHub
  Releases page (`xattr -d com.apple.quarantine` after download).
  Release artifacts are **keyless-signed with Sigstore** from CI — verify
  before running:

  ```sh
  cosign verify-blob \
    --bundle sovereign_ledger-vX.Y.Z-macos-universal.tar.gz.sigstore.json \
    --certificate-identity-regexp 'github.com/savageAZfck/sovereign_ledger' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    sovereign_ledger-vX.Y.Z-macos-universal.tar.gz
  ```

- Homebrew: `brew install savageAZfck/tap/sovereign-ledger`

## License

Proprietary — (c) 2026 Adam Clark.
Contact savagetism@icloud.com for licensing or partnership.
