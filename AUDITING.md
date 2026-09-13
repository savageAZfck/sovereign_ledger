# Auditing a sovereign_ledger file

How a third party verifies a sealed ledger without holding any secret.
You need: the ledger file, and the public key the log owner claims
anchors it (embedded in every seal — verify it matches what you expect;
trust-on-first-use is stated, not hidden).

## Quick check

```sh
sovereign_ledger path/to/ledger.jsonl verify --public
# chain valid (N sealed entries in M segments, K unsealed)
```

A clean pass means:

1. **Every sealed entry authenticates.** The seal for each segment
   reveals the derived HMAC key used for that segment. The verifier
   recomputes every entry's MAC and the segment's Merkle root.
2. **The chain is append-only.** Every `prev_hash` links to the previous
   entry's hash, from the zero genesis through the file tip.
3. **Each seal is genuinely signed.** The signature over the canonical
   seal payload (segment index, range, tip hash, Merkle root, revealed
   keys) verifies under the embedded public key — `ed25519-file`
   (Ed25519) or `secure-enclave` (ECDSA P-256, x963 public key, DER
   signature).
4. **Seals cannot be dropped or reordered.** Each seal records the hash
   of the previous seal event; segment indices must be consecutive.
5. **One anchor identity.** All seals must share scheme and public key;
   a mid-chain identity change fails.

## What a pass does NOT prove

- **The unsealed tail.** Entries after the last seal are parse- and
  linkage-checked only. Their MACs need the live segment key, which is
  intentionally not yet public. Ask the owner to run `seal` and give you
  the updated file, or check `unsealed_entries` in `--json` output.
- **Rollback.** `verify --public` proves the file is self-consistent.
  Proving it is the *latest* state requires a signed checkpoint (see
  below) or your own prior copy.
- **Content truth.** A ledger proves entries were recorded, not that
  they were true.

## Checkpoints (rollback detection)

The owner can sign the current tip out-of-band:

```sh
sovereign_ledger ledger.jsonl anchor --ed25519-key-file anchor.seed
# writes ledger.checkpoint.json — signed tip hash + merkle root + count
```

Hand the checkpoint file to the auditor with the ledger. The auditor
verifies the signature (`anchor-verify`) and can later confirm the
ledger still ends at that tip — or that it extended consistently.

## Verifying by hand (no tool trust)

The formats are stable and documented:

- Entries: `v=3` (or `v=2`/absent for pre-sealing ledgers), `hash =
  HMAC-SHA256(key, "SL2" || prev_hash || seq:u64le || ts:u64le ||
  len(type):u32le || type || len(body):u64le || body)`.
- v3 entries in segment `s` use `key = HMAC-SHA256(base,
  "sovereign-segment-v1" || s:u64le)` — independent per segment, so a
  revealed key cannot produce the open segment's key. v ≤ 2 entries in
  segment 0 use the epoch base directly; seals publish whichever key the
  segment's entries actually used, so the verifier never derives — it
  reads `revealed` verbatim.
- Seal payload: canonical JSON `{"end_seq": …, "merkle_root": …,
  "revealed": {…}, "segment": …, "start_seq": …, "tip_hash": …}` —
  stored verbatim in the seal's `payload` field.
- Merkle tree: RFC 6962 — leaf `SHA256(0x00||h)`, node
  `SHA256(0x01||l||r)`, empty `SHA256("")`.
- Ed25519 seals: `public_key`/`signature` are hex. Enclave seals: x963
  public key and DER signature, both base64, ECDSA-P256/SHA-256.

Any independent implementation can re-verify; nothing about the format
requires this binary.
