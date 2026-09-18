# Conformance test vectors

Known-good and deliberately corrupted ledgers, with the required verifier
outcome for each declared in `expected.json`. Third-party verifier
implementations should consume this directory and produce the same
results.

## Layout

- `valid-*.jsonl` — ledgers that must verify: a plain keyed chain, a
  mid-chain key rotation, a two-segment sealed ledger with an unsealed
  tail (Ed25519 anchor), and a sealed ledger spanning a key rotation
  (multi-epoch `revealed` map).
- `broken-*.jsonl` — ledgers that must *fail*: a tampered entry body,
  swapped (reordered) entries, a mid-line truncated tail, a seal whose
  body was edited inside a sealed segment, an entry carrying an extra
  unauthenticated JSON field, and a crafted ledger whose `seq` values
  gap but whose MACs are all *valid* — only a verifier enforcing
  canonical sequence ordering rejects it.
- `expected.json` — per-file expectations for `keyed` verification
  (with the listed seeds) and `public` verification (no key material).
- `anchor-seed.bin` — the deterministic 32-byte Ed25519 seed whose
  verifying key is recorded in `expected.json`. It is a *test key*:
  public by construction, used nowhere else.

## Consuming

Keyed verification needs the seeds listed in `expected.json`
(`vector-seed-0`, `vector-seed-1`). Public verification needs nothing
but the file bytes — entry MACs are recomputed under keys the seals
themselves reveal, and anchor signatures check against the public keys
embedded in the seal records.

Expectations are substring-matched against the reference verifier's
error text (e.g. `broken hash chain`, `invalid ledger line`,
`fails authentication`). A conforming verifier should fail the same
vector at the same check, though the exact wording may differ.

## Regenerating

    cargo run --example gen_testvectors -- testvectors

Timestamps differ between runs; the *semantics* (what passes, what
fails, and where) are what's pinned, enforced by `tests/testvectors.rs`
in CI.

## Note on signature forgery

There is deliberately no "bad signature" vector: a seal's signature
lives inside the event's own `body`, which is covered by the entry MAC
— so flipping signature bytes is detected as a broken chain *before*
signature verification is reached. Signature validity over wrong keys
is exercised by unit tests in `tests/seals.rs`.
