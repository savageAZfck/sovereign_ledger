# JS verifier

Single-file, zero-dependency implementation of the sovereign_ledger
verifier — written against `SPEC.md` only. Runs on Node ≥ 18
(`node:crypto` for HMAC-SHA256, SHA-256, Ed25519, and ECDSA-P256).

```sh
# Keyed verification (needs the ledger's seeds):
node verify.mjs <ledger.jsonl> --seed <seed0> [--seed <seed1> ...]

# Public verification (no key material; sealed segments only):
node verify.mjs <ledger.jsonl> --public

# Conformance against the vectors:
node verify.mjs --selftest ../..
```

Exits non-zero on any verification failure — an error is the verdict.
