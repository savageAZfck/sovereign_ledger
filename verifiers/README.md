# Independent verifiers

Verifier implementations that share **no code** with the Rust crate —
each written against [`SPEC.md`](../SPEC.md) alone. They exist to prove
the format is implementable independently, and to cross-check the
reference implementation: both must produce the same verdict on every
ledger, especially every `testvectors/broken-*` file.

## Implementations

| path | language | deps | covers |
|---|---|---|---|
| [`js/`](js/) | JavaScript (Node ≥ 18) | none — `node:crypto` only | keyed + public verification, all three anchor schemes |

## Conformance

Each implementation runs the vectors and must produce the outcomes
declared in `testvectors/expected.json`:

```sh
node verifiers/js/verify.mjs --selftest testvectors
# 20 checks passed, 0 failed
```

Expectations are substring-matched (`broken hash chain`,
`invalid ledger line`, `tip_hash does not match`, …) so implementations
need not share error text — only the verdict and the check that catches
the corruption.

## Contributing one

A verifier in any language is welcome and is the strongest possible
correctness evidence for the format. The contract is `SPEC.md` +
`testvectors/`; open a PR adding your implementation under
`verifiers/<lang>/` with a selftest runner.
