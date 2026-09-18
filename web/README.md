# Browser verifier

`index.html` + the wasm-bindgen build of the pure verification core.
Drop or paste a `.jsonl` ledger and the page verifies every sealed
segment locally — entry MACs under the seals' revealed keys, Merkle
roots, chain tips, seal ordering, anchor signatures. Nothing is
uploaded; there is no network code in the verifier path.

## Build

```sh
cargo install wasm-pack          # once
wasm-pack build --target web --out-dir web/pkg -- --no-default-features --features wasm
```

`--no-default-features` compiles the verification core without the
filesystem surface; `--features wasm` adds the `verify_ledger_public`
binding. The output lands in `web/pkg/` (gitignored).

## Serve

Any static file server works — ES modules need `http://`, not `file://`:

```sh
cd web && python3 -m http.server 8080   # or: npx serve web
```

Open `http://localhost:8080`. `testvectors/valid-sealed.jsonl` is a
good first drop; any `broken-*` vector shows the failure rendering.

## What it checks

| check | how |
|---|---|
| chain linkage | `prev_hash` = prior `hash`, first = 32 zero bytes |
| entry MACs | recomputed under keys the seals themselves reveal |
| Merkle root | RFC 6962 MTH over the segment's entry hashes |
| seal ordering | `segment` index + `prev_seal` hash chain |
| anchor identity | `(scheme, public_key)` pinned from the first seal |
| signature | Ed25519 or ECDSA-P256 over the canonical payload |

Format details: `../SPEC.md`. Conformance fixtures: `../testvectors/`.
