# Sovereign Ledger Format Specification

Version 3 — normative. Conforming implementations MUST produce identical
verification outcomes for every vector in `testvectors/`.

Notation: `||` is byte concatenation. Integers are little-endian unless
stated otherwise. `H(k, m)` is HMAC-SHA256 with key `k`. `SHA256` is
SHA-256. All hex is lowercase. All hash strings encode exactly 32 bytes.

## 1. Ledger file

A ledger is UTF-8 text: one JSON object per line, `\n`-terminated.
Empty lines are skipped. Lines MUST parse as an *event* — and an event
line MUST NOT carry fields outside the set below. The MAC covers
exactly this field set, so an extra key would ride through verification
unauthenticated; conforming parsers reject it.

```json
{"v":3,"seq":1,"ts":1758150000,"event_type":"audit","body":"{...}","epoch":0,"prev_hash":"00…","hash":"ab…"}
```

| field | type | meaning |
|---|---|---|
| `v` | u32 | format version of this entry; absent ⇒ 1 |
| `seq` | u64 | sequence number — canonical: starts at 1, increments by exactly 1 per event. Gaps or renumbering are a chain break even when all MACs check |
| `ts` | u64 | writer-supplied Unix seconds (not a verified value) |
| `event_type` | string | free-form kind; `sovereign:*` names are reserved |
| `body` | string | opaque payload (JSON-encoded seal/rotation records use it) |
| `epoch` | u32 | keyring index; absent ⇒ 0 |
| `prev_hash` | hex(32) | `hash` of the previous event; 32 zero bytes for the first |
| `hash` | hex(32) | this event's MAC (see §4) |

A verifier MUST reject unknown `v` values (> 3).

## 2. Keys

### 2.1 Base key (per epoch)

```
base_key(seed) = SHA256("SOVEREIGN_LEDGER:" || seed)      # 32 bytes
```

A random 32-byte key is used when no seed is supplied; such ledgers are
verifiable only by the key holder.

### 2.2 Segment key (format v ≥ 3)

The chain is divided into *segments*. Segment `s` (0-indexed, s = number
of seal events recorded before the segment's first entry) authenticates
under:

```
segment_key(base, s) = H(base, "sovereign-segment-v1" || s:u64le)
```

Each segment key is an independent PRF output. This is deliberate: a
ratchet `k_{s+1} = H(k_s, …)` would let one published key derive every
later key, which would defeat sealing.

### 2.3 Key selection for an entry

- `v` ≤ 2: the epoch's **base key** directly (legacy entries).
- `v` ≥ 3: `segment_key(base[epoch], s)` where `s` counts seal events
  seen *up to and including* the entry. **A seal event is the first
  entry of the segment it opens** — the first seal authenticates under
  `segment_key(base, 1)`, and so do all entries until the next seal.

An entry referencing an epoch outside the verifier's keyring MUST fail
(`MissingKey`).

## 3. Event MAC

### v2 and v3 (identical construction)

```
hash = H(entry_key,
         "SL2" ||
         prev_hash:32B ||
         seq:u64le ||
         ts:u64le ||
         len(event_type):u32le || event_type:utf8 ||
         len(body):u64le || body:utf8)
```

Length-prefixing `event_type` and `body` makes field splits
non-colliding. The stored `hash` MUST equal the hex of this MAC;
`prev_hash` MUST equal the previous event's `hash` (linkage is checked
independently of the MAC).

### v1 (legacy, verify-only)

```
hash = SHA256(prev_hash || seq:u64le || ts:u64le || event_type || body || key)
```

Suffix-keyed SHA-256, retained solely so pre-versioning ledgers verify.
New writers MUST NOT emit `v` = 1.

## 4. Reserved events

### 4.1 `sovereign:key-rotation`

Body: `{"epoch":N}`. Authenticated under the *new* epoch's key —
verifiers need seeds for every epoch the ledger uses.

### 4.2 `sovereign:seal`

Closes the buffered segment and opens a new one. Body is a JSON
`SealRecord`:

| field | meaning |
|---|---|
| `segment` | segment index it closes = count of prior seals |
| `start_seq`, `end_seq` | inclusive seq range of the segment's events |
| `tip_hash` | `hash` of the `end_seq` event |
| `merkle_root` | MTH over the segment's entry hashes (§5) |
| `revealed` | map `epoch:string → hex(entry_key)` — the key that authenticates that epoch's entries in this segment: `segment_key(base, segment)` for v ≥ 3 entries, or the epoch **base key** for a legacy (v ≤ 2) segment 0 |
| `prev_seal` | `hash` of the previous seal event; `""` for the first |
| `scheme` | `"ed25519-file"`, `"secure-enclave"`, or `"hmac-sha256"` |
| `public_key` | verification material, embedded (self-verifying ledger) |
| `signature` | signature over `payload` |
| `payload` | canonical JSON the signature covers (§4.3) |

As with events, a `SealRecord` MUST NOT carry fields outside this set —
the signature commits to the canonical fields, not stray keys.

Post-seal, the revealed segment keys are public by design — they
authenticate only that segment, and only for verification.

### 4.3 Canonical seal payload

The signature covers exactly this JSON — sorted keys, `", "` between
members, `": "` between key and value, `revealed` members sorted by
epoch:

```json
{"end_seq": 8, "merkle_root": "…", "revealed": {"0": "…"}, "segment": 0, "start_seq": 1, "tip_hash": "…"}
```

A stored `payload` that is non-empty MUST be byte-identical to the
canonical serialization of the other fields; otherwise a signature over
a different payload could be replayed onto forged fields.

### 4.4 Signature schemes

- **`ed25519-file`**: `public_key` is hex(32) Ed25519 verifying key;
  `signature` is hex(64) Ed25519 signature over `payload` bytes.
- **`secure-enclave`**: `public_key` is base64 SEC1-encoded P-256 point;
  `signature` is base64 DER ECDSA-P256-SHA256 signature.
- **`hmac-sha256`**: symmetric anchor — seals are NOT publicly
  verifiable; public verifiers MUST fail with an explicit error.

The anchor identity `(scheme, public_key)` is pinned by the first seal;
any change mid-chain MUST fail verification.

## 5. Merkle tree (RFC 6962 §2.1)

Leaves are the segment's decoded 32-byte entry `hash` values.

```
MTH({})       = SHA256("")
MTH({d})      = SHA256(0x00 || d)
MTH(D[0:n])   = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
              k = largest power of two < n
```

Inclusion proofs (`InclusionProof`) and consistency proofs
(`ConsistencyProof`) follow RFC 6962 §2.1.1/§2.1.2 semantics; the Rust
API in `merkle.rs` is the reference implementation.

## 6. Verification procedures

### 6.1 Keyed verification (key holder)

Requires seeds for every epoch used:

1. For each non-empty line: parse event, check `prev_hash` equals the
   running hash (init: 32 zero bytes) and `seq` equals the running
   count (init: 1, +1 per event) — else `BrokenChain`.
2. Select `entry_key` per §2.3 (counting seal events as they occur —
   each seal increments `s` *before* its own MAC check).
3. Recompute `hash` per §3 — mismatch ⇒ `BrokenChain`/`Compromised`.
4. Malformed JSON or bad hex ⇒ `InvalidLine`.
5. On each seal, additionally check `revealed[epoch]` equals the key
   §2.3 derives for that segment — a wrong reveal is itself tamper.
   (Public verification cannot perform this check; it is keyed-only.)

### 6.2 Public verification (no key material)

Checks everything a seal cryptographically commits to:

1. Chain linkage on every event plus canonical `seq` (as 6.1.1).
2. Buffer events between seals. On each `sovereign:seal` event, in order:
   - `segment` equals the running seal count; `prev_seal` equals the
     previous seal event's `hash`.
   - `[start_seq..end_seq]` covers exactly the buffered events.
   - Recompute every buffered event's MAC under
     `revealed[event.epoch]` — missing epoch keys or MAC mismatch fail.
   - `merkle_root` equals MTH over the buffered entry hashes;
     `tip_hash` equals the last entry hash.
   - `(scheme, public_key)` matches the first seal's — pinned anchor.
   - Stored `payload`, if present, is byte-identical to canonical;
     `signature` verifies over the canonical payload.
3. The seal event itself is buffered into the segment it opens; its MAC
   is checked when the next seal reveals that segment's key.
4. Report `sealed_entries`, `unsealed_entries` (trailing segment —
   linkage-checked only), `segments`, and the pinned anchor identity.

**Security consequence**: forging a sealed segment requires the anchor
private key, not the ledger key. The unsealed tail carries no public
guarantee — writers SHOULD seal on a schedule.

## 7. What the format does NOT guarantee

- `ts` is writer-supplied; nothing proves when an entry was written.
- Chain verification proves *what was written is what is read* — not
  that the statements are true.
- An unsealed tail can be rewritten by anyone holding the current epoch
  seed; only sealed segments are publicly anchored.
- `hmac-sha256`-anchored seals are verifiable only by key holders.

## 8. Conformance

`testvectors/` contains valid and corrupted ledgers with declared
outcomes in `expected.json`. A conforming verifier MUST pass every
`valid-*` vector and reject every `broken-*` vector at the declared
check (substring-matched: `broken hash chain`, `invalid ledger line`,
`tip_hash does not match`, …). Regenerate with:

```
cargo run --example gen_testvectors -- testvectors
```
