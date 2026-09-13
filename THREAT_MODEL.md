# Threat model

`sovereign_ledger` is designed to be honest about what it stops. This
document names attacker capabilities and states exactly which controls
hold, and which do not.

## Assets

- **The ledger file** — ordered event history.
- **The ledger seed / derived keys** — authenticate new entries.
- **Anchor keys** — Secure Enclave identity (never exportable) or an
  on-disk anchor seed file (Ed25519 or HMAC).
- **Checkpoints** — external signed attestations of a ledger tip.

## Attacker capabilities considered

### A1. Can read and write the ledger file (e.g. root on the host, malware, a rogue process)

- **Edit/delete/reorder entries in a sealed segment** → detected.
  Entry MACs verify under the revealed segment key, but the segment's
  Merkle root is bound by the anchor signature. Any content change moves
  the root off the signed value.
- **Forge a seal** → requires the anchor key. A software anchor seed file
  readable by the attacker means the anchor is compromised (see A3).
- **Append to the open tail** → undetectable *to a public verifier* until
  the next seal. The writer's live key is needed to produce a valid MAC;
  an attacker without it breaks chain linkage, which `verify --public`
  still catches. An attacker *with* the key (A3) can extend the tail.
- **Roll back the file to an old state** → detected by checkpoint
  comparison: a rolled-back tip does not match the latest signed
  checkpoint, and consistency proofs expose a non-prefix tree.
  Checkpoints are the rollback control; seals are the tamper control.

### A2. Steals the ledger seed / current key material

- **Rewrite sealed history** → still fails. The derived key revealed in
  each seal is public post-seal; integrity of sealed segments rests on
  the anchor signature, not key secrecy.
- **Forge new entries in the open tail** → possible *with the seed*.
  Segment keys are independent PRF outputs — a revealed seal key yields
  nothing about the open segment's key — so the tail requires live
  (unrevealed) key material. Mitigation: seal frequently; a stolen key
  cannot forge a seal without the anchor key.
- **Derive future segment keys** → impossible: `key(e, s) =
  HMAC(base_e, "sovereign-segment-v1" ‖ s)` is a PRF derivation, not an
  iterated chain, so publishing segment keys gives no forward
  leverage. Exception: sealing a legacy (v ≤ 2) segment 0 publishes the
  epoch base itself; the library then refuses appends under that epoch
  until `rotate_key` supplies a fresh seed.

### A3. Steals the anchor key

- **File anchors**: if the anchor seed file is readable, all bets are off
  for seals signed after the theft — the attacker can re-seal forged
  segments. Detectable only by holding an earlier signed checkpoint or a
  copy of the log elsewhere.
- **Secure Enclave anchor**: the private key cannot be extracted. An
  attacker who can *talk to* the agent while it runs can get signatures,
  but cannot take the capability with them — agent compromise is
  time-bounded by uptime, and the key never exists on disk.

### A4. Controls the machine's clock

- `ts` is informational; ordering is `seq` and the hash chain. Seals and
  checkpoints carry `signed_at` — a clock lie is visible but not
  prevented. `cert`-style staleness checks bound clock games to the
  freshness window.

### A5. Replaces the verifier binary

- Out of scope. Distribute the verifier independently (release binary,
  different machine, or read-only media). A compromised host can lie
  about everything — this is why checkpoints and seals are portable
  artifacts verifiable elsewhere.

## Explicit non-goals

- Confidentiality — entries are plaintext.
- Denial of service — a locked or deleted file is a denial, not a
  forgery; availability is an ops concern.
- Remote/networked notarization — the design is deliberately cloudless.
  Multi-machine assurance belongs to copies + cross-anchored
  checkpoints, not to this file format.

## The trust chain in one paragraph

Sealed segments rest on the anchor key. The open tail rests on the live
ledger key plus the next seal. Rollback rests on the newest checkpoint
you hold. Everything else — insertion, deletion, reordering, mutation,
silent truncation, key reuse across segments — is detected by hashing
alone. Keep the anchor key in hardware, seal on a schedule, and keep one
checkpoint off the box.
