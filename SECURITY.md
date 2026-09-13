# Security Policy

## Reporting a vulnerability

Email **savagetism@icloud.com** with the subject line
`sovereign_ledger security report`. Include a reproduction case (a crafted
ledger file or CLI invocation is ideal). Do not open a public issue for
unresolved vulnerabilities.

Expect acknowledgment within a few days. This is a solo-maintained beta —
be reasonable.

## Scope

In scope:

- Forging or mutating ledger entries without detection
- Crafted input that panics the parser, verifier, or proof checkers
- Lock, file-permission, or atomicity weaknesses
- Anchor/checkpoint signature verification bypasses

Out of scope:

- Attacks requiring possession of the key seeds or the anchor key file —
  if an attacker has your keys, the threat model is already lost
- The Secure Enclave anchor path, which delegates to Bad Apple's identity
  agent (report those to Bad Apple directly)
- Denial of service via resource exhaustion on attacker-supplied ledgers

## Guarantees and limits

See the README's "What it does not guarantee" section. Notably: v1-format
entries use a legacy ad-hoc keyed hash kept only for backward
compatibility; new writes are always v2/HMAC-SHA256.
