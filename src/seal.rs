//! Segment sealing and public verification.
//!
//! A *seal* closes a segment of the chain: it publishes the segment's
//! derived key — an independent PRF output that reveals nothing about
//! other segments' keys — and binds the segment's Merkle root under an
//! anchor signature. After sealing, the segment is publicly verifiable:
//! anyone can check entry MACs with the revealed key, recompute the
//! Merkle root, and verify the signature — without holding any secret.
//!
//! Security model: forging a sealed segment requires the anchor key (e.g.
//! the Secure Enclave), not the ledger key. Entries after the last seal
//! are structurally checked but are not yet publicly verifiable — seal on
//! a schedule and treat unsealed-tail integrity as covered by the
//! writer's live key plus the next seal.
//!
//! Legacy note: ledgers written before sealing existed authenticate
//! segment 0 under the epoch base key directly (format v ≤ 2). Sealing
//! such a segment publishes the base key, so appends under that epoch are
//! refused until `rotate_key` brings in a fresh seed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::BufRead;

use crate::{decode_hash, event_hash, Error, Event, Key, HASH_SIZE, SEAL_EVENT};

/// Something that can sign a seal payload and identify its key. Anchors
/// that sign with asymmetric keys produce publicly verifiable seals;
/// `FileKeyAnchor` (HMAC) produces seals verifiable only by key holders.
pub trait SealSigner {
    /// Scheme tag stored in the seal ("ed25519-file", "secure-enclave",
    /// "hmac-sha256").
    fn scheme(&self) -> &'static str;
    /// Public verification material, embedded in the seal so the ledger is
    /// self-verifying. Hex or base64 depending on scheme.
    fn public_key(&self) -> Result<String, Error>;
    /// Sign the canonical seal payload, returning the encoded signature.
    fn sign(&self, payload: &[u8]) -> Result<String, Error>;
}

/// The body of a `sovereign:seal` event.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealRecord {
    /// Segment index — number of seals recorded before this one.
    pub segment: u64,
    /// First and last seq covered by this seal.
    pub start_seq: u64,
    pub end_seq: u64,
    /// Chain tip hash at `end_seq`.
    pub tip_hash: String,
    /// RFC 6962 Merkle root over the segment's entry hashes.
    pub merkle_root: String,
    /// Derived key per epoch used in this segment, revealed at seal time.
    /// Post-seal these keys are public — anyone can recompute entry MACs.
    pub revealed: BTreeMap<u32, String>,
    /// Hash of the previous seal event ("" for the first seal). Binds seal
    /// ordering so a mid-chain seal cannot be silently dropped.
    pub prev_seal: String,
    /// Signing scheme tag.
    pub scheme: String,
    /// Embedded public verification material.
    pub public_key: String,
    /// Signature over `payload`.
    pub signature: String,
    /// Canonical JSON that `signature` covers, stored verbatim.
    pub payload: String,
}

/// Canonical signed payload: sorted keys, `", "` / `": "` separators —
/// the same convention as checkpoint payloads.
pub fn seal_payload(r: &SealRecord) -> String {
    let revealed = r
        .revealed
        .iter()
        .map(|(e, k)| format!("\"{e}\": \"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"end_seq\": {}, \"merkle_root\": \"{}\", \"revealed\": {{{}}}, \"segment\": {}, \"start_seq\": {}, \"tip_hash\": \"{}\"}}",
        r.end_seq, r.merkle_root, revealed, r.segment, r.start_seq, r.tip_hash
    )
}

/// Fill in `payload` and `signature` on a record using `signer`.
pub fn sign_record(mut r: SealRecord, signer: &dyn SealSigner) -> Result<SealRecord, Error> {
    r.payload = seal_payload(&r);
    r.signature = signer.sign(r.payload.as_bytes())?;
    Ok(r)
}

/// Parse a seal event body.
pub fn parse_body(body: &str) -> Result<SealRecord, Error> {
    serde_json::from_str(body)
        .map_err(|e| Error::Verification(format!("malformed seal record: {e}")))
}

/// Verify a seal signature against its embedded public material.
/// `hmac-sha256` seals are symmetric and cannot be publicly verified.
pub fn verify_signature(
    scheme: &str,
    public_key: &str,
    signature: &str,
    payload: &[u8],
) -> Result<bool, Error> {
    match scheme {
        "ed25519-file" => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let pk_bytes: [u8; 32] = hex::decode(public_key)
                .ok()
                .and_then(|v| v.as_slice().try_into().ok())
                .ok_or_else(|| Error::Verification("bad ed25519 seal public key".into()))?;
            let vk = VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| Error::Verification(format!("bad ed25519 seal public key: {e}")))?;
            let sig_bytes: [u8; 64] = hex::decode(signature)
                .ok()
                .and_then(|v| v.as_slice().try_into().ok())
                .ok_or_else(|| Error::Verification("bad ed25519 seal signature".into()))?;
            Ok(vk
                .verify(payload, &Signature::from_bytes(&sig_bytes))
                .is_ok())
        }
        "secure-enclave" => {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            use p256::ecdsa::signature::Verifier as _;
            use p256::ecdsa::{Signature, VerifyingKey};
            let pk = B64
                .decode(public_key)
                .map_err(|e| Error::Verification(format!("bad enclave seal public key: {e}")))?;
            let vk = VerifyingKey::from_sec1_bytes(&pk)
                .map_err(|e| Error::Verification(format!("bad enclave seal public key: {e}")))?;
            let der = B64
                .decode(signature)
                .map_err(|e| Error::Verification(format!("bad enclave seal signature: {e}")))?;
            let sig = Signature::from_der(&der)
                .map_err(|e| Error::Verification(format!("bad enclave seal signature: {e}")))?;
            Ok(vk.verify(payload, &sig).is_ok())
        }
        other => Err(Error::Verification(format!(
            "seal scheme '{other}' is not publicly verifiable (symmetric anchor)"
        ))),
    }
}

/// Outcome of a public (key-free) verification pass.
#[derive(Debug)]
pub struct PublicVerifyReport {
    /// Entries covered by a valid seal.
    pub sealed_entries: u64,
    /// Entries after the last seal — linkage-checked only.
    pub unsealed_entries: u64,
    /// Number of seals verified.
    pub segments: u64,
    /// Anchor identity pinned from the first seal.
    pub scheme: Option<String>,
    pub public_key: Option<String>,
}

/// Verify a ledger without any key material. Every sealed segment is
/// checked end-to-end: entry HMACs under the revealed derived keys,
/// Merkle root, chain tip, seal ordering, and the anchor signature. The
/// trailing unsealed segment is structurally checked (parse + chain
/// linkage) and reported separately.
pub fn verify_public<R: BufRead>(reader: R) -> Result<PublicVerifyReport, Error> {
    let mut seals_seen = 0u64;
    let mut last_hash = [0u8; HASH_SIZE];
    let mut buffer: Vec<Event> = Vec::new();
    let mut segment_start = 1u64;
    let mut sealed_entries = 0u64;
    let mut prev_seal_hash = String::new();
    let mut anchor_id: Option<(String, String)> = None;

    let finish_segment = |seal: &SealRecord,
                          buffer: &[Event],
                          line_no: usize,
                          seals_seen: u64,
                          segment_start: u64,
                          prev_seal_hash: &str,
                          anchor_id: &mut Option<(String, String)>|
     -> Result<(), Error> {
        let fail = |m: String| Err(Error::Verification(format!("line {line_no}: {m}")));
        if seal.segment != seals_seen {
            return fail(format!(
                "seal out of order: claims segment {} but {} seals seen",
                seal.segment, seals_seen
            ));
        }
        if seal.prev_seal != prev_seal_hash {
            return fail("seal prev_seal does not match the previous seal event".into());
        }
        if buffer.is_empty()
            || seal.start_seq != segment_start
            || seal.end_seq != segment_start + buffer.len() as u64 - 1
        {
            return fail(format!(
                "seal covers [{}..{}] but segment contains {} entries from {}",
                seal.start_seq,
                seal.end_seq,
                buffer.len(),
                segment_start
            ));
        }
        // Recompute entry MACs under the revealed keys, the Merkle root,
        // and the segment tip.
        let mut leaves = Vec::with_capacity(buffer.len());
        let mut prev = decode_hash(&buffer[0].prev_hash)
            .ok_or_else(|| Error::Verification("bad prev_hash".into()))?;
        let mut hash = prev;
        for e in buffer.iter() {
            let key_hex = match seal.revealed.get(&e.epoch) {
                Some(k) => k,
                None => return fail(format!("seal does not reveal a key for epoch {}", e.epoch)),
            };
            let key_bytes: [u8; HASH_SIZE] = match decode_hash(key_hex) {
                Some(k) => k,
                None => return fail("seal reveals a malformed key".into()),
            };
            let expected = event_hash(
                e.v,
                &prev,
                e.seq,
                e.ts,
                &e.event_type,
                &e.body,
                &Key::from_bytes(key_bytes),
            )?;
            if e.hash != hex::encode(expected) {
                return fail(format!("entry seq {} fails authentication", e.seq));
            }
            hash = expected;
            prev = hash;
            leaves.push(hash);
        }
        let root = crate::merkle::mth(&leaves);
        if hex::encode(root) != seal.merkle_root {
            return fail("seal merkle_root does not match segment entries".into());
        }
        if hex::encode(hash) != seal.tip_hash {
            return fail("seal tip_hash does not match segment tip".into());
        }
        // Anchor identity is pinned from the first seal.
        if let Some((scheme, pk)) = anchor_id.as_ref() {
            if *scheme != seal.scheme || *pk != seal.public_key {
                return fail("seal anchor identity changed mid-chain".into());
            }
        } else {
            *anchor_id = Some((seal.scheme.clone(), seal.public_key.clone()));
        }
        // Signature over the canonical payload. A stored payload must be
        // byte-identical to the canonical form — otherwise a signature over
        // some other payload could be replayed onto forged seal fields.
        let canonical = seal_payload(seal);
        if !seal.payload.is_empty() && seal.payload != canonical {
            return fail("seal payload does not match canonical seal fields".into());
        }
        if !verify_signature(
            &seal.scheme,
            &seal.public_key,
            &seal.signature,
            canonical.as_bytes(),
        )? {
            return fail("seal signature invalid".into());
        }
        Ok(())
    };

    for (this_line, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(line.trim_end())
            .map_err(|e| Error::InvalidLine(this_line, e.to_string()))?;
        let prev_hash = decode_hash(&event.prev_hash)
            .ok_or_else(|| Error::InvalidLine(this_line, "bad prev_hash".into()))?;
        if prev_hash != last_hash {
            return Err(Error::BrokenChain(this_line));
        }
        last_hash = decode_hash(&event.hash)
            .ok_or_else(|| Error::InvalidLine(this_line, "bad hash".into()))?;

        if event.event_type == SEAL_EVENT {
            let seal = parse_body(&event.body)
                .map_err(|e| Error::InvalidLine(this_line, e.to_string()))?;
            finish_segment(
                &seal,
                &buffer,
                this_line,
                seals_seen,
                segment_start,
                &prev_seal_hash,
                &mut anchor_id,
            )?;
            sealed_entries += buffer.len() as u64;
            buffer.clear();
            prev_seal_hash = event.hash.clone();
            seals_seen += 1;
            // The seal event is the first entry of the segment it opens.
            segment_start = event.seq;
            // Its MAC is checked when the next seal reveals that segment's key.
        }
        buffer.push(event);
    }

    Ok(PublicVerifyReport {
        sealed_entries,
        unsealed_entries: buffer.len() as u64,
        segments: seals_seen,
        scheme: anchor_id.as_ref().map(|(s, _)| s.clone()),
        public_key: anchor_id.map(|(_, p)| p),
    })
}
