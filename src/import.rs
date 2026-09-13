//! Foreign-ledger import: verify a source log in its native format, then
//! append each entry into a sovereign ledger under its own keyed chain.
//!
//! `badapple` understands all three historical Bad Apple ledger schemas
//! (Python plain/HMAC SHA-256, early-Swift inline chaining, current
//! prev_hash + HMAC). `journald` accepts `journalctl -o json` output.
//! `jsonl` wraps any line-delimited JSON (or text) without verification —
//! the source gains a keyed chain from import time forward.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::BufRead;

use crate::{Error, SovereignLedger};

type HmacSha256 = Hmac<Sha256>;

pub const BADAPPLE_GENESIS_LABEL: &str = "bad-apple-genesis-v1";

fn hex_sha256(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

fn hex_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Remove the top-level `"hash":"…64hex…"` field from a raw JSON object
/// line, preserving every other byte (escaping, key order, spacing) exactly
/// as the original writer produced it. Returns (body_json, hash_hex).
fn strip_hash_field(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if &bytes[i..i + 6] == b"\"hash\"" {
            let mut j = i + 6;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] != b':' {
                i += 1;
                continue;
            }
            j += 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] != b'"' {
                i += 1;
                continue;
            }
            let val_start = j + 1;
            let val_end = val_start + 64;
            if val_end < bytes.len()
                && bytes[val_end] == b'"'
                && bytes[val_start..val_end]
                    .iter()
                    .all(|c| c.is_ascii_hexdigit())
            {
                let hash = line[val_start..val_end].to_string();
                // Remove `,` immediately before the field (with optional
                // whitespace) plus the field itself.
                let mut k = i;
                while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                    k -= 1;
                }
                if k > 0 && bytes[k - 1] == b',' {
                    k -= 1;
                    let body = format!("{}{}", &line[..k], &line[val_end + 1..]);
                    // Sanity check the result is still a JSON object.
                    if serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&body).is_ok() {
                        return Some((body, hash));
                    }
                }
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    None
}

/// Verify one Bad Apple ledger line against the running `prev` hash.
/// Returns the stored hash (the new `prev`). `secrets` are candidate SLICKS
/// key representations (decoded hex, raw file text, trimmed text, raw bytes).
pub fn verify_badapple_line(line: &str, secrets: &[Vec<u8>], prev: &str) -> Result<String, Error> {
    if line.trim().is_empty() {
        return Ok(prev.to_string());
    }
    let entry: serde_json::Value =
        serde_json::from_str(line).map_err(|e| Error::Verification(e.to_string()))?;
    let (body_json, stored_hash) =
        strip_hash_field(line).ok_or_else(|| Error::Verification("missing 'hash' field".into()))?;

    let valid = if let Some(entry_prev) = entry.get("prev_hash").and_then(|v| v.as_str()) {
        // Python + current Swift schema: explicit prev_hash, hash over body.
        if entry_prev != prev {
            return Err(Error::Verification(format!(
                "prev_hash mismatch: expected {prev}, got {entry_prev}"
            )));
        }
        hex_sha256(&body_json) == stored_hash
            || secrets
                .iter()
                .any(|k| hex_hmac_sha256(k, body_json.as_bytes()) == stored_hash)
    } else if entry.get("timestamp").is_some() && entry.get("event_type").is_some() {
        // Early Swift schema: chain folded into hash = SHA256(prev + body).
        let material = format!("{prev}{body_json}");
        hex_sha256(&material) == stored_hash
            || secrets
                .iter()
                .any(|k| hex_hmac_sha256(k, material.as_bytes()) == stored_hash)
    } else {
        return Err(Error::Verification(
            "unrecognized entry schema (no prev_hash, no timestamp/event_type)".into(),
        ));
    };

    if !valid {
        return Err(Error::Verification(format!(
            "hash mismatch: stored {stored_hash} does not match any known scheme"
        )));
    }
    Ok(stored_hash)
}

/// Candidate key representations from a Bad Apple slicks.key file:
/// decoded hex (Swift era), raw file text with trailing newline (Python
/// era), trimmed text, and raw bytes.
pub fn slicks_key_candidates(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    if let Ok(text) = String::from_utf8(raw.to_vec()) {
        let trimmed = text.trim();
        if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(decoded) = hex::decode(trimmed) {
                candidates.push(decoded);
            }
        }
        candidates.push(text.as_bytes().to_vec());
        if !trimmed.is_empty() && trimmed != text {
            candidates.push(trimmed.as_bytes().to_vec());
        }
    }
    if !raw.is_empty() {
        candidates.push(raw.to_vec());
    }
    candidates
}

/// Extract (event_type, body) for the sovereign copy from a verified
/// Bad Apple source line.
fn badapple_event_fields(line: &str) -> Result<(String, String), Error> {
    let entry: serde_json::Value = serde_json::from_str(line)?;
    let event_type = entry
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("audit")
        .to_string();
    let body = entry
        .get("data")
        .map(|d| d.to_string())
        .unwrap_or_else(|| line.to_string());
    Ok((event_type, body))
}

pub struct ImportReport {
    /// Entries appended to the sovereign ledger.
    pub entries: usize,
    /// Tip hash of the source chain (Bad Apple native hash), or the
    /// sovereign tip for unverifiable formats.
    pub source_tip: String,
    /// Merkle root over the source chain's stored entry hashes, when the
    /// source format is verifiable.
    pub source_merkle_root: Option<String>,
}

/// Verify a Bad Apple ledger end-to-end and append each entry to `ledger`.
/// Fails closed on the first unverifiable line.
pub fn import_badapple<R: BufRead>(
    reader: R,
    secrets: &[Vec<u8>],
    ledger: &mut SovereignLedger,
) -> Result<ImportReport, Error> {
    let genesis = hex_sha256(BADAPPLE_GENESIS_LABEL.as_bytes());
    let mut prev = genesis;
    let mut entries = 0usize;
    let mut leaves = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let hash = verify_badapple_line(&line, secrets, &prev).map_err(|e| match e {
            Error::Verification(m) => {
                Error::Verification(format!("source ledger failed at line {idx}: {m}"))
            }
            other => other,
        })?;
        if let Ok(h) = hex::decode(&hash) {
            if h.len() == crate::HASH_SIZE {
                leaves.push(<[u8; 32]>::try_from(h.as_slice()).unwrap_or([0u8; 32]));
            }
        }
        prev = hash;
        let (event_type, body) = badapple_event_fields(&line)?;
        ledger.append(&event_type, &body)?;
        entries += 1;
    }
    Ok(ImportReport {
        entries,
        source_tip: prev,
        source_merkle_root: Some(hex::encode(crate::merkle::mth(&leaves))),
    })
}

/// Import `journalctl -o json` output. journald entries carry no
/// inter-entry chain, so each line becomes a sovereign entry whose body is
/// the raw journald record; SYSLOG_IDENTIFIER becomes the event type.
pub fn import_journald<R: BufRead>(
    reader: R,
    ledger: &mut SovereignLedger,
) -> Result<ImportReport, Error> {
    let mut entries = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| Error::InvalidLine(idx, e.to_string()))?;
        let event_type = record
            .get("SYSLOG_IDENTIFIER")
            .and_then(|v| v.as_str())
            .unwrap_or("journald")
            .to_string();
        ledger.append(&event_type, &line)?;
        entries += 1;
    }
    Ok(ImportReport {
        entries,
        source_tip: hex::encode(ledger.last_hash()),
        source_merkle_root: None,
    })
}

/// Import any line-delimited text as `import`-typed events. No source
/// verification — the sovereign chain authenticates from import forward.
pub fn import_jsonl<R: BufRead>(
    reader: R,
    ledger: &mut SovereignLedger,
) -> Result<ImportReport, Error> {
    let mut entries = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        ledger.append("import", &line)?;
        entries += 1;
    }
    Ok(ImportReport {
        entries,
        source_tip: hex::encode(ledger.last_hash()),
        source_merkle_root: None,
    })
}
