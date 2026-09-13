//! Checkpoint anchors: external signatures over a ledger tip.
//!
//! The hash chain makes tampering detectable; an anchor bounds *when* it
//! could have happened, by attesting the tip hash under a key that lives
//! outside the ledger file — a Secure Enclave identity via Bad Apple's
//! identity agent, or a separate key file as a software fallback.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{Error, HASH_SIZE};

/// A signed attestation over a ledger tip. The `payload` field is the
/// canonical JSON string that was actually signed — keeping it verbatim
/// makes verification independent of field ordering or reconstruction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Checkpoint {
    pub entry_count: u64,
    pub genesis: String,
    pub tip_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    pub signed_at: String,
    /// "secure-enclave" (hardware, via identity agent) or "hmac-sha256"
    /// (software key file — symmetric; see FileKeyAnchor docs).
    #[serde(default)]
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub signature: String,
    /// Canonical JSON payload that `signature` covers. Checkpoints written
    /// by older tooling omit it; verification rebuilds the payload.
    #[serde(default)]
    pub payload: String,
}

/// Something that can attest a ledger tip under an external key.
pub trait Anchor {
    /// Produce a signed checkpoint over the current tip.
    fn attest(&self, tip: &Tip) -> Result<Checkpoint, Error>;
    /// Verify a previously issued checkpoint.
    fn verify(&self, checkpoint: &Checkpoint) -> Result<bool, Error>;
}

/// The state an anchor commits to.
pub struct Tip {
    pub tip_hash: [u8; HASH_SIZE],
    pub merkle_root: [u8; HASH_SIZE],
    pub entry_count: u64,
    /// Identifier for the empty-prefix hash of the source format, e.g.
    /// "bad-apple-genesis-v1" for Bad Apple ledgers or the 64-zero hex
    /// genesis of a native sovereign chain.
    pub genesis: String,
}

/// Canonical signed payload. Keys sorted, `", "` / `": "` separators —
/// the same shape as the historical Bad Apple checkpoint writer so older
/// checkpoints and tooling stay inter-compatible.
fn canonical_payload(tip: &Tip, signed_at: &str) -> String {
    format!(
        "{{\"entry_count\": {}, \"genesis\": \"{}\", \"merkle_root\": \"{}\", \"signed_at\": \"{}\", \"tip_hash\": \"{}\"}}",
        tip.entry_count,
        tip.genesis,
        hex::encode(tip.merkle_root),
        signed_at,
        hex::encode(tip.tip_hash),
    )
}

/// Reconstruct the payload a checkpoint was signed over. Prefers the
/// stored verbatim `payload`; falls back to rebuilding the legacy
/// (pre-merkle_root) format for checkpoints written by older tooling.
fn checkpoint_payload(c: &Checkpoint) -> String {
    if !c.payload.is_empty() {
        return c.payload.clone();
    }
    match &c.merkle_root {
        Some(root) => format!(
            "{{\"entry_count\": {}, \"genesis\": \"{}\", \"merkle_root\": \"{}\", \"signed_at\": \"{}\", \"tip_hash\": \"{}\"}}",
            c.entry_count, c.genesis, root, c.signed_at, c.tip_hash
        ),
        None => format!(
            "{{\"entry_count\": {}, \"genesis\": \"{}\", \"signed_at\": \"{}\", \"tip_hash\": \"{}\"}}",
            c.entry_count, c.genesis, c.signed_at, c.tip_hash
        ),
    }
}

/// Write a checkpoint file atomically next to the ledger.
pub fn write_checkpoint(dir: &Path, name: &str, c: &Checkpoint) -> Result<PathBuf, Error> {
    let path = dir.join(name);
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(serde_json::to_string_pretty(c)?.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Anchor backed by Bad Apple's identity agent — a long-lived process that
/// owns a Secure Enclave signing key and speaks newline-delimited JSON over
/// a unix socket. Signatures are ECDSA/P-256; the private key never leaves
/// the enclave.
pub struct IdentityAgentAnchor {
    socket_path: PathBuf,
}

impl IdentityAgentAnchor {
    pub fn new<P: Into<PathBuf>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Bad Apple's default agent socket.
    pub fn default_socket() -> Self {
        Self::new("/var/run/badapple/identity.sock")
    }

    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }

    fn call(&self, request: serde_json::Value) -> Result<serde_json::Value, Error> {
        if !self.is_available() {
            return Err(Error::Anchor("identity agent socket not found".into()));
        }
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let mut frame = serde_json::to_vec(&request)?;
        frame.push(b'\n');
        writer.write_all(&frame)?;
        writer.flush()?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(Error::Anchor("identity agent closed the connection".into()));
        }
        let resp: serde_json::Value = serde_json::from_str(&line)?;
        if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(Error::Anchor(
                resp.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown agent error")
                    .to_string(),
            ));
        }
        Ok(resp)
    }

    pub fn public_key(&self) -> Result<String, Error> {
        self.call(serde_json::json!({"command": "public_key"}))?
            .get("public_key")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| Error::Anchor("agent returned no public key".into()))
    }

    fn sign(&self, message_b64: &str) -> Result<String, Error> {
        self.call(serde_json::json!({
            "command": "sign",
            "message_b64": message_b64,
        }))?
        .get("signature")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| Error::Anchor("agent returned no signature".into()))
    }
}

impl Anchor for IdentityAgentAnchor {
    fn attest(&self, tip: &Tip) -> Result<Checkpoint, Error> {
        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
        let payload = canonical_payload(tip, &signed_at);
        let signature = self.sign(&B64.encode(payload.as_bytes()))?;
        let public_key = self.public_key()?;
        Ok(Checkpoint {
            entry_count: tip.entry_count,
            genesis: tip.genesis.clone(),
            tip_hash: hex::encode(tip.tip_hash),
            merkle_root: Some(hex::encode(tip.merkle_root)),
            signed_at,
            scheme: "secure-enclave".into(),
            public_key: Some(public_key),
            signature,
            payload,
        })
    }

    fn verify(&self, checkpoint: &Checkpoint) -> Result<bool, Error> {
        let public_key = checkpoint
            .public_key
            .as_deref()
            .ok_or_else(|| Error::Anchor("checkpoint has no public key".into()))?;
        let payload = checkpoint_payload(checkpoint);
        let resp = self.call(serde_json::json!({
            "command": "verify",
            "message_b64": B64.encode(payload.as_bytes()),
            "signature": checkpoint.signature,
            "public_key": public_key,
        }))?;
        Ok(resp.get("valid").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}

/// Software anchor: HMAC-SHA256 over the payload with a standalone key
/// file. Useful for offline/test deployments and as a second, differently
/// keyed attestation — but the key is symmetric, so anyone who can verify
/// can also forge. Prefer IdentityAgentAnchor where an agent is running.
pub struct FileKeyAnchor {
    key: Vec<u8>,
}

impl FileKeyAnchor {
    /// Load the anchor key from a file. The raw file bytes are the key.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(Self {
            key: std::fs::read(path)?,
        })
    }

    /// Create a fresh random anchor key and write it to `path` (0600).
    pub fn generate<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        use rand::Rng;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill(&mut key);
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(&key)?;
            f.sync_all()?;
        }
        Ok(Self { key: key.to_vec() })
    }

    fn mac(&self, payload: &str) -> String {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC key length");
        m.update(payload.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    /// Stable identifier for this key (its fingerprint — never the key).
    pub fn key_id(&self) -> String {
        hex::encode(Sha256::digest(&self.key))
    }
}

impl Drop for FileKeyAnchor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

use zeroize::Zeroize;

impl Anchor for FileKeyAnchor {
    fn attest(&self, tip: &Tip) -> Result<Checkpoint, Error> {
        let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
        let payload = canonical_payload(tip, &signed_at);
        let signature = self.mac(&payload);
        Ok(Checkpoint {
            entry_count: tip.entry_count,
            genesis: tip.genesis.clone(),
            tip_hash: hex::encode(tip.tip_hash),
            merkle_root: Some(hex::encode(tip.merkle_root)),
            signed_at,
            scheme: "hmac-sha256".into(),
            public_key: Some(self.key_id()),
            signature,
            payload,
        })
    }

    fn verify(&self, checkpoint: &Checkpoint) -> Result<bool, Error> {
        Ok(self.mac(&checkpoint_payload(checkpoint)) == checkpoint.signature)
    }
}
