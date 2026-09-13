use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub mod anchor;
pub mod import;
pub mod merkle;

pub const HASH_SIZE: usize = 32;
/// Current on-disk entry format version.
pub const FORMAT_VERSION: u32 = 2;
/// Special event type recorded when a ledger rotates to a new key epoch.
pub const KEY_ROTATION_EVENT: &str = "sovereign:key-rotation";

#[derive(Debug)]
pub enum Error {
    Compromised,
    ReadOnly,
    Io(std::io::Error),
    Serialization(serde_json::Error),
    InvalidLine(usize, String),
    BrokenChain(usize),
    Verification(String),
    Lock(String),
    /// An entry references a key epoch for which no seed was supplied.
    MissingKey(u32),
    UnsupportedVersion(u32),
    Anchor(String),
    Proof(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Compromised => write!(f, "ledger is compromised"),
            Error::ReadOnly => write!(f, "ledger is read-only"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Serialization(e) => write!(f, "serialization error: {e}"),
            Error::InvalidLine(n, e) => write!(f, "invalid ledger line {n}: {e}"),
            Error::BrokenChain(n) => write!(f, "broken hash chain at line {n}"),
            Error::Verification(e) => write!(f, "verification error: {e}"),
            Error::Lock(e) => write!(f, "lock error: {e}"),
            Error::MissingKey(e) => write!(f, "no key supplied for epoch {e}"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported entry version {v}"),
            Error::Anchor(e) => write!(f, "anchor error: {e}"),
            Error::Proof(e) => write!(f, "proof error: {e}"),
        }
    }
}

impl StdError for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e)
    }
}

#[cfg(target_family = "unix")]
fn pin_bytes(ptr: *mut u8, bytes: usize) {
    use libc::mlock;
    unsafe {
        if bytes > 0 {
            let _ = mlock(ptr as *const _, bytes);
        }
    }
}

#[cfg(not(target_family = "unix"))]
fn pin_bytes(_ptr: *mut u8, _bytes: usize) {}

#[cfg(target_family = "unix")]
fn unpin_bytes(ptr: *mut u8, bytes: usize) {
    use libc::munlock;
    unsafe {
        if bytes > 0 {
            let _ = munlock(ptr as *const _, bytes);
        }
    }
}

#[cfg(not(target_family = "unix"))]
fn unpin_bytes(_ptr: *mut u8, _bytes: usize) {}

#[cfg(target_family = "unix")]
fn flock_ex(file: &File) -> Result<(), Error> {
    // Blocking exclusive lock: concurrent openers serialize rather than race
    // or spuriously fail. flock is released automatically on process death,
    // so a crashed writer can never wedge the ledger.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(Error::Lock(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

#[cfg(not(target_family = "unix"))]
fn flock_ex(_file: &File) -> Result<(), Error> {
    Ok(())
}

/// In-memory cryptographic key. Pinned on heap and zeroized on drop.
pub struct Key {
    data: Box<[u8; HASH_SIZE]>,
}

impl Key {
    /// Derive a key from a seed, or generate a random one if no seed is given.
    pub fn new(seed: Option<&[u8]>) -> Self {
        let mut data = Box::new([0u8; HASH_SIZE]);
        if let Some(seed) = seed {
            let mut h = Sha256::new();
            h.update(b"SOVEREIGN_LEDGER:");
            h.update(seed);
            let out = h.finalize();
            data[..HASH_SIZE].copy_from_slice(out.as_slice());
        } else {
            use rand::Rng;
            rand::rngs::OsRng.fill(&mut *data);
        }
        pin_bytes(data.as_mut_ptr(), HASH_SIZE);
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &*self.data
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unpin_bytes(self.data.as_mut_ptr(), HASH_SIZE);
        self.data.zeroize();
    }
}

/// One ledger entry. `v` is the format version: entries written before
/// versioning have no `v` field and deserialize as version 1 (the legacy
/// ad-hoc keyed hash). Version 2 entries are authenticated with
/// HMAC-SHA256 over length-prefixed fields. `epoch` selects which key in
/// the supplied keyring authenticates the entry.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    #[serde(default = "default_version")]
    pub v: u32,
    pub seq: u64,
    pub ts: u64,
    pub event_type: String,
    pub body: String,
    #[serde(default)]
    pub epoch: u32,
    pub prev_hash: String,
    pub hash: String,
}

fn default_version() -> u32 {
    1
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Legacy v1 hash: ad-hoc suffix-keyed SHA-256. Retained only so ledgers
/// written before format versioning still verify; never used for new writes.
fn event_hash_v1(
    prev_hash: &[u8; HASH_SIZE],
    seq: u64,
    ts: u64,
    event_type: &str,
    body: &str,
    key: &Key,
) -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update(prev_hash);
    h.update(seq.to_le_bytes());
    h.update(ts.to_le_bytes());
    h.update(event_type.as_bytes());
    h.update(body.as_bytes());
    h.update(key.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(digest.as_slice());
    out
}

/// v2 hash: HMAC-SHA256 over domain-tagged, length-prefixed fields so no
/// two field splits can collide.
fn event_hash_v2(
    prev_hash: &[u8; HASH_SIZE],
    seq: u64,
    ts: u64,
    event_type: &str,
    body: &str,
    key: &Key,
) -> [u8; HASH_SIZE] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(b"SL2");
    mac.update(prev_hash);
    mac.update(&seq.to_le_bytes());
    mac.update(&ts.to_le_bytes());
    mac.update(&(event_type.len() as u32).to_le_bytes());
    mac.update(event_type.as_bytes());
    mac.update(&(body.len() as u64).to_le_bytes());
    mac.update(body.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut digest = [0u8; HASH_SIZE];
    digest.copy_from_slice(&out);
    digest
}

fn event_hash(
    version: u32,
    prev_hash: &[u8; HASH_SIZE],
    seq: u64,
    ts: u64,
    event_type: &str,
    body: &str,
    key: &Key,
) -> Result<[u8; HASH_SIZE], Error> {
    match version {
        1 => Ok(event_hash_v1(prev_hash, seq, ts, event_type, body, key)),
        2 => Ok(event_hash_v2(prev_hash, seq, ts, event_type, body, key)),
        v => Err(Error::UnsupportedVersion(v)),
    }
}

fn decode_hash(s: &str) -> Option<[u8; HASH_SIZE]> {
    match hex::decode(s) {
        Ok(v) if v.len() == HASH_SIZE => v.try_into().ok(),
        _ => None,
    }
}

/// Streaming iterator over ledger entries — never materializes the whole file.
pub struct LedgerIter {
    reader: BufReader<File>,
    line: usize,
}

impl Iterator for LedgerIter {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut buf = String::new();
            match self.reader.read_line(&mut buf) {
                Ok(0) => return None,
                Ok(_) => {
                    let line_no = self.line;
                    self.line += 1;
                    if buf.trim().is_empty() {
                        continue;
                    }
                    return Some(
                        serde_json::from_str(buf.trim_end())
                            .map_err(|e| Error::InvalidLine(line_no, e.to_string())),
                    );
                }
                Err(e) => return Some(Err(Error::Io(e))),
            }
        }
    }
}

/// Standalone hardened, hash-chained audit ledger.
pub struct SovereignLedger {
    path: PathBuf,
    _lock: File,
    keys: Vec<Key>,
    last_hash: [u8; HASH_SIZE],
    seq: u64,
    epoch: u32,
    read_only: AtomicBool,
    compromised: AtomicBool,
    durable: AtomicBool,
}

impl SovereignLedger {
    /// Open or create a ledger at `path` with a single epoch-0 key.
    /// If `key_seed` is supplied, the key is deterministic. Otherwise a
    /// random key is generated.
    pub fn new<P: AsRef<Path>>(path: P, key_seed: Option<&[u8]>) -> Result<Self, Error> {
        match key_seed {
            Some(seed) => Self::open_with_seeds(path, &[seed]),
            None => Self::open_with_seeds(path, &[] as &[&[u8]]),
        }
    }

    /// Open or create a ledger with an explicit keyring. `seeds[i]` derives
    /// the key for epoch `i`. An empty slice generates a random epoch-0 key.
    /// Entries whose `epoch` has no corresponding seed fail verification.
    pub fn open_with_seeds<P: AsRef<Path>>(path: P, seeds: &[&[u8]]) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let keys: Vec<Key> = if seeds.is_empty() {
            vec![Key::new(None)]
        } else {
            seeds.iter().map(|s| Key::new(Some(s))).collect()
        };

        // Hold an advisory lock for the lifetime of this handle. The lock file is a sibling
        // of the ledger file named `<ledger>.lock`.
        let file_name = path.file_name().map(|n| n.to_string_lossy().to_string());
        let lock_path = if let Some(name) = file_name {
            path.with_file_name(format!("{}.lock", name))
        } else {
            path.with_extension("lock")
        };
        let _lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)?;
        flock_ex(&_lock)?;

        // Enforce owner-only access on an existing ledger that was created or
        // copied in with looser permissions.
        #[cfg(target_family = "unix")]
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        let mut last_hash = [0u8; HASH_SIZE];
        let mut seq = 0u64;
        let mut max_epoch = 0u32;
        let mut compromised = false;

        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for (idx, line) in reader.lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: Event = match serde_json::from_str(&line) {
                    Ok(e) => e,
                    Err(e) => return Err(Error::InvalidLine(idx, e.to_string())),
                };
                let key = keys
                    .get(event.epoch as usize)
                    .ok_or(Error::MissingKey(event.epoch))?;

                let prev_hash: [u8; HASH_SIZE] = match decode_hash(&event.prev_hash) {
                    Some(h) => h,
                    None => return Err(Error::InvalidLine(idx, "bad prev_hash".into())),
                };
                if prev_hash != last_hash {
                    compromised = true;
                    break;
                }

                let expected = event_hash(
                    event.v,
                    &last_hash,
                    event.seq,
                    event.ts,
                    &event.event_type,
                    &event.body,
                    key,
                )?;
                let expected_hex = hex::encode(expected);
                if event.hash != expected_hex {
                    compromised = true;
                    break;
                }

                last_hash = expected;
                seq = event.seq;
                max_epoch = max_epoch.max(event.epoch);
            }
        }

        Ok(Self {
            path,
            _lock,
            keys,
            last_hash,
            seq,
            epoch: max_epoch,
            read_only: AtomicBool::new(false),
            compromised: AtomicBool::new(compromised),
            durable: AtomicBool::new(false),
        })
    }

    /// When enabled, every append fsyncs before returning. Off by default —
    /// call `sync()` explicitly after batches for much better throughput.
    pub fn set_durable(&self, durable: bool) {
        self.durable.store(durable, Ordering::SeqCst);
    }

    /// Current key epoch. New appends are authenticated under this epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Rotate to a new signing key. Records a `sovereign:key-rotation`
    /// entry authenticated under the new key, then returns the new epoch.
    /// Verifying a rotated ledger requires seeds for every used epoch.
    pub fn rotate_key(&mut self, new_seed: &[u8]) -> Result<u32, Error> {
        self.keys.push(Key::new(Some(new_seed)));
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| Error::Verification("epoch overflow".into()))?;
        let body = format!("{{\"epoch\":{}}}", self.epoch);
        self.append(KEY_ROTATION_EVENT, &body)?;
        Ok(self.epoch)
    }

    /// Append an event to the ledger.
    pub fn append(&mut self, event_type: &str, body: &str) -> Result<u64, Error> {
        if self.compromised.load(Ordering::SeqCst) {
            return Err(Error::Compromised);
        }
        if self.read_only.load(Ordering::SeqCst) {
            return Err(Error::ReadOnly);
        }
        let key = self
            .keys
            .get(self.epoch as usize)
            .ok_or(Error::MissingKey(self.epoch))?;

        let ts = now();
        let next_seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Verification("sequence overflow".into()))?;
        let hash = event_hash_v2(&self.last_hash, next_seq, ts, event_type, body, key);

        let event = Event {
            v: FORMAT_VERSION,
            seq: next_seq,
            ts,
            event_type: event_type.to_string(),
            body: body.to_string(),
            epoch: self.epoch,
            prev_hash: hex::encode(self.last_hash),
            hash: hex::encode(hash),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        let line = serde_json::to_string(&event)?;
        writeln!(file, "{}", line)?;
        if self.durable.load(Ordering::SeqCst) {
            file.sync_all()?;
        }

        self.last_hash = hash;
        self.seq = next_seq;
        Ok(next_seq)
    }

    /// Force all buffered data to stable storage.
    pub fn sync(&self) -> Result<(), Error> {
        let file = OpenOptions::new().append(true).open(&self.path)?;
        file.sync_all()?;
        Ok(())
    }

    /// Stream entries from disk without materializing the whole file.
    pub fn iter(&self) -> Result<LedgerIter, Error> {
        let file = File::open(&self.path)?;
        Ok(LedgerIter {
            reader: BufReader::new(file),
            line: 0,
        })
    }

    /// Re-read the ledger and verify the entire chain. Streams entries, so
    /// memory use stays flat regardless of ledger size.
    pub fn verify(&self) -> Result<(), Error> {
        if !self.path.exists() {
            return Ok(());
        }
        let mut last_hash = [0u8; HASH_SIZE];
        for (idx, item) in self.iter()?.enumerate() {
            let event = item?;
            let key = self
                .keys
                .get(event.epoch as usize)
                .ok_or(Error::MissingKey(event.epoch))?;
            let prev_hash: [u8; HASH_SIZE] = match decode_hash(&event.prev_hash) {
                Some(h) => h,
                None => return Err(Error::InvalidLine(idx, "bad prev_hash".into())),
            };
            if prev_hash != last_hash {
                return Err(Error::BrokenChain(idx));
            }
            let expected = event_hash(
                event.v,
                &last_hash,
                event.seq,
                event.ts,
                &event.event_type,
                &event.body,
                key,
            )?;
            if event.hash != hex::encode(expected) {
                return Err(Error::BrokenChain(idx));
            }
            last_hash = expected;
        }
        Ok(())
    }

    /// Return every entry in the ledger. Prefer `iter()` for large ledgers.
    pub fn dump(&self) -> Result<Vec<Event>, Error> {
        match self.iter() {
            Ok(it) => it.collect(),
            Err(e) => match e {
                Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                e => Err(e),
            },
        }
    }

    /// Prevent further writes.
    pub fn mark_readonly(&self) {
        self.read_only.store(true, Ordering::SeqCst);
    }

    /// Mark the ledger as compromised.
    pub fn mark_compromised(&self) {
        self.compromised.store(true, Ordering::SeqCst);
    }

    pub fn is_compromised(&self) -> bool {
        self.compromised.load(Ordering::SeqCst)
    }

    pub fn is_readonly(&self) -> bool {
        self.read_only.load(Ordering::SeqCst)
    }

    pub fn last_hash(&self) -> [u8; HASH_SIZE] {
        self.last_hash
    }

    /// Number of verified entries seen at open time.
    pub fn len(&self) -> u64 {
        self.seq
    }

    pub fn is_empty(&self) -> bool {
        self.seq == 0
    }

    /// Stream just the per-entry hashes — the leaves of the Merkle tree.
    pub fn leaf_hashes(&self) -> Result<Vec<[u8; HASH_SIZE]>, Error> {
        let mut out = Vec::new();
        for item in self.iter()? {
            let event = item?;
            out.push(
                decode_hash(&event.hash)
                    .ok_or_else(|| Error::Verification("bad stored hash".into()))?,
            );
        }
        Ok(out)
    }

    /// Merkle root over all entry hashes (RFC 6962 MTH).
    pub fn merkle_root(&self) -> Result<[u8; HASH_SIZE], Error> {
        Ok(merkle::mth(&self.leaf_hashes()?))
    }

    /// Inclusion proof for the entry with the given `seq` (1-based entries
    /// map to 0-based leaves).
    pub fn prove_inclusion(&self, seq: u64) -> Result<merkle::InclusionProof, Error> {
        let leaves = self.leaf_hashes()?;
        if seq == 0 || seq as usize > leaves.len() {
            return Err(Error::Proof(format!("no entry with seq {seq}")));
        }
        Ok(merkle::InclusionProof {
            index: seq - 1,
            tree_size: leaves.len() as u64,
            path: merkle::audit_path(seq - 1, &leaves),
        })
    }

    /// Consistency proof that the tree with `old_size` entries is a prefix
    /// of the current tree.
    pub fn prove_consistency(&self, old_size: u64) -> Result<merkle::ConsistencyProof, Error> {
        let leaves = self.leaf_hashes()?;
        let n = leaves.len() as u64;
        if old_size > n {
            return Err(Error::Proof(format!(
                "old_size {old_size} exceeds tree size {n}"
            )));
        }
        Ok(merkle::ConsistencyProof {
            old_size,
            new_size: n,
            nodes: merkle::consistency_proof(old_size, &leaves),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
