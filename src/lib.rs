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

pub const HASH_SIZE: usize = 32;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    pub seq: u64,
    pub ts: u64,
    pub event_type: String,
    pub body: String,
    pub prev_hash: String,
    pub hash: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Hash an event record.
fn event_hash(
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

/// Standalone hardened, hash-chained audit ledger.
pub struct SovereignLedger {
    path: PathBuf,
    _lock: File,
    key: Key,
    last_hash: [u8; HASH_SIZE],
    seq: u64,
    read_only: AtomicBool,
    compromised: AtomicBool,
    durable: AtomicBool,
}

impl SovereignLedger {
    /// Open or create a ledger at `path`.
    /// If `key_seed` is supplied, the key is deterministic. Otherwise a random key is generated.
    pub fn new<P: AsRef<Path>>(path: P, key_seed: Option<&[u8]>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let key = Key::new(key_seed);

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

                // Validate chain linkage.
                let prev_hash: [u8; HASH_SIZE] = match hex::decode(&event.prev_hash) {
                    Ok(v) if v.len() == HASH_SIZE => v.try_into().unwrap_or([0u8; HASH_SIZE]),
                    _ => return Err(Error::InvalidLine(idx, "bad prev_hash".into())),
                };
                if prev_hash != last_hash {
                    compromised = true;
                    break;
                }

                // Validate this entry's hash.
                let expected = event_hash(
                    &last_hash,
                    event.seq,
                    event.ts,
                    &event.event_type,
                    &event.body,
                    &key,
                );
                let expected_hex = hex::encode(expected);
                if event.hash != expected_hex {
                    compromised = true;
                    break;
                }

                last_hash = expected;
                seq = event.seq;
            }
        }

        Ok(Self {
            path,
            _lock,
            key,
            last_hash,
            seq,
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

    /// Append an event to the ledger.
    pub fn append(&mut self, event_type: &str, body: &str) -> Result<u64, Error> {
        if self.compromised.load(Ordering::SeqCst) {
            return Err(Error::Compromised);
        }
        if self.read_only.load(Ordering::SeqCst) {
            return Err(Error::ReadOnly);
        }

        let ts = now();
        let next_seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Verification("sequence overflow".into()))?;
        let hash = event_hash(&self.last_hash, next_seq, ts, event_type, body, &self.key);

        let event = Event {
            seq: next_seq,
            ts,
            event_type: event_type.to_string(),
            body: body.to_string(),
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

    /// Re-read the ledger and verify the entire chain.
    pub fn verify(&self) -> Result<(), Error> {
        if !self.path.exists() {
            return Ok(());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut last_hash = [0u8; HASH_SIZE];
        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line)?;
            let prev_hash: [u8; HASH_SIZE] = match hex::decode(&event.prev_hash) {
                Ok(v) if v.len() == HASH_SIZE => v.try_into().unwrap_or([0u8; HASH_SIZE]),
                _ => return Err(Error::InvalidLine(idx, "bad prev_hash".into())),
            };
            if prev_hash != last_hash {
                return Err(Error::BrokenChain(idx));
            }
            let expected = event_hash(
                &last_hash,
                event.seq,
                event.ts,
                &event.event_type,
                &event.body,
                &self.key,
            );
            if event.hash != hex::encode(expected) {
                return Err(Error::BrokenChain(idx));
            }
            last_hash = expected;
        }
        Ok(())
    }

    /// Return every entry in the ledger.
    pub fn dump(&self) -> Result<Vec<Event>, Error> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(&line)?);
        }
        Ok(out)
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

    pub fn path(&self) -> &Path {
        &self.path
    }
}
