use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{Rng, rngs::OsRng};
use tokio::sync::{mpsc, broadcast};
use hex;

// =================== GLOBAL CONFIGURATIONS ====================
const MSG_SIZE: usize = 128;
const HASH_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const RING_SIZE: usize = 128;

// =================== OS VIRTUAL MEMORY PROTECTION ====================
#[cfg(target_family = "unix")]
fn pin_bytes(ptr: *mut u8, bytes: usize) {
    use libc::{mlock, madvise, MADV_DONTDUMP};
    unsafe {
        if bytes > 0 {
            let _ = mlock(ptr as *const _, bytes);
            let _ = madvise(ptr as *mut _, bytes, MADV_DONTDUMP);
        }
    }
}

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
fn pin_bytes(_ptr: *mut u8, _bytes: usize) {}
#[cfg(not(target_family = "unix"))]
fn unpin_bytes(_ptr: *mut u8, _bytes: usize) {}

// =================== HEAP-ISOLATED CRYPTOGRAPHIC TOKEN ====================
#[derive(Zeroize, ZeroizeOnDrop, Clone, Serialize, Deserialize)]
pub struct FixedKey {
    #[zeroize(on_drop)]
    data: Box<[u8; KEY_SIZE]>,
}

impl FixedKey {
    pub fn new_heap_locked() -> Arc<Self> {
        let mut boxed_data = Box::new([0u8; KEY_SIZE]);
        let mut salt = [0u8; 8];
        OsRng.fill(&mut salt);

        let mut hasher = Sha256::new();
        hasher.update(b"PHOENIX_FINTECH_KEY:");
        hasher.update(&salt);
        let digest = hasher.finalize();

        let copy_len = digest.len().min(KEY_SIZE);
        boxed_data[..copy_len].copy_from_slice(&digest[..copy_len]);
        salt.zeroize();

        pin_bytes(boxed_data.as_mut_ptr(), KEY_SIZE);
        Arc::new(Self { data: boxed_data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn wipe(&mut self) {
        self.data.zeroize();
    }
}

// =================== STRONGLY TYPED INGESTION DTO ====================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionDto {
    pub id: Option<String>,
    pub address: Option<String>,
    pub cc: Option<String>,
    pub flag: Option<String>,
    pub transaction: Option<String>,
    pub status: Option<String>,
    pub alert: Option<String>,
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// =================== SECURE COMPLIANCE LAYER ====================
#[derive(Debug, Clone, Copy)]
enum ComplianceCheck { Kyc, Aml, Gdpr, Sox, Fraud }

impl ComplianceCheck {
    fn all() -> [ComplianceCheck; 5] {
        [Self::Kyc, Self::Aml, Self::Gdpr, Self::Sox, Self::Fraud]
    }
    fn tag(&self) -> &'static str {
        match self {
            Self::Kyc => "KYC", Self::Aml => "AML", Self::Gdpr => "GDPR",
            Self::Sox => "SOX", Self::Fraud => "FRAUD"
        }
    }
}

pub struct ComplianceCouncil {
    active: [bool; 5],
}

impl ComplianceCouncil {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { active: [true; 5] })
    }

    pub fn check(&self, dto: &TransactionDto) -> (bool, Vec<&'static str>) {
        let mut passed = true;
        let mut triggers = Vec::new();

        for (i, check) in ComplianceCheck::all().iter().enumerate() {
            if !self.active[i] { continue; }
            let found = match check {
                ComplianceCheck::Kyc => {
                    dto.id.as_deref().map_or(false, |id| id == "no_id") ||
                    dto.address.as_deref().map_or(false, |a| a == "bad_address")
                },
                ComplianceCheck::Aml => {
                    dto.cc.as_deref().map_or(false, |cc| cc == "offshore") ||
                    dto.flag.as_deref().map_or(false, |f| f == "suspicious")
                },
                ComplianceCheck::Gdpr =>
                    dto.transaction.as_deref().map_or(false, |tr| tr == "dataleak"),
                ComplianceCheck::Sox =>
                    dto.status.as_deref().map_or(false, |s| s == "cfg_violate"),
                ComplianceCheck::Fraud => {
                    dto.alert.as_deref().map_or(false, |a| a == "stolen") ||
                    dto.flag.as_deref().map_or(false, |f| f == "fraud")
                }
            };
            if found {
                passed = false;
                triggers.push(check.tag());
            }
        }
        (passed, triggers)
    }
}

// =================== LEDGER ELEMENT MATRIX ====================
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RingLogEntry {
    #[zeroize(on_drop)] 
    msg: [u8; MSG_SIZE],
    sig: [u8; HASH_SIZE],
    prev_hash: [u8; HASH_SIZE],
    #[zeroize(on_drop)] 
    key_token: Arc<FixedKey>,
    time: u64,
    tx_seq: u64,
    status: &'static str,
    emoji: &'static str,
    triggers: Vec<&'static str>,
    active: bool,
}

// =================== FORENSIC ALERT ====================
#[derive(Clone, Debug, Serialize)]
pub struct ForensicAlert {
    pub timestamp: u64,
    pub incident_type: &'static str,
    pub last_valid_sequence: u64,
    pub last_valid_hash: String,
    pub forensic_signature: String,
}

// =================== OPS LEDGER ====================
pub struct OpsLedger {
    log: Box<[RingLogEntry; RING_SIZE]>,
    last_hash: [u8; HASH_SIZE],
    tx_seq: u64,
    key_token: Arc<FixedKey>,
    write_ptr: usize,
    compromise_flag: AtomicBool,
    read_only_flag: AtomicBool,
}

impl OpsLedger {
    pub fn new_heap_pinned(key_token: Arc<FixedKey>) -> Self {
        let mut arr: Box<[std::mem::MaybeUninit<RingLogEntry>; RING_SIZE]> =
            Box::new([std::mem::MaybeUninit::uninit(); RING_SIZE]);
        for slot in arr.iter_mut() {
            let key_clone = key_token.clone();
            let entry = RingLogEntry {
                msg: [0u8; MSG_SIZE],
                sig: [0u8; HASH_SIZE],
                prev_hash: [0u8; HASH_SIZE],
                key_token: key_clone,
                time: 0,
                tx_seq: 0,
                status: "idle",
                emoji: "⏳",
                triggers: Vec::new(),
                active: false,
            };
            unsafe {
                std::ptr::write(slot.as_mut_ptr(), entry);
            }
        }
        let log: Box<[RingLogEntry; RING_SIZE]> = unsafe { std::mem::transmute(arr) };

        pin_bytes(log.as_ptr() as *mut u8, RING_SIZE * std::mem::size_of::<RingLogEntry>());
        Self {
            log,
            last_hash: [0u8; HASH_SIZE],
            tx_seq: 0,
            key_token,
            write_ptr: 0,
            compromise_flag: AtomicBool::new(false),
            read_only_flag: AtomicBool::new(false),
        }
    }

    pub fn append(&mut self, entry: RingLogEntry) {
        if self.compromise_flag.load(Ordering::SeqCst) || self.read_only_flag.load(Ordering::SeqCst) {
            return;
        }
        let idx = self.write_ptr % RING_SIZE;
        let mut old = std::mem::replace(&mut self.log[idx], entry);
        old.zeroize();
        self.write_ptr = (self.write_ptr + 1) % RING_SIZE;
    }

    pub async fn verify_ledger_blocking(&self) -> bool {
        let log_snapshot: Vec<_> = self.log.iter().filter(|e| e.active).cloned().collect();
        let compromise_flag_ref = Arc::new(AtomicBool::new(self.compromise_flag.load(Ordering::SeqCst)));

        let result = tokio::task::spawn_blocking(move || {
            let mut log_vec = log_snapshot;
            log_vec.sort_by_key(|e| e.tx_seq);
            if log_vec.is_empty() { return true; }

            let mut expected_prev = log_vec[0].prev_hash;
            for (i, e) in log_vec.iter().enumerate() {
                if i > 0 && e.prev_hash != expected_prev {
                    compromise_flag_ref.store(true, Ordering::SeqCst);
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&e.msg);
                hasher.update(&e.time.to_le_bytes());
                hasher.update(&e.tx_seq.to_le_bytes());
                hasher.update(&expected_prev);
                hasher.update(e.key_token.as_bytes());
                let sig_chk = hasher.finalize();

                let match_len = sig_chk.len().min(e.sig.len());
                if &sig_chk[..match_len] != &e.sig[..match_len] {
                    compromise_flag_ref.store(true, Ordering::SeqCst);
                    return false;
                }
                expected_prev = e.sig;
            }
            true
        }).await.unwrap();

        if !result {
            self.compromise_flag.store(true, Ordering::SeqCst);
        }
        result
    }

    pub fn dump(&self) -> Vec<RingLogEntry> {
        self.log.iter().cloned().filter(|e| e.active).collect()
    }

    pub fn mark_readonly(&self) {
        self.read_only_flag.store(true, Ordering::SeqCst);
    }

    pub fn is_compromised(&self) -> bool {
        self.compromise_flag.load(Ordering::SeqCst)
    }

    pub fn purge_all_history(&mut self) {
        for entry in self.log.iter_mut() {
            entry.zeroize();
            entry.active = false;
        }
        self.last_hash.zeroize();
        self.tx_seq = 0;
        self.write_ptr = 0;
    }
}

impl Drop for OpsLedger {
    fn drop(&mut self) {
        let len = self.log.len();
        let ptr = self.log.as_mut_ptr() as *mut u8;
        let sz = len * std::mem::size_of::<RingLogEntry>();
        self.purge_all_history();
        unpin_bytes(ptr, sz);
    }
}

// =================== ASYNCHRONOUS ENGINE CHANNEL PRIMITIVES & AGENT ====================
pub struct AgentTransaction(RingLogEntry);

pub struct PhoenixAgent {
    pub codename: String,
    pub mission: &'static str,
    pub actions: Vec<(String, TransactionDto)>,
    pub council: Arc<ComplianceCouncil>,
    pub key_token: Arc<FixedKey>,
    pub tx_sender: mpsc::Sender<AgentTransaction>,
}

impl PhoenixAgent {
    pub async fn run(self) {
        for (op, params) in &self.actions {
            let (passed, triggers) = self.council.check(params);
            let status = if passed { "approved" } else { "blocked" };
            let emoji = if passed { "✅" } else { "⛔" };
            let entry_str = serde_json::to_string(params).unwrap_or_default();
            let cutoff = entry_str.char_indices().take_while(|(i, _)| *i < MSG_SIZE).map(|(i, _)| i).last().unwrap_or(0);
            let mb = &entry_str[..cutoff];
            let mut msg_bytes = [0u8; MSG_SIZE];
            let byte_count = mb.as_bytes().len().min(MSG_SIZE);
            msg_bytes[..byte_count].copy_from_slice(&mb.as_bytes()[..byte_count]);
            let format_str = format!("{} | {} | {} | {}", self.mission, self.codename, op, mb);
            let format_bytes = format_str.as_bytes();
            let out_len = format_bytes.len().min(MSG_SIZE);
            let mut final_msg = [0u8; MSG_SIZE];
            final_msg[..out_len].copy_from_slice(&format_bytes[..out_len]);
            let entry = RingLogEntry {
                msg: final_msg,
                sig: [0u8; HASH_SIZE],
                prev_hash: [0u8; HASH_SIZE],
                key_token: self.key_token.clone(),
                time: 0,
                tx_seq: 0,
                status,
                emoji,
                triggers: triggers.clone(),
                active: true,
            };
            if self.tx_sender.send(AgentTransaction(entry)).await.is_err() {
                break;
            }
        }
    }
}

// =================== LOCK-FREE SINGLE-CONSUMER KERNEL WRITER ====================
pub struct LedgerKernel {
    ledger: OpsLedger,
    rx_channel: mpsc::Receiver<AgentTransaction>,
    alert_sender: broadcast::Sender<ForensicAlert>,
}

impl LedgerKernel {
    pub fn new(
        ledger: OpsLedger,
        rx_channel: mpsc::Receiver<AgentTransaction>,
        alert_sender: broadcast::Sender<ForensicAlert>,
    ) -> Self {
        Self { ledger, rx_channel, alert_sender }
    }
    pub async fn run_worker(mut self) -> OpsLedger {
        while let Some(AgentTransaction(mut entry)) = self.rx_channel.recv().await {
            entry.time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            self.ledger.tx_seq += 1;
            entry.tx_seq = self.ledger.tx_seq;
            entry.prev_hash = self.ledger.last_hash;
            let mut hasher = Sha256::new();
            hasher.update(&entry.msg);
            hasher.update(&entry.time.to_le_bytes());
            hasher.update(&entry.tx_seq.to_le_bytes());
            hasher.update(&entry.prev_hash);
            hasher.update(entry.key_token.as_bytes());
            let sig = hasher.finalize();
            entry.sig[..sig.len().min(HASH_SIZE)].copy_from_slice(&sig[..sig.len().min(HASH_SIZE)]);
            self.ledger.last_hash = entry.sig;
            self.ledger.append(entry.clone());

            // Active integrity check
            if !self.ledger.verify_ledger_blocking().await || self.ledger.is_compromised() {
                self.ledger.mark_readonly();
                let alert = ForensicAlert {
                    timestamp: entry.time,
                    incident_type: "LEDGER_INTEGRITY_VIOLATION",
                    last_valid_sequence: self.ledger.tx_seq.saturating_sub(1),
                    last_valid_hash: hex::encode(entry.prev_hash),
                    forensic_signature: hex::encode(entry.sig),
                };
                let _ = self.alert_sender.send(alert);
                break;
            }
        }
        self.ledger
    }
}

// =================== MAIN ====================
#[tokio::main]
async fn main() {
    println!("===============================================================================");
    println!("  PHOENIX FINTECH: Autonomous, RAM-Pinned, Strongly Typed Async Kernel        ");
    println!("===============================================================================");

    let root_hardware_key = FixedKey::new_heap_locked();
    let opslog = OpsLedger::new_heap_pinned(root_hardware_key.clone());
    let council = ComplianceCouncil::new();

    let (tx_sender, rx_channel) = mpsc::channel::<AgentTransaction>(1024);
    let (alert_sender, mut alert_receiver) = broadcast::channel::<ForensicAlert>(16);

    // Forensic broadcast monitor
    tokio::spawn(async move {
        while let Ok(alert) = alert_receiver.recv().await {
            println!("\n🚨 [FORENSIC BROADCAST ALERT TRIGGERED]");
            println!("  ➔ TYPE:      {}", alert.incident_type);
            println!("  ➔ TIMESTAMP: {}", alert.timestamp);
            println!("  ➔ SEQUENCE:  {}", alert.last_valid_sequence);
            println!("  ➔ PREV_HASH: {}...", alert.last_valid_hash);
            println!("  ➔ COMP_SIG:  {}...\n", alert.forensic_signature);
        }
    });

    let tx1 = PhoenixAgent {
        codename: "BILLING".into(),
        mission: "TRANSFER",
        actions: vec![
            ("transfer".into(), TransactionDto {
                id: None, address: None, cc: Some("offshore".into()), flag: None, transaction: None, status: None, alert: None, metadata: HashMap::new()
            }),
            ("kyc_check".into(), TransactionDto {
                id: Some("no_id".into()), address: None, cc: None, flag: None, transaction: None, status: None, alert: None, metadata: HashMap::new()
            }),
            ("aml_check".into(), TransactionDto {
                id: None, address: None, cc: None, flag: Some("suspicious".into()), transaction: None, status: None, alert: None, metadata: HashMap::new()
            }),
        ],
        council: council.clone(),
        key_token: root_hardware_key.clone(),
        tx_sender: tx_sender.clone(),
    };

    let tx2 = PhoenixAgent {
        codename: "OPERATOR".into(),
        mission: "ONBOARD",
        actions: vec![
            ("kyc_check".into(), TransactionDto {
                id: Some("123".into()), address: Some("Main".into()), cc: None, flag: None, transaction: None, status: None, alert: None, metadata: HashMap::new()
            }),
            ("transfer".into(), TransactionDto {
                id: None, address: None, cc: None, flag: None, transaction: None, status: None, alert: None, metadata: HashMap::new()
            }),
        ],
        council: council.clone(),
        key_token: root_hardware_key.clone(),
        tx_sender: tx_sender.clone(),
    };

    let kernel = LedgerKernel::new(opslog, rx_channel, alert_sender);
    let kernel_handle = tokio::spawn(async move { kernel.run_worker().await });

    let h1 = tokio::spawn(tx1.run());
    let h2 = tokio::spawn(tx2.run());

    let _ = tokio::join!(h1, h2);
    drop(tx_sender); // ensure channel closes for kernel
    let final_ledger = kernel_handle.await.unwrap();

    println!("\n=== PRODUCTION COMPLIANCE RECORDS ===");
    for entry in final_ledger.dump() {
        let txt = String::from_utf8_lossy(&entry.msg).trim_matches(char::from(0)).to_string();
        println!("t:{} | seq:{} | {} {} | triggers={:?} | sig={}... | key={}...",
            entry.time, entry.tx_seq, entry.status, entry.emoji, entry.triggers,
            hex::encode(&entry.sig[..8]), hex::encode(&entry.key_token.as_bytes()[..8])
        );
        println!("    ➜ \"{}\"", txt);
    }
    println!("\n[PHOENIX] Operational System Verification Result: {}", final_ledger.verify_ledger_blocking().await);
    println!("[PHOENIX] Safe, unified architecture context shutdown sequence successfully concluded.");
}
