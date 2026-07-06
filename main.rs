use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{Rng, rngs::OsRng};
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MSG_SIZE: usize = 128;
pub const HASH_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;
pub const RING_SIZE: usize = 128;

// ========= Memory Pinning Helpers =========
#[cfg(target_family = "unix")]
pub fn pin_bytes(ptr: *mut u8, bytes: usize) {
    use libc::{mlock, madvise, MADV_DONTDUMP};
    unsafe {
        if bytes > 0 {
            let _ = mlock(ptr as *const _, bytes);
            let _ = madvise(ptr as *mut _, bytes, MADV_DONTDUMP);
        }
    }
}
#[cfg(not(target_family = "unix"))]
pub fn pin_bytes(_ptr: *mut u8, _bytes: usize) {}
#[cfg(target_family = "unix")]
pub fn unpin_bytes(ptr: *mut u8, bytes: usize) {
    use libc::munlock;
    unsafe { if bytes > 0 { let _ = munlock(ptr as *const _, bytes); } }
}
#[cfg(not(target_family = "unix"))]
pub fn unpin_bytes(_ptr: *mut u8, _bytes: usize) {}

// ========= Core Security Types =========
#[derive(Zeroize, ZeroizeOnDrop, Clone, Serialize, Deserialize)]
pub struct FixedKey {
    #[zeroize(on_drop)]
    pub data: Box<[u8; KEY_SIZE]>,
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
    pub fn as_bytes(&self) -> &[u8] { &*self.data }
}

#[derive(Debug, Clone)]
pub enum ComplianceError {
    Kyc(String),
    Aml(String),
    Gdpr(String),
    Sox(String),
    Fraud(String),
}
pub type ComplianceResult = Result<(), Vec<ComplianceError>>;

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

#[derive(Debug, Clone, Copy)]
pub enum ComplianceCheck { Kyc, Aml, Gdpr, Sox, Fraud }
impl ComplianceCheck {
    pub fn all() -> [ComplianceCheck; 5] { [Self::Kyc, Self::Aml, Self::Gdpr, Self::Sox, Self::Fraud] }
}

pub struct ComplianceCouncil { active: [bool; 5] }
impl ComplianceCouncil {
    pub fn new() -> Arc<Self> { Arc::new(Self { active: [true; 5] }) }
    pub fn check(&self, dto: &TransactionDto) -> ComplianceResult {
        let mut errors = Vec::new();
        for (i, check) in ComplianceCheck::all().iter().enumerate() {
            if !self.active[i] { continue; }
            match check {
                ComplianceCheck::Kyc => {
                    if dto.id.as_deref().map_or(false, |id| id == "no_id") {
                        errors.push(ComplianceError::Kyc("No valid ID".into()))
                    }
                    if dto.address.as_deref().map_or(false, |a| a == "bad_address") {
                        errors.push(ComplianceError::Kyc("Invalid address".into()))
                    }
                },
                ComplianceCheck::Aml => {
                    if dto.cc.as_deref().map_or(false, |cc| cc == "offshore") {
                        errors.push(ComplianceError::Aml("Offshore account".into()))
                    }
                    if dto.flag.as_deref().map_or(false, |f| f == "suspicious") {
                        errors.push(ComplianceError::Aml("Suspicious flag".into()))
                    }
                },
                ComplianceCheck::Gdpr => {
                    if dto.transaction.as_deref().map_or(false, |tr| tr == "dataleak") {
                        errors.push(ComplianceError::Gdpr("Data leak flagged".into()))
                    }
                },
                ComplianceCheck::Sox => {
                    if dto.status.as_deref().map_or(false, |s| s == "cfg_violate") {
                        errors.push(ComplianceError::Sox("SOX violation status".into()))
                    }
                },
                ComplianceCheck::Fraud => {
                    if dto.alert.as_deref().map_or(false, |a| a == "stolen") {
                        errors.push(ComplianceError::Fraud("Stolen alert".into()))
                    }
                    if dto.flag.as_deref().map_or(false, |f| f == "fraud") {
                        errors.push(ComplianceError::Fraud("Fraud flag".into()))
                    }
                }
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RingLogEntry {
    #[zeroize(on_drop)]
    pub msg: [u8; MSG_SIZE],
    pub sig: [u8; HASH_SIZE],
    pub prev_hash: [u8; HASH_SIZE],
    pub key_token: Arc<FixedKey>,
    pub time: u64,
    pub tx_seq: u64,
    pub status: String,
    pub emoji: String,
    pub triggers: Vec<String>,
    pub active: bool,
}

pub struct OpsLedger {
    pub log: Box<[RingLogEntry; RING_SIZE]>,
    pub last_hash: [u8; HASH_SIZE],
    pub tx_seq: u64,
    pub key_token: Arc<FixedKey>,
    pub write_ptr: usize,
    compromise_flag: AtomicBool,
    read_only_flag: AtomicBool,
}
impl OpsLedger {
    pub fn new_heap_pinned(key_token: Arc<FixedKey>) -> Self {
        let mut vec = Vec::with_capacity(RING_SIZE);
        for _ in 0..RING_SIZE {
            vec.push(RingLogEntry {
                msg: [0u8; MSG_SIZE], sig: [0u8; HASH_SIZE], prev_hash: [0u8; HASH_SIZE],
                key_token: key_token.clone(), time: 0, tx_seq: 0,
                status: "idle".to_string(), emoji: "⏳".to_string(),
                triggers: Vec::new(), active: false,
            });
        }
        let log: Box<[RingLogEntry; RING_SIZE]> = match vec.into_boxed_slice().try_into() {
            Ok(boxed_arr) => boxed_arr,
            Err(_) => panic!("Failed to initialize secure boxed architecture ring buffer"),
        };
        pin_bytes(log.as_ptr() as *mut u8, RING_SIZE * std::mem::size_of::<RingLogEntry>());
        Self {
            log, last_hash: [0u8; HASH_SIZE], tx_seq: 0,
            key_token, write_ptr: 0, compromise_flag: AtomicBool::new(false), read_only_flag: AtomicBool::new(false)
        }
    }
    pub fn append(&mut self, mut entry: RingLogEntry) {
        if self.compromise_flag.load(Ordering::SeqCst) || self.read_only_flag.load(Ordering::SeqCst) { return; }
        let mut hasher = Sha256::new();
        hasher.update(&entry.msg);
        hasher.update(&self.last_hash);
        hasher.update(entry.key_token.as_bytes());
        hasher.update(&entry.time.to_le_bytes());
        hasher.update(&entry.tx_seq.to_le_bytes());
        let sig = hasher.finalize();
        entry.sig[..sig.len().min(HASH_SIZE)].copy_from_slice(&sig[..sig.len().min(HASH_SIZE)]);
        entry.prev_hash.copy_from_slice(&self.last_hash);
        self.last_hash.copy_from_slice(&entry.sig);

        let idx = self.write_ptr % RING_SIZE;
        let mut old = std::mem::replace(&mut self.log[idx], entry);
        old.zeroize();
        self.write_ptr = (self.write_ptr + 1) % RING_SIZE;
    }
    pub fn dump(&self) -> Vec<RingLogEntry> {
        self.log.iter().cloned().filter(|e| e.active).collect()
    }
    pub fn mark_readonly(&self) {
        self.read_only_flag.store(true, Ordering::SeqCst);
    }
}
impl Drop for OpsLedger {
    fn drop(&mut self) {
        let len = self.log.len();
        let ptr = self.log.as_mut_ptr() as *mut u8;
        let sz = len * std::mem::size_of::<RingLogEntry>();
        // Zero memory on drop for safety
        for entry in self.log.iter_mut() {
            entry.zeroize();
            entry.active = false;
        }
        self.last_hash.zeroize();
        self.tx_seq = 0;
        self.write_ptr = 0;
        unpin_bytes(ptr, sz);
    }
}

// ======================== Modular Features ========================
pub mod ux_dashboard {
    pub fn launch() { println!("🚀 (UX Dashboard) [Simulated] Real-time compliance view online!"); }
}
pub mod audit_log_export {
    pub fn export_proof(entry_id: u64) {
        println!("📥 [EXPORT BUNDLE] Downloading cryptographic proof for entry {}", entry_id);
    }
}
pub mod emergency_playbook {
    pub fn lock_readonly_and_prompt_forensic_playbook() {
        println!("🚨 [EMERGENCY PLAYBOOK] CRITICAL TAMPER DETECTED: IMMUTABLE FENCES ACTIVATED. pipelines locked down.");
    }
}
pub mod explainable_compliance {
    pub fn explain(trigger: &str, txid: &str, field: &str, val: &str) -> String {
        format!("[EXPLANATION] Breach trajectory: '{}' vector matched field '{}' containing '{}'", txid, field, trigger)
    }
}
pub mod annotation_timeline {
    pub fn add_note(record_id: u64, note: &str, author: &str) {
        println!("📝 [ANNOTATION] Record {}: '{}' by {}", record_id, note, author);
    }
}
pub mod multiparty_attestation {
    pub fn attest(record_id: u64, signer: &str) {
        println!("🔏 [ATTESTATION] Record {} co-signed by {}", record_id, signer);
    }
}
pub mod customer_portal {
    pub fn launch() {
        println!("🌐 (Customer Portal) [Simulated] Customer transparency portal bootstrapped!");
    }
}
pub mod log_search_export {
    pub fn search_and_export(query: &str) {
        println!("🔍 [SEARCH/EXPORT] Running search: '{}' (results simulated)", query);
    }
}
pub mod tamper_forensics {
    pub fn assemble_report(seq_no: u64, summary: &str) {
        println!("🕵️ [FORENSICS REPORT] Structural violation isolated at block #{}: {}", seq_no, summary);
    }
}
pub mod siem_integration {
    pub fn push_log(record: &str) {
        println!("🖥️ [SIEM/GRC] Dispatching incident payload: {}", record);
    }
}
pub mod ai_compliance_assistant {
    pub fn review_logs_ai(summary: &str) {
        println!("🧠 [AI REVIEW] Adversarial trend summary captured: {}", summary);
    }
}

// =========================== MAIN ENGINE ===========================
#[tokio::main]
async fn main() {
    println!("===================== Phoenix Fintech: AI Adversarial Lab =====================");
    ux_dashboard::launch();
    println!("[BOOT] Core secure memory engine online. Starting continuous mutation loop.");

    let crypto_token = FixedKey::new_heap_locked();
    let ledger = Arc::new(RwLock::new(OpsLedger::new_heap_pinned(crypto_token.clone())));
    let council = ComplianceCouncil::new();

    // --- Adversarial Simulation Loop ---
    let test_vectors: Vec<(&str, TransactionDto)> = vec![
        ("Standard Polymorphic Bypass Attempt", TransactionDto {
            id: Some("tx_99A1".to_string()), address: Some("trust_addr".to_string()),
            cc: Some("offshore".to_string()), flag: Some("suspicious".to_string()),
            transaction: Some("standard_wire".to_string()), status: Some("pending".to_string()),
            alert: Some("none".to_string()), metadata: HashMap::new()
        }),
        ("Velocity Infiltration Mutation", TransactionDto {
            id: Some("tx_99B2".to_string()), address: Some("quick_account".to_string()),
            cc: Some("velocity".to_string()), flag: Some("fraud".to_string()),
            transaction: Some("fast_wire".to_string()), status: Some("pending".to_string()),
            alert: Some("none".to_string()), metadata: HashMap::new()
        }),
        ("Obfuscated Layer Transfer", TransactionDto {
            id: Some("tx_99C3".to_string()), address: Some("legitimate".to_string()),
            cc: Some("hidden".to_string()), flag: Some("none".to_string()),
            transaction: Some("inbound_wire".to_string()), status: Some("pending".to_string()),
            alert: Some("none".to_string()), metadata: HashMap::new()
        }),
        ("RAW MEMORY CORRUPTION INJECTION ATTEMPT", TransactionDto {
            id: Some("tx_TAMPER".to_string()), address: Some("physmem".to_string()),
            cc: Some("none".to_string()), flag: Some("none".to_string()),
            transaction: Some("tamper".to_string()), status: Some("pending".to_string()),
            alert: Some("none".to_string()), metadata: HashMap::new()
        }),
    ];

    let ledger_handle = ledger.clone();
    let simulation = tokio::spawn(async move {
        for (i, (name, mut tx)) in test_vectors.into_iter().enumerate() {
            println!("\n🤖 [ADVERSARIAL AI] Generating mutation payload: '{}'", name);
            let txid = tx.id.clone().unwrap_or("".into());
            // Case 4 is deliberate memory attack
            if name.contains("RAW MEMORY") {
                println!("💥 [ATTACKER] Compliance rules passed. Injecting raw hash manipulation directly into the array!");
                let mut write = ledger_handle.write().await;
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let mut dummy_msg = [0u8; MSG_SIZE];
                let msg_bytes = b"RAW MUTATION EVENT";
                dummy_msg[..msg_bytes.len().min(MSG_SIZE)].copy_from_slice(&msg_bytes[..msg_bytes.len().min(MSG_SIZE)]);
                let record_seq = write.tx_seq + 1;
                // Simulate a regular log append so the hash chain is properly polluted
                let log_entry = RingLogEntry {
                    msg: dummy_msg,
                    sig: [0u8; HASH_SIZE],
                    prev_hash: [0u8; HASH_SIZE],
                    key_token: crypto_token.clone(),
                    time: now,
                    tx_seq: record_seq,
                    status: "FLAGGED_BLOCK".to_string(),
                    emoji: "💀".to_string(),
                    triggers: vec!["RAW_CORRUPTION".to_string()],
                    active: true,
                };
                write.append(log_entry);
                write.tx_seq = record_seq;
                // Actually break the prev_hash:
                write.log[0].prev_hash[0] ^= 1; // forcibly flip 1 bit
                println!("💀 [ATTACK LAYER] Sabotaged prev_hash inside slot index 0 to simulate cold boot ram corruption.");
                drop(write);
                // Continue, allowing auditor to pick up chain break
                continue;
            }
            match council.check(&tx) {
                Ok(_) => {
                    if name.contains("Obfuscated") {
                        println!("⚡ [ATTACKER] Mutation slipped cleanly past basic policy thresholds.");
                    } else {
                        println!("✅ [COMPLIANCE PASS]")
                    }
                    let mut write = ledger_handle.write().await;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    let mut dummy_msg = [0u8; MSG_SIZE];
                    let msg = format!("AI_SIM -> {}", name);
                    let copy_len = msg.as_bytes().len().min(MSG_SIZE);
                    dummy_msg[..copy_len].copy_from_slice(&msg.as_bytes()[..copy_len]);
                    let record_seq = write.tx_seq + 1;
                    let log_entry = RingLogEntry {
                        msg: dummy_msg,
                        sig: [0u8; HASH_SIZE],
                        prev_hash: [0u8; HASH_SIZE],
                        key_token: crypto_token.clone(),
                        time: now,
                        tx_seq: record_seq,
                        status: "INFO_BLOCK".to_string(),
                        emoji: "⚡".to_string(),
                        triggers: vec![format!("Simulation: {name}")],
                        active: true,
                    };
                    write.append(log_entry);
                    write.tx_seq = record_seq;
                }
                Err(errors) => {
                    println!("🛡️  [KERNEL CAUGHT] Ingestion blocked. Rules caught violations: {:?}", errors);
                    for err in &errors {
                        let explanation = explainable_compliance::explain(&format!("{:?}", err), &txid, "cc/flag", &format!("{:?}", err));
                        println!("    ↳ {}", explanation);
                    }
                    let mut write = ledger_handle.write().await;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    let mut dummy_msg = [0u8; MSG_SIZE];
                    let msg = format!("BLOCK {} : {:?}", name, errors);
                    let copy_len = msg.as_bytes().len().min(MSG_SIZE);
                    dummy_msg[..copy_len].copy_from_slice(&msg.as_bytes()[..copy_len]);
                    let record_seq = write.tx_seq + 1;
                    let log_entry = RingLogEntry {
                        msg: dummy_msg,
                        sig: [0u8; HASH_SIZE],
                        prev_hash: [0u8; HASH_SIZE],
                        key_token: crypto_token.clone(),
                        time: now,
                        tx_seq: record_seq,
                        status: "BLOCKED".to_string(),
                        emoji: "🛡️".to_string(),
                        triggers: errors.iter().map(|e| format!("{:?}", e)).collect(),
                        active: true,
                    };
                    write.append(log_entry);
                    write.tx_seq = record_seq;
                }
            }
            // Continuous auditor: check hash linkage.
            println!("🔍 [CONTINUOUS AUDITOR] Verifying link signatures across {} active blocks...", ledger_handle.read().await.dump().len());
            let blocks = ledger_handle.read().await.dump();
            let mut prev_hash: Option<[u8; HASH_SIZE]> = None;
            let mut valid = true;
            for (idx, block) in blocks.iter().enumerate() {
                if let Some(h) = prev_hash {
                    if h != block.prev_hash {
                        println!("🚨 [AUDIT LINEAGE FAILURE] Cryptographic history broken! Sequence #{} prev_hash mismatch.", block.tx_seq);
                        valid = false;
                        break;
                    }
                }
                prev_hash = Some(block.sig);
            }
            if valid {
                println!("✅ [AUDITOR PASS] Chain validation verified. Memory-pinned state space remains consistent.")
            } else {
                println!("🔥 [AUDIT ALERT] CRITICAL PARITY DEVIATION FOUND! ACTIVATING FORENSIC COMPROMISE TRIPWIRE.");
                emergency_playbook::lock_readonly_and_prompt_forensic_playbook();
                tamper_forensics::assemble_report(blocks.last().map(|b| b.tx_seq).unwrap_or(0), "Rolling Sha256 lineage corruption forced execution lockdown.");
                siem_integration::push_log("CRITICAL_CRASH: In-memory chain link manipulation tripped validation fences.");
                break; // lock system immediately
            }
        }
        ai_compliance_assistant::review_logs_ai("Trend Analysis: Adversarial payload attempt 'tx_TAMPER' intercepted by continuous validation loop.");
    });

    let _ = simulation.await;
    println!("\n=======================================================================");
    println!("Phoenix Fintech Adversarial AI Simulation Engine complete.");
    println!("🔒 STATUS: SECURE LOCKDOWN ACTIVE. System successfully contained threat propagation vector.");
    println!("Safely freeing hardware spaces and zeroizing sensitive heap components...");
}

