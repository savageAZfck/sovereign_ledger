use clap::{Parser, Subcommand, ValueEnum};
use sovereign_ledger::anchor::{write_checkpoint, Anchor, FileKeyAnchor, IdentityAgentAnchor, Tip};
use sovereign_ledger::import;
use sovereign_ledger::{Error, SovereignLedger};
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(
    name = "sovereign_ledger",
    version,
    about = "Hardened hash-chained audit ledger — tamper-evident, keyed, anchored"
)]
struct Cli {
    /// Path to the ledger file
    path: PathBuf,

    /// Key seed for epoch 0 (env: SOVEREIGN_LEDGER_KEY). Repeatable — each
    /// subsequent --key provides the next epoch's seed.
    #[arg(short = 'k', long = "key", global = true)]
    keys: Vec<String>,

    /// File with one key seed per line; line number is the key epoch
    #[arg(long = "keys-file", global = true)]
    keys_file: Option<PathBuf>,

    /// Emit machine-readable JSON where supported
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum ImportFormat {
    Badapple,
    Journald,
    Jsonl,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    Jsonl,
    Cef,
}

#[derive(Subcommand)]
enum Commands {
    /// Create or open a ledger
    Init,
    /// Append one event (body "-" reads stdin)
    Append {
        event_type: String,
        body: Option<String>,
        /// fsync before returning
        #[arg(long)]
        durable: bool,
    },
    /// Verify the entire hash chain
    Verify,
    /// Print the last N events, optionally following new appends
    Tail {
        #[arg(short = 'n', default_value_t = 10)]
        count: usize,
        /// Follow: keep printing as entries are appended
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Stream all events as JSONL or CEF (for SIEM pipelines)
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,
    },
    /// Verify a foreign ledger in its native format, then append every
    /// entry into this ledger. Output is built atomically (tmp + rename).
    Import {
        #[arg(long, value_enum)]
        from: ImportFormat,
        /// Source ledger path ("-" reads stdin)
        #[arg(long)]
        source: String,
        /// Source key file (e.g. Bad Apple slicks.key)
        #[arg(long)]
        source_key: Option<PathBuf>,
    },
    /// Rotate to a new signing key (records a key-rotation event)
    RotateKey {
        /// New epoch seed. If omitted and --keys-file is set, a random
        /// seed is generated and appended to the keys file.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Print the chain tip and Merkle root
    Root,
    /// Emit an RFC 6962 inclusion proof for entry <seq>
    Prove { seq: u64 },
    /// Verify an inclusion proof against a root (no ledger needed)
    CheckInclusion {
        /// Leaf hash (the entry's "hash" field)
        #[arg(long)]
        leaf: String,
        /// Trusted Merkle root
        #[arg(long)]
        root: String,
        /// Proof JSON file produced by `prove`
        #[arg(long)]
        proof: PathBuf,
    },
    /// Emit an RFC 6962 consistency proof: the tree at --old-size is a
    /// prefix of the current tree
    ProveConsistency {
        #[arg(long)]
        old_size: u64,
    },
    /// Verify a consistency proof between two roots
    CheckConsistency {
        #[arg(long)]
        old_root: String,
        #[arg(long)]
        new_root: String,
        #[arg(long)]
        proof: PathBuf,
    },
    /// Sign a checkpoint over the current tip
    Anchor {
        /// Identity agent socket (Secure Enclave; default
        /// /var/run/badapple/identity.sock)
        #[arg(long)]
        agent: Option<PathBuf>,
        /// Software HMAC key file (fallback when no agent is available)
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Generate a fresh anchor key file and use it
        #[arg(long)]
        gen_key_file: Option<PathBuf>,
        /// Checkpoint filename (default: <ledger>.checkpoint.json)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Genesis label recorded in the checkpoint
        #[arg(long, default_value = "sovereign-genesis-v1")]
        genesis: String,
    },
    /// Verify a checkpoint file
    AnchorVerify {
        /// Checkpoint JSON path
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        agent: Option<PathBuf>,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

fn gather_seeds(cli: &Cli) -> Result<Vec<Vec<u8>>, Error> {
    if let Some(f) = &cli.keys_file {
        let text = fs::read_to_string(f)?;
        return Ok(text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .map(String::into_bytes)
            .collect());
    }
    let mut seeds: Vec<Vec<u8>> = cli.keys.iter().map(|s| s.clone().into_bytes()).collect();
    if seeds.is_empty() {
        if let Ok(k) = std::env::var("SOVEREIGN_LEDGER_KEY") {
            seeds.push(k.into_bytes());
        }
    }
    Ok(seeds)
}

fn open(cli: &Cli) -> Result<SovereignLedger, Error> {
    let seeds = gather_seeds(cli)?;
    let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    // Keep the seeds alive for the duration of open by leaking nothing:
    // open_with_seeds derives keys immediately and does not retain refs.
    SovereignLedger::open_with_seeds(&cli.path, &refs)
}

fn read_body(body: Option<String>) -> Result<String, Error> {
    match body.as_deref() {
        None | Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s.trim_end_matches('\n').to_string())
        }
        Some(b) => Ok(b.to_string()),
    }
}

fn ledger_tip(cli: &Cli, genesis: &str) -> Result<Tip, Error> {
    let ledger = open(cli)?;
    ledger.verify()?;
    Ok(Tip {
        tip_hash: ledger.last_hash(),
        merkle_root: ledger.merkle_root()?,
        entry_count: ledger.len(),
        genesis: genesis.to_string(),
    })
}

fn pick_anchor(
    agent: Option<PathBuf>,
    key_file: Option<PathBuf>,
    gen_key_file: Option<PathBuf>,
) -> Result<Box<dyn Anchor>, Error> {
    if let Some(p) = gen_key_file {
        return Ok(Box::new(FileKeyAnchor::generate(p)?));
    }
    if let Some(p) = key_file {
        return Ok(Box::new(FileKeyAnchor::from_file(p)?));
    }
    let sock = agent.unwrap_or_else(|| PathBuf::from("/var/run/badapple/identity.sock"));
    let a = IdentityAgentAnchor::new(sock);
    if a.is_available() {
        Ok(Box::new(a))
    } else {
        Err(Error::Anchor(
            "no anchor available: identity agent socket absent; use --key-file <path> \
             for a software anchor or --gen-key-file <path> to create one"
                .into(),
        ))
    }
}

fn decode_hex32(s: &str) -> Result<[u8; 32], Error> {
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| Error::Verification(format!("not a 32-byte hex hash: {s}")))
}

fn run(cli: Cli) -> Result<(), Error> {
    match &cli.command {
        Commands::Init => {
            let ledger = open(&cli)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"path": cli.path, "entries": ledger.len(), "epoch": ledger.epoch()})
                );
            } else {
                println!("ledger ready at {}", cli.path.display());
            }
        }
        Commands::Append {
            event_type,
            body,
            durable,
        } => {
            let mut ledger = open(&cli)?;
            if *durable {
                ledger.set_durable(true);
            }
            let body = read_body(body.clone())?;
            let seq = ledger.append(event_type, &body)?;
            if cli.json {
                println!("{}", serde_json::json!({"seq": seq}));
            } else {
                println!("appended entry {seq}");
            }
        }
        Commands::Verify => {
            let ledger = open(&cli)?;
            ledger.verify()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "entries": ledger.len(),
                        "tip": hex::encode(ledger.last_hash()),
                        "merkle_root": hex::encode(ledger.merkle_root()?),
                    })
                );
            } else {
                println!("chain valid ({} entries)", ledger.len());
            }
        }
        Commands::Tail { count, follow } => {
            let ledger = open(&cli)?;
            let start = ledger.len().saturating_sub(*count as u64);
            for item in ledger.iter()? {
                let e = item?;
                if e.seq > start {
                    println!("{}", serde_json::to_string(&e)?);
                }
            }
            if *follow {
                drop(ledger);
                // Follow raw appends. The lock is released; tail is read-only.
                let mut file = fs::File::open(&cli.path)?;
                file.seek(SeekFrom::End(0))?;
                let mut reader = BufReader::new(file);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => std::thread::sleep(std::time::Duration::from_millis(200)),
                        Ok(_) => {
                            let t = line.trim();
                            if !t.is_empty() {
                                println!("{t}");
                            }
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                    let _ = std::io::stdout().flush();
                }
            }
        }
        Commands::Export { format } => {
            let ledger = open(&cli)?;
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for item in ledger.iter()? {
                let e = item?;
                match format {
                    ExportFormat::Jsonl => writeln!(out, "{}", serde_json::to_string(&e)?)?,
                    ExportFormat::Cef => writeln!(
                        out,
                        "CEF:0|SovereignLedger|sovereign_ledger|{}|{}|{}|5|rt={} msg={}",
                        env!("CARGO_PKG_VERSION"),
                        e.event_type.replace('|', "!"),
                        e.seq,
                        e.ts,
                        e.body.replace('\\', "\\\\").replace('=', "\\=")
                    )?,
                }
            }
        }
        Commands::Import {
            from,
            source,
            source_key,
        } => {
            // Build into a sibling temp file, then atomically replace.
            let tmp = cli.path.with_file_name(format!(
                "{}.{}.tmp",
                cli.path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                process::id()
            ));
            let tmp_lock = tmp.with_file_name(format!(
                "{}.lock",
                tmp.file_name().unwrap().to_string_lossy()
            ));
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&tmp_lock);

            let seeds = gather_seeds(&cli)?;
            let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
            let report = {
                let mut ledger = SovereignLedger::open_with_seeds(&tmp, &refs)?;
                let report = if source == "-" {
                    let stdin = std::io::stdin();
                    let reader = stdin.lock();
                    match from {
                        ImportFormat::Jsonl => import::import_jsonl(reader, &mut ledger)?,
                        ImportFormat::Journald => import::import_journald(reader, &mut ledger)?,
                        ImportFormat::Badapple => {
                            return Err(Error::Verification(
                                "badapple import needs --source <file>".into(),
                            ))
                        }
                    }
                } else {
                    let file = fs::File::open(source)?;
                    let reader = BufReader::new(file);
                    match from {
                        ImportFormat::Badapple => {
                            let key_path = source_key.clone().unwrap_or_else(|| {
                                Path::new(source)
                                    .parent()
                                    .unwrap_or(Path::new("."))
                                    .join("slicks.key")
                            });
                            let raw = fs::read(&key_path).unwrap_or_default();
                            let secrets = import::slicks_key_candidates(&raw);
                            import::import_badapple(reader, &secrets, &mut ledger)?
                        }
                        ImportFormat::Journald => import::import_journald(reader, &mut ledger)?,
                        ImportFormat::Jsonl => import::import_jsonl(reader, &mut ledger)?,
                    }
                };
                ledger.verify()?;
                ledger.sync()?;
                report
            };
            fs::rename(&tmp, &cli.path)?;
            let _ = fs::remove_file(&tmp_lock);
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"imported": report.entries, "source_tip": report.source_tip})
                );
            } else {
                println!("imported {} entries", report.entries);
            }
        }
        Commands::RotateKey { seed } => {
            let mut ledger = open(&cli)?;
            let seed_bytes: Vec<u8> = match (seed, &cli.keys_file) {
                (Some(s), _) => s.clone().into_bytes(),
                (None, Some(f)) => {
                    use rand::Rng;
                    let mut k = [0u8; 32];
                    rand::rngs::OsRng.fill(&mut k);
                    let s = hex::encode(k);
                    let mut file = fs::OpenOptions::new().append(true).open(f)?;
                    writeln!(file, "{s}")?;
                    file.sync_all()?;
                    s.into_bytes()
                }
                (None, None) => {
                    return Err(Error::Verification(
                        "rotate-key needs --seed or --keys-file".into(),
                    ))
                }
            };
            let epoch = ledger.rotate_key(&seed_bytes)?;
            if cli.json {
                println!("{}", serde_json::json!({"epoch": epoch}));
            } else {
                println!("rotated to key epoch {epoch}");
            }
        }
        Commands::Root => {
            let ledger = open(&cli)?;
            ledger.verify()?;
            println!(
                "{}",
                serde_json::json!({
                    "entries": ledger.len(),
                    "tip_hash": hex::encode(ledger.last_hash()),
                    "merkle_root": hex::encode(ledger.merkle_root()?),
                })
            );
        }
        Commands::Prove { seq } => {
            let ledger = open(&cli)?;
            let proof = ledger.prove_inclusion(*seq)?;
            let leaves = ledger.leaf_hashes()?;
            let leaf = leaves
                .get(proof.index as usize)
                .ok_or_else(|| Error::Proof("leaf missing".into()))?;
            println!(
                "{}",
                serde_json::json!({
                    "leaf": hex::encode(leaf),
                    "root": hex::encode(ledger.merkle_root()?),
                    "proof": proof,
                })
            );
        }
        Commands::CheckInclusion { leaf, root, proof } => {
            let leaf = decode_hex32(leaf)?;
            let root = decode_hex32(root)?;
            let proof: sovereign_ledger::merkle::InclusionProof =
                serde_json::from_str(&fs::read_to_string(proof)?)?;
            proof.verify(&leaf, &root)?;
            println!("inclusion verified");
        }
        Commands::ProveConsistency { old_size } => {
            let ledger = open(&cli)?;
            let proof = ledger.prove_consistency(*old_size)?;
            println!(
                "{}",
                serde_json::json!({
                    "old_root_hint": "root of tree at old_size",
                    "new_root": hex::encode(ledger.merkle_root()?),
                    "proof": proof,
                })
            );
        }
        Commands::CheckConsistency {
            old_root,
            new_root,
            proof,
        } => {
            let old_root = decode_hex32(old_root)?;
            let new_root = decode_hex32(new_root)?;
            let proof: sovereign_ledger::merkle::ConsistencyProof =
                serde_json::from_str(&fs::read_to_string(proof)?)?;
            proof.verify(&old_root, &new_root)?;
            println!("consistency verified");
        }
        Commands::Anchor {
            agent,
            key_file,
            gen_key_file,
            out,
            genesis,
        } => {
            let anchor = pick_anchor(agent.clone(), key_file.clone(), gen_key_file.clone())?;
            let tip = ledger_tip(&cli, genesis)?;
            let checkpoint = anchor.attest(&tip)?;
            let out_path = out.clone().unwrap_or_else(|| {
                cli.path.with_file_name(format!(
                    "{}.checkpoint.json",
                    cli.path.file_name().unwrap().to_string_lossy()
                ))
            });
            let dir = out_path.parent().unwrap_or(Path::new("."));
            let name = out_path.file_name().unwrap().to_string_lossy();
            let p = write_checkpoint(dir, &name, &checkpoint)?;
            println!("checkpoint signed at {}", p.display());
        }
        Commands::AnchorVerify {
            checkpoint,
            agent,
            key_file,
        } => {
            let c: sovereign_ledger::anchor::Checkpoint =
                serde_json::from_str(&fs::read_to_string(checkpoint)?)?;
            let anchor = pick_anchor(agent.clone(), key_file.clone(), None)?;
            if anchor.verify(&c)? {
                println!("checkpoint valid");
            } else {
                return Err(Error::Anchor("checkpoint signature invalid".into()));
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
