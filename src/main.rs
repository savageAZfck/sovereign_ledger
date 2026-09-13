use std::env;
use std::process;

fn usage() {
    eprintln!("Usage: sovereign_ledger <ledger-path> <command> [args]");
    eprintln!("Commands:");
    eprintln!("  init                         create or open a ledger");
    eprintln!("  append <event-type> <body>   append one event");
    eprintln!("  verify                       verify the hash chain");
    eprintln!("  tail [n]                     print the last n events (default 10)");
    eprintln!("Environment:");
    eprintln!("  SOVEREIGN_LEDGER_KEY         optional 32-byte seed for key derivation");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let path = &args[1];
    let command = &args[2];
    let seed = env::var("SOVEREIGN_LEDGER_KEY")
        .ok()
        .map(|s| s.into_bytes());
    let seed_ref = seed.as_deref();

    let mut ledger = match sovereign_ledger::SovereignLedger::new(path, seed_ref) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error opening ledger: {e}");
            process::exit(1);
        }
    };

    if ledger.is_compromised() {
        eprintln!("warning: existing ledger shows a broken chain");
    }

    match command.as_str() {
        "init" => {
            println!("ledger ready at {path}");
        }
        "append" => {
            if args.len() < 5 {
                usage();
            }
            let event_type = &args[3];
            let body = &args[4];
            match ledger.append(event_type, body) {
                Ok(seq) => println!("appended entry {seq}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
        }
        "verify" => match ledger.verify() {
            Ok(()) => {
                println!("chain valid");
            }
            Err(e) => {
                eprintln!("verification failed: {e}");
                process::exit(1);
            }
        },
        "tail" => {
            let n = if args.len() >= 4 {
                args[3].parse::<usize>().unwrap_or(10)
            } else {
                10
            };
            match ledger.dump() {
                Ok(events) => {
                    let start = events.len().saturating_sub(n);
                    for e in &events[start..] {
                        println!("{}", serde_json::to_string(e).unwrap());
                    }
                }
                Err(e) => {
                    eprintln!("error dumping ledger: {e}");
                    process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}
