#![no_main]

use libfuzzer_sys::fuzz_target;

// Seal bodies and the public verifier must handle arbitrary input
// without panicking — auditors feed this thing hostile files.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sovereign_ledger::seal::parse_body(s);
        let _ = sovereign_ledger::seal::verify_public(std::io::BufReader::new(
            std::io::Cursor::new(data.to_vec()),
        ));
    }
});
