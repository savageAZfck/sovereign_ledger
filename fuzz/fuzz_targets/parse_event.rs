#![no_main]

use libfuzzer_sys::fuzz_target;
use sovereign_ledger::Event;

// The ledger parser must reject or accept arbitrary bytes without panicking.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Event>(s);
        // The import path also touches raw lines.
        const GENESIS: &str =
            "0000000000000000000000000000000000000000000000000000000000000000";
        let _ = sovereign_ledger::import::verify_badapple_line(s, &[], GENESIS);
    }
});
