//! Conformance test: every vector in `testvectors/` must produce the
//! outcome declared in `expected.json` — under both keyed and public
//! verification where specified.
//!
//! Vectors are generated artifacts (see `examples/gen_testvectors.rs`);
//! this test pins their *semantics*: valid ledgers pass, corrupted
//! ledgers fail at the declared check.
use serde_json::Value;
use sovereign_ledger::seal;
use sovereign_ledger::SovereignLedger;
use std::io::BufReader;
use std::path::PathBuf;

fn tv(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testvectors")
        .join(name)
}

fn keyed_verify(file: &str, seeds: &[String]) -> Result<(), String> {
    // Open in a temp copy: opening a ledger creates a sibling lock file
    // and tightens permissions — neither belongs in the vectors dir.
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dst = tmp.path().join(file);
    std::fs::copy(tv(file), &dst).map_err(|e| e.to_string())?;
    let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_bytes()).collect();
    SovereignLedger::open_with_seeds(&dst, &refs)
        .and_then(|l| l.verify())
        .map_err(|e| e.to_string())
}

#[test]
fn vectors_match_expected() {
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(tv("expected.json")).expect("read expected.json"),
    )
    .expect("parse expected.json");

    for v in expected["vectors"].as_array().expect("vectors array") {
        let file = v["file"].as_str().unwrap();
        let data = std::fs::read(tv(file)).unwrap_or_else(|e| panic!("{file}: {e}"));

        if let Some(k) = v.get("keyed") {
            let seeds: Vec<String> = k["seeds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            let res = keyed_verify(file, &seeds);
            match k["expect"].as_str().unwrap() {
                "ok" => assert!(res.is_ok(), "{file}: keyed verify should pass: {res:?}"),
                err => {
                    let e = res.expect_err(&format!("{file}: keyed verify should fail"));
                    assert!(
                        e.contains(err),
                        "{file}: keyed verify expected '{err}', got '{e}'"
                    );
                }
            }
        }

        if let Some(p) = v.get("public") {
            let res = seal::verify_public(BufReader::new(data.as_slice()));
            match p["expect"].as_str().unwrap() {
                "ok" => {
                    let r = res.unwrap_or_else(|e| panic!("{file}: public verify: {e}"));
                    if let Some(seg) = p.get("segments") {
                        assert_eq!(r.segments, seg.as_u64().unwrap(), "{file}: segment count");
                    }
                }
                "no_seals" => {
                    let r = res.unwrap_or_else(|e| panic!("{file}: public verify: {e}"));
                    assert_eq!(r.segments, 0, "{file}: expected no seals");
                }
                "error" => {
                    assert!(res.is_err(), "{file}: public verify should fail");
                }
                err => {
                    let e = res.expect_err(&format!("{file}: public verify should fail"));
                    assert!(
                        e.to_string().contains(err),
                        "{file}: public verify expected '{err}', got '{e}'"
                    );
                }
            }
        }
    }
}
