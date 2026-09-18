//! JavaScript bindings for the in-browser public verifier.
//!
//! Built with `--no-default-features --features wasm` and packaged via
//! `wasm-pack` / `wasm-bindgen` (see `web/`). Exposes the same public
//! verification path the CLI's `verify --public` uses — no filesystem,
//! no key material, no network.
use wasm_bindgen::prelude::*;

/// Verify a JSONL ledger string with no key material.
///
/// Sealed segments are fully verified — entry MACs under revealed keys,
/// Merkle roots, chain tips, seal ordering, anchor signatures. The
/// trailing unsealed segment is linkage-checked and counted separately.
///
/// Returns the `PublicVerifyReport` serialized as JSON. Throws a string
/// describing the failure (invalid line, broken chain, bad seal, …)
/// when verification fails — an error *is* the verdict.
#[wasm_bindgen]
pub fn verify_ledger_public(input: &str) -> Result<String, JsValue> {
    let report = crate::seal::verify_public(input.as_bytes())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}
