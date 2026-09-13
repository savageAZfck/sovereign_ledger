#![no_main]

use libfuzzer_sys::fuzz_target;
use sovereign_ledger::merkle::{ConsistencyProof, InclusionProof};

// Fuzz the proof verifiers: arbitrary sizes, indices, and node lists must
// never panic — only Ok/Err.
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut u64s = [0u64; 4];
    for (i, slot) in u64s.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[i * 8..i * 8 + 8]);
        *slot = u64::from_le_bytes(b);
    }
    let nodes: Vec<[u8; 32]> = data[32..]
        .chunks_exact(32)
        .map(|c| <[u8; 32]>::try_from(c).unwrap())
        .collect();
    if nodes.is_empty() {
        return;
    }

    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&nodes[0]);
    let root = *nodes.last().unwrap();

    let _ = InclusionProof {
        index: u64s[0],
        tree_size: u64s[1].min(u64::MAX / 2),
        path: nodes.clone(),
    }
    .verify(&leaf, &root);

    let _ = ConsistencyProof {
        old_size: u64s[2].min(u64::MAX / 2),
        new_size: u64s[3].min(u64::MAX / 2),
        nodes,
    }
    .verify(&leaf, &root);
});
