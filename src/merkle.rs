//! RFC 6962-style Merkle tree over the ledger's entry hashes.
//!
//! Leaves are the 32-byte `hash` fields of ledger entries. The tree gives
//! two proofs the flat chain cannot:
//! - **inclusion**: prove one entry is in the tree rooted at a given hash,
//!   in O(log n), without revealing or resending the whole ledger;
//! - **consistency**: prove the tree at size n extends the tree at size m,
//!   which is what makes append-only claims auditable between checkpoints.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, HASH_SIZE};

fn leaf_hash(d: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(d);
    h.finalize().into()
}

fn node_hash(l: &[u8; HASH_SIZE], r: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Largest power of two strictly smaller than n. Requires n >= 2.
fn largest_pow2_lt(n: u64) -> u64 {
    let mut k = 1u64;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Merkle Tree Hash over a slice of leaf inputs, per RFC 6962 §2.1.
/// MTH({}) = SHA256(""), MTH({d}) = SHA256(0x00 || d), and for n > 1 with
/// k the largest power of two < n: MTH = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
pub fn mth(d: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
    match d.len() {
        0 => Sha256::digest([]).into(),
        1 => leaf_hash(&d[0]),
        n => {
            let k = largest_pow2_lt(n as u64) as usize;
            node_hash(&mth(&d[..k]), &mth(&d[k..]))
        }
    }
}

fn audit_path_rec(m: u64, d: &[[u8; HASH_SIZE]], out: &mut Vec<[u8; HASH_SIZE]>) {
    let n = d.len() as u64;
    if n == 1 {
        return;
    }
    let k = largest_pow2_lt(n) as usize;
    if m < k as u64 {
        audit_path_rec(m, &d[..k], out);
        out.push(mth(&d[k..]));
    } else {
        audit_path_rec(m - k as u64, &d[k..], out);
        out.push(mth(&d[..k]));
    }
}

/// Audit path (sibling node list) proving leaf `m` is in MTH(d).
pub fn audit_path(m: u64, d: &[[u8; HASH_SIZE]]) -> Vec<[u8; HASH_SIZE]> {
    let mut out = Vec::new();
    if !d.is_empty() && m < d.len() as u64 {
        audit_path_rec(m, d, &mut out);
    }
    out
}

/// Inclusion proof for one leaf.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InclusionProof {
    pub index: u64,
    pub tree_size: u64,
    #[serde(with = "hash_vec")]
    pub path: Vec<[u8; HASH_SIZE]>,
}

/// Levels in the inclusion proof that sit strictly inside the subtree
/// covering both `index` and the last leaf.
fn inner_proof_size(index: u64, size: u64) -> u64 {
    64 - (index ^ (size - 1)).leading_zeros() as u64
}

/// Split an inclusion proof's expected length into (inner, border) parts —
/// below and above the point where the paths to `index` and `size-1`
/// diverge.
fn decomp_incl_proof(index: u64, size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    (inner as usize, (index >> inner).count_ones() as usize)
}

/// Chain proof hashes below the split: bit i of `index` selects ordering.
fn chain_inner(seed: [u8; HASH_SIZE], proof: &[[u8; HASH_SIZE]], index: u64) -> [u8; HASH_SIZE] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        acc = if (index >> i) & 1 == 0 {
            node_hash(&acc, h)
        } else {
            node_hash(h, &acc)
        };
    }
    acc
}

/// Like chain_inner, but keeps only left-side nodes — reconstructs the
/// earlier version of the subtree.
fn chain_inner_right(
    seed: [u8; HASH_SIZE],
    proof: &[[u8; HASH_SIZE]],
    index: u64,
) -> [u8; HASH_SIZE] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            acc = node_hash(h, &acc);
        }
    }
    acc
}

/// Chain proof hashes along the tree's right border (all left-side).
fn chain_border_right(seed: [u8; HASH_SIZE], proof: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
    let mut acc = seed;
    for h in proof {
        acc = node_hash(h, &acc);
    }
    acc
}

impl InclusionProof {
    /// Verify this proof against a trusted root and a known leaf.
    pub fn verify(&self, leaf: &[u8; HASH_SIZE], root: &[u8; HASH_SIZE]) -> Result<(), Error> {
        if self.tree_size == 0 || self.index >= self.tree_size {
            return Err(Error::Proof("proof index out of range".into()));
        }
        if self.tree_size == 1 {
            if !self.path.is_empty() {
                return Err(Error::Proof("proof too long".into()));
            }
            return if &leaf_hash(leaf) == root {
                Ok(())
            } else {
                Err(Error::Proof("root mismatch".into()))
            };
        }
        let (inner, border) = decomp_incl_proof(self.index, self.tree_size);
        if self.path.len() != inner + border {
            return Err(Error::Proof("wrong proof size".into()));
        }
        let mut r = chain_inner(leaf_hash(leaf), &self.path[..inner], self.index);
        r = chain_border_right(r, &self.path[inner..]);
        if &r == root {
            Ok(())
        } else {
            Err(Error::Proof("root mismatch".into()))
        }
    }
}

fn subproof(m: u64, d: &[[u8; HASH_SIZE]], b: bool, out: &mut Vec<[u8; HASH_SIZE]>) {
    let n = d.len() as u64;
    if m == n {
        if !b {
            out.push(mth(d));
        }
        return;
    }
    let k = largest_pow2_lt(n) as usize;
    if m <= k as u64 {
        subproof(m, &d[..k], b, out);
        out.push(mth(&d[k..]));
    } else {
        subproof(m - k as u64, &d[k..], false, out);
        out.push(mth(&d[..k]));
    }
}

/// Minimal consistency proof that MTH(D[0:m]) is a prefix of MTH(D[0:n]).
pub fn consistency_proof(m: u64, d: &[[u8; HASH_SIZE]]) -> Vec<[u8; HASH_SIZE]> {
    let n = d.len() as u64;
    if m == 0 || m == n || m > n {
        return Vec::new();
    }
    let mut out = Vec::new();
    subproof(m, d, true, &mut out);
    out
}

/// Consistency proof between two tree sizes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    #[serde(with = "hash_vec")]
    pub nodes: Vec<[u8; HASH_SIZE]>,
}

impl ConsistencyProof {
    /// Verify that `old_root` (the tree at `old_size`) is a prefix of
    /// `new_root` (the tree at `new_size`).
    pub fn verify(
        &self,
        old_root: &[u8; HASH_SIZE],
        new_root: &[u8; HASH_SIZE],
    ) -> Result<(), Error> {
        let (m, n) = (self.old_size, self.new_size);
        if m == n {
            return if self.nodes.is_empty() && old_root == new_root {
                Ok(())
            } else {
                Err(Error::Proof("invalid empty-tree consistency".into()))
            };
        }
        if m == 0 {
            return if self.nodes.is_empty() {
                Ok(())
            } else {
                Err(Error::Proof("non-empty proof for empty old tree".into()))
            };
        }
        if m > n {
            return Err(Error::Proof("old_size exceeds new_size".into()));
        }

        if self.nodes.is_empty() {
            return Err(Error::Proof("empty proof".into()));
        }

        // The proof is a suffix of the inclusion proof for leaf m-1 in the
        // size-n tree. Decompose it, then drop the `shift` levels that fall
        // inside the subtree the old root already commits to.
        let (mut inner, border) = decomp_incl_proof(m - 1, n);
        let shift = m.trailing_zeros() as usize;
        inner -= shift;

        // Unless m is itself that 2^shift subtree, proof[0] is the subtree
        // root that seeds both chains; otherwise the old root seeds them.
        let (seed, start) = if m == 1 << shift {
            (*old_root, 0usize)
        } else {
            (self.nodes[0], 1usize)
        };
        if self.nodes.len() != start + inner + border {
            return Err(Error::Proof("wrong proof size".into()));
        }
        let proof = &self.nodes[start..];

        let mask = (m - 1) >> shift;
        let mut hash1 = chain_inner_right(seed, &proof[..inner], mask);
        hash1 = chain_border_right(hash1, &proof[inner..]);
        if &hash1 != old_root {
            return Err(Error::Proof("old root mismatch".into()));
        }

        let mut hash2 = chain_inner(seed, &proof[..inner], mask);
        hash2 = chain_border_right(hash2, &proof[inner..]);
        if &hash2 == new_root {
            Ok(())
        } else {
            Err(Error::Proof("root mismatch".into()))
        }
    }
}

/// Hex serialization for `Vec<[u8; 32]>`.
mod hash_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let hexes: Vec<String> = v.iter().map(hex::encode).collect();
        hexes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let hexes: Vec<String> = Vec::deserialize(d)?;
        hexes
            .iter()
            .map(|h| {
                hex::decode(h)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                    .ok_or_else(|| serde::de::Error::custom("bad hash hex"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> [u8; HASH_SIZE] {
        let mut h = Sha256::new();
        h.update([i]);
        h.finalize().into()
    }

    #[test]
    fn mth_matches_rfc_definitions() {
        let empty: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(mth(&[]), empty);
        let d = leaf(0);
        assert_eq!(mth(&[d]), leaf_hash(&d));
        let two = [leaf(0), leaf(1)];
        assert_eq!(
            mth(&two),
            node_hash(&leaf_hash(&leaf(0)), &leaf_hash(&leaf(1)))
        );
    }

    #[test]
    fn inclusion_roundtrip_all_sizes() {
        for n in 1..=33usize {
            let leaves: Vec<_> = (0..n).map(|i| leaf(i as u8)).collect();
            let root = mth(&leaves);
            for m in 0..n {
                let path = audit_path(m as u64, &leaves);
                let proof = InclusionProof {
                    index: m as u64,
                    tree_size: n as u64,
                    path,
                };
                proof.verify(&leaves[m], &root).unwrap();
                // A different leaf must not verify.
                let wrong = leaf(200);
                assert!(proof.verify(&wrong, &root).is_err() || leaves[m] == wrong);
            }
        }
    }

    #[test]
    fn consistency_roundtrip() {
        let leaves: Vec<_> = (0..64).map(leaf).collect();
        for m in 1..64u64 {
            for n in (m + 1)..=64u64 {
                let d = &leaves[..n as usize];
                let proof = ConsistencyProof {
                    old_size: m,
                    new_size: n,
                    nodes: consistency_proof(m, d),
                };
                proof
                    .verify(&mth(&leaves[..m as usize]), &mth(d))
                    .unwrap_or_else(|e| panic!("m={m} n={n}: {e}"));
            }
        }
    }

    #[test]
    fn consistency_rejects_wrong_root() {
        let leaves: Vec<_> = (0..8).map(leaf).collect();
        let proof = ConsistencyProof {
            old_size: 4,
            new_size: 8,
            nodes: consistency_proof(4, &leaves),
        };
        let bad_old = mth(&leaves[..3]);
        assert!(proof.verify(&bad_old, &mth(&leaves)).is_err());
    }
}
