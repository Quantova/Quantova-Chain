// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::proto::put_varint;
use crate::sha256::sha256;

pub const DEPOSIT_VALUE_LEN: usize = 32 + 16 + 16;

fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    put_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafOp {
    pub prefix: Vec<u8>,
}

impl LeafOp {
    pub fn apply(&self, key: &[u8], value: &[u8]) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.prefix);
        buf.extend_from_slice(&length_prefixed(key));
        buf.extend_from_slice(&length_prefixed(&sha256(value)));
        sha256(&buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerOp {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

impl InnerOp {
    pub fn apply(&self, child: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.prefix);
        buf.extend_from_slice(child);
        buf.extend_from_slice(&self.suffix);
        sha256(&buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistenceProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub leaf: LeafOp,
    pub path: Vec<InnerOp>,
    pub store: Option<Box<ExistenceProof>>,
}

impl ExistenceProof {
    pub fn calculate_root(&self) -> [u8; 32] {
        let mut hash = self.leaf.apply(&self.key, &self.value);
        for op in &self.path {
            hash = op.apply(&hash);
        }
        hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deposit {
    pub source_ref: [u8; 32],
    pub asset_id: [u8; 16],
    pub amount: u128,
    pub recipient: [u8; 32],
}

pub fn wrap_store_layer(mut iavl: ExistenceProof, store_name: &[u8]) -> ([u8; 32], ExistenceProof) {
    let iavl_root = iavl.calculate_root();
    let store = ExistenceProof {
        key: store_name.to_vec(),
        value: iavl_root.to_vec(),
        leaf: LeafOp {
            prefix: vec![LEAF_MARKER],
        },
        path: Vec::new(),
        store: None,
    };
    let app_hash = store.calculate_root();
    iavl.store = Some(Box::new(store));
    (app_hash, iavl)
}

pub fn encode_deposit_value(recipient: &[u8; 32], asset_id: &[u8; 16], amount: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEPOSIT_VALUE_LEN);
    out.extend_from_slice(recipient);
    out.extend_from_slice(asset_id);
    out.extend_from_slice(&amount.to_le_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    RootMismatch,
    BadValueLength,
    MalformedProofOp,
    ForeignStoreKey,
    MissingStoreProof,
    ForeignStore,
    StoreRootMismatch,
}

const LEAF_MARKER: u8 = 0x00;
const MAX_OP_PREFIX_LEN: usize = 64;
const MAX_INNER_SUFFIX_LEN: usize = 64;
const MAX_PROOF_PATH_LEN: usize = 128;

fn canonical_ops(proof: &ExistenceProof) -> Result<(), ProofError> {
    if proof.path.len() > MAX_PROOF_PATH_LEN {
        return Err(ProofError::MalformedProofOp);
    }
    if proof.leaf.prefix.first() != Some(&LEAF_MARKER) {
        return Err(ProofError::MalformedProofOp);
    }
    if proof.leaf.prefix.len() > MAX_OP_PREFIX_LEN {
        return Err(ProofError::MalformedProofOp);
    }
    for op in &proof.path {
        if op.prefix.is_empty() || op.prefix.len() > MAX_OP_PREFIX_LEN {
            return Err(ProofError::MalformedProofOp);
        }
        if op.prefix.first() == Some(&LEAF_MARKER) {
            return Err(ProofError::MalformedProofOp);
        }
        if op.suffix.len() > MAX_INNER_SUFFIX_LEN {
            return Err(ProofError::MalformedProofOp);
        }
    }
    Ok(())
}

pub fn extract_deposit(
    app_hash: &[u8; 32],
    store_name: &[u8],
    store_prefix: &[u8],
    proof: &ExistenceProof,
) -> Result<Deposit, ProofError> {
    canonical_ops(proof)?;
    if proof.value.len() != DEPOSIT_VALUE_LEN {
        return Err(ProofError::BadValueLength);
    }
    if store_prefix.is_empty() || !proof.key.starts_with(store_prefix) {
        return Err(ProofError::ForeignStoreKey);
    }
    let iavl_root = proof.calculate_root();
    let store = proof
        .store
        .as_deref()
        .ok_or(ProofError::MissingStoreProof)?;
    canonical_ops(store)?;
    if store_name.is_empty() || store.key != store_name {
        return Err(ProofError::ForeignStore);
    }
    if store.value != iavl_root {
        return Err(ProofError::StoreRootMismatch);
    }
    if &store.calculate_root() != app_hash {
        return Err(ProofError::RootMismatch);
    }
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&proof.value[0..32]);
    let mut asset_id = [0u8; 16];
    asset_id.copy_from_slice(&proof.value[32..48]);
    let mut amount_bytes = [0u8; 16];
    amount_bytes.copy_from_slice(&proof.value[48..64]);
    let source_ref = sha256(&proof.key);

    Ok(Deposit {
        source_ref,
        asset_id,
        amount: u128::from_le_bytes(amount_bytes),
        recipient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_PREFIX: &[u8] = b"bridge/deposits/";
    const STORE_NAME: &[u8] = b"bridge";

    fn sample_proof() -> (ExistenceProof, Deposit) {
        let recipient = [0x51u8; 32];
        let asset_id = [0x22u8; 16];
        let amount: u128 = 4_200_000_000u128;
        let value = encode_deposit_value(&recipient, &asset_id, amount);
        let key = b"bridge/deposits/quantova-recipient".to_vec();

        let proof = ExistenceProof {
            key: key.clone(),
            value,
            leaf: LeafOp {
                prefix: vec![0x00, 0x02, 0x00],
            },
            path: vec![
                InnerOp {
                    prefix: vec![0x01, 0xaa],
                    suffix: vec![0xbb, 0xcc],
                },
                InnerOp {
                    prefix: vec![0x01],
                    suffix: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ],
            store: None,
        };
        let deposit = Deposit {
            source_ref: sha256(&key),
            asset_id,
            amount,
            recipient,
        };
        (proof, deposit)
    }

    #[test]
    fn a_valid_two_layer_proof_extracts_the_deposit() {
        let (iavl, expected) = sample_proof();
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Ok(expected)
        );
    }

    #[test]
    fn the_amount_is_carried_in_base_units() {
        let (iavl, _) = sample_proof();
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        let deposit = extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof).unwrap();
        assert_eq!(deposit.amount, 4_200_000_000u128);
    }

    #[test]
    fn a_proof_in_a_foreign_store_is_rejected() {
        let (iavl, _) = sample_proof();
        let (app_hash, proof) = wrap_store_layer(iavl, b"staking");
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::ForeignStore)
        );
    }

    #[test]
    fn a_single_layer_proof_without_a_store_is_rejected() {
        let (proof, _) = sample_proof();
        let app_hash = proof.calculate_root();
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::MissingStoreProof)
        );
    }

    #[test]
    fn a_tampered_value_breaks_the_store_root() {
        let (iavl, _) = sample_proof();
        let (app_hash, mut proof) = wrap_store_layer(iavl, STORE_NAME);
        proof.value[48] ^= 0x01;
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::StoreRootMismatch)
        );
    }

    #[test]
    fn a_tampered_key_breaks_the_store_root() {
        let (iavl, _) = sample_proof();
        let (app_hash, mut proof) = wrap_store_layer(iavl, STORE_NAME);
        proof.key[20] ^= 0x01;
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::StoreRootMismatch)
        );
    }

    #[test]
    fn a_tampered_inner_node_breaks_the_store_root() {
        let (iavl, _) = sample_proof();
        let (app_hash, mut proof) = wrap_store_layer(iavl, STORE_NAME);
        proof.path[1].suffix[0] ^= 0x01;
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::StoreRootMismatch)
        );
    }

    #[test]
    fn a_proof_against_a_foreign_app_hash_is_rejected() {
        let (iavl, _) = sample_proof();
        let (_app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        let foreign = [0x99u8; 32];
        assert_eq!(
            extract_deposit(&foreign, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::RootMismatch)
        );
    }

    #[test]
    fn a_key_outside_the_bridge_store_is_rejected() {
        let recipient = [0x51u8; 32];
        let asset_id = [0x22u8; 16];
        let value = encode_deposit_value(&recipient, &asset_id, 4_200_000_000u128);
        let iavl = ExistenceProof {
            key: b"staking/deposits/quantova-recipient".to_vec(),
            value,
            leaf: LeafOp {
                prefix: vec![0x00, 0x02, 0x00],
            },
            path: vec![
                InnerOp {
                    prefix: vec![0x01, 0xaa],
                    suffix: vec![0xbb, 0xcc],
                },
                InnerOp {
                    prefix: vec![0x01],
                    suffix: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ],
            store: None,
        };
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::ForeignStoreKey)
        );
    }

    #[test]
    fn an_empty_store_prefix_is_fail_closed() {
        let (iavl, _) = sample_proof();
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, b"", &proof),
            Err(ProofError::ForeignStoreKey)
        );
    }

    #[test]
    fn an_inner_op_posing_as_a_leaf_is_rejected() {
        let (mut iavl, _) = sample_proof();
        iavl.path[0].prefix = vec![0x00, 0xaa];
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::MalformedProofOp)
        );
    }

    #[test]
    fn a_leaf_without_the_leaf_marker_is_rejected() {
        let (mut iavl, _) = sample_proof();
        iavl.leaf.prefix = vec![0x01, 0x02, 0x00];
        let (app_hash, proof) = wrap_store_layer(iavl, STORE_NAME);
        assert_eq!(
            extract_deposit(&app_hash, STORE_NAME, STORE_PREFIX, &proof),
            Err(ProofError::MalformedProofOp)
        );
    }
}
