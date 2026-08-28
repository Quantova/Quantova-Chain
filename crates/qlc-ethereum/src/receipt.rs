// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::keccak::keccak256;
use crate::rlp::{self, Rlp};

pub const DEPOSIT_EVENT_SIGNATURE: &[u8] = b"QBridgeDeposit(bytes32,uint256,bytes16)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Malformed,
    NotSuccessful,
    NoDeposit,
    AmountOverflow,
    MultipleDeposits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDeposit {
    pub recipient: [u8; 32],
    pub amount: u128,
    pub asset_id: [u8; 16],
    pub log_index: u32,
}

pub fn deposit_topic() -> [u8; 32] {
    keccak256(DEPOSIT_EVENT_SIGNATURE)
}

fn strip_type_prefix(bytes: &[u8]) -> &[u8] {
    if !bytes.is_empty() && bytes[0] < 0xc0 {
        &bytes[1..]
    } else {
        bytes
    }
}

fn is_successful(status: &Rlp) -> bool {
    matches!(status.as_bytes(), Some(b) if b == [1u8])
}

pub fn extract_deposit(
    receipt_bytes: &[u8],
    deposit_contract: &[u8; 20],
) -> Result<RawDeposit, ReceiptError> {
    let body = strip_type_prefix(receipt_bytes);
    let decoded = rlp::decode(body).map_err(|_| ReceiptError::Malformed)?;
    let fields = decoded.as_list().ok_or(ReceiptError::Malformed)?;
    if fields.len() != 4 {
        return Err(ReceiptError::Malformed);
    }
    if !is_successful(&fields[0]) {
        return Err(ReceiptError::NotSuccessful);
    }
    let logs = fields[3].as_list().ok_or(ReceiptError::Malformed)?;
    let topic0 = deposit_topic();

    let mut found: Option<RawDeposit> = None;
    for (index, log) in logs.iter().enumerate() {
        let parts = match log.as_list() {
            Some(p) if p.len() == 3 => p,
            _ => return Err(ReceiptError::Malformed),
        };
        let address = parts[0].as_bytes().ok_or(ReceiptError::Malformed)?;
        if address != deposit_contract.as_slice() {
            continue;
        }
        let topics = parts[1].as_list().ok_or(ReceiptError::Malformed)?;
        if topics.len() != 2 {
            continue;
        }
        let t0 = topics[0].as_bytes().ok_or(ReceiptError::Malformed)?;
        if t0 != topic0.as_slice() {
            continue;
        }
        let recipient_bytes = topics[1].as_bytes().ok_or(ReceiptError::Malformed)?;
        if recipient_bytes.len() != 32 {
            return Err(ReceiptError::Malformed);
        }
        let data = parts[2].as_bytes().ok_or(ReceiptError::Malformed)?;
        if data.len() < 64 {
            return Err(ReceiptError::Malformed);
        }
        for &b in &data[0..16] {
            if b != 0 {
                return Err(ReceiptError::AmountOverflow);
            }
        }
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&data[16..32]);
        let amount = u128::from_be_bytes(amount_bytes);
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(recipient_bytes);
        let mut asset_id = [0u8; 16];
        asset_id.copy_from_slice(&data[32..48]);
        if found.is_some() {
            return Err(ReceiptError::MultipleDeposits);
        }
        found = Some(RawDeposit {
            recipient,
            amount,
            asset_id,
            log_index: index as u32,
        });
    }

    found.ok_or(ReceiptError::NoDeposit)
}

#[cfg(any(test, feature = "test-util"))]
pub mod fixtures {
    use super::*;

    pub fn encode_log(address: &[u8; 20], topics: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
        let topic_items: Vec<Vec<u8>> = topics.iter().map(|t| rlp::encode_bytes(t)).collect();
        rlp::encode_list(&[
            rlp::encode_bytes(address),
            rlp::encode_list(&topic_items),
            rlp::encode_bytes(data),
        ])
    }

    pub fn deposit_data(amount: u128, asset_id: &[u8; 16]) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[16..32].copy_from_slice(&amount.to_be_bytes());
        data[32..48].copy_from_slice(asset_id);
        data
    }

    pub fn deposit_receipt(
        contract: &[u8; 20],
        recipient: &[u8; 32],
        amount: u128,
        asset_id: &[u8; 16],
    ) -> Vec<u8> {
        let log = encode_log(
            contract,
            &[deposit_topic(), *recipient],
            &deposit_data(amount, asset_id),
        );
        rlp::encode_list(&[
            rlp::encode_bytes(&[1u8]),
            rlp::encode_uint(21000),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[log]),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn contract() -> [u8; 20] {
        [0xab; 20]
    }

    #[test]
    fn a_deposit_receipt_yields_the_recipient_and_amount() {
        let recipient = [0x5c; 32];
        let asset = [0x11; 16];
        let bytes = deposit_receipt(
            &contract(),
            &recipient,
            7_500_000_000_000_000_000u128,
            &asset,
        );
        let deposit = extract_deposit(&bytes, &contract()).unwrap();
        assert_eq!(deposit.recipient, recipient);
        assert_eq!(deposit.amount, 7_500_000_000_000_000_000u128);
        assert_eq!(deposit.asset_id, asset);
        assert_eq!(deposit.log_index, 0);
    }

    #[test]
    fn a_receipt_with_two_deposit_logs_is_refused() {
        let asset = [0x11; 16];
        let log_a = encode_log(&contract(), &[deposit_topic(), [0x5c; 32]], &deposit_data(10, &asset));
        let log_b = encode_log(&contract(), &[deposit_topic(), [0x6d; 32]], &deposit_data(20, &asset));
        let bytes = rlp::encode_list(&[
            rlp::encode_bytes(&[1u8]),
            rlp::encode_uint(21000),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[log_a, log_b]),
        ]);
        assert_eq!(
            extract_deposit(&bytes, &contract()),
            Err(ReceiptError::MultipleDeposits),
            "a receipt must not silently drop a second deposit log"
        );
    }

    #[test]
    fn a_typed_receipt_prefix_is_stripped() {
        let recipient = [0x5c; 32];
        let asset = [0x11; 16];
        let mut bytes = vec![0x02u8];
        bytes.extend_from_slice(&deposit_receipt(&contract(), &recipient, 42, &asset));
        let deposit = extract_deposit(&bytes, &contract()).unwrap();
        assert_eq!(deposit.amount, 42);
    }

    #[test]
    fn a_failed_receipt_is_refused() {
        let log = encode_log(
            &contract(),
            &[deposit_topic(), [0x5c; 32]],
            &deposit_data(1, &[0x11; 16]),
        );
        let bytes = rlp::encode_list(&[
            rlp::encode_bytes(&[]),
            rlp::encode_uint(21000),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[log]),
        ]);
        assert_eq!(
            extract_deposit(&bytes, &contract()),
            Err(ReceiptError::NotSuccessful)
        );
    }

    #[test]
    fn a_log_from_another_contract_is_not_a_deposit() {
        let bytes = deposit_receipt(&[0x99; 20], &[0x5c; 32], 1, &[0x11; 16]);
        assert_eq!(
            extract_deposit(&bytes, &contract()),
            Err(ReceiptError::NoDeposit)
        );
    }

    #[test]
    fn an_amount_above_the_base_unit_word_is_rejected() {
        let mut data = deposit_data(0, &[0x11; 16]);
        data[15] = 0x01;
        let log = encode_log(&contract(), &[deposit_topic(), [0x5c; 32]], &data);
        let bytes = rlp::encode_list(&[
            rlp::encode_bytes(&[1u8]),
            rlp::encode_uint(21000),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[log]),
        ]);
        assert_eq!(
            extract_deposit(&bytes, &contract()),
            Err(ReceiptError::AmountOverflow)
        );
    }

    #[test]
    fn the_event_topic_is_the_keccak_of_the_signature() {
        assert_eq!(
            deposit_topic(),
            keccak256(b"QBridgeDeposit(bytes32,uint256,bytes16)")
        );
    }
}
