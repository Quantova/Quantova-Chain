// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{StarkStatement, StatementKind};

pub const SOURCE_REF_LEN: usize = 32;
pub const ASSET_ID_LEN: usize = 16;
pub const RECIPIENT_LEN: usize = 32;
pub const ANCHOR_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventClaim {
    pub source_ref: [u8; SOURCE_REF_LEN],
    pub asset_id: [u8; ASSET_ID_LEN],
    pub amount: u128,
    pub recipient: [u8; RECIPIENT_LEN],
}

impl EventClaim {
    pub const ENCODED_LEN: usize = SOURCE_REF_LEN + ASSET_ID_LEN + 16 + RECIPIENT_LEN;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_ref);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.recipient);
    }

    fn decode_from(bytes: &[u8]) -> Option<EventClaim> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut source_ref = [0u8; SOURCE_REF_LEN];
        source_ref.copy_from_slice(&bytes[0..32]);
        let mut asset_id = [0u8; ASSET_ID_LEN];
        asset_id.copy_from_slice(&bytes[32..48]);
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&bytes[48..64]);
        let mut recipient = [0u8; RECIPIENT_LEN];
        recipient.copy_from_slice(&bytes[64..96]);
        Some(EventClaim {
            source_ref,
            asset_id,
            amount: u128::from_le_bytes(amount_bytes),
            recipient,
        })
    }
}

pub fn is_proof_corridor(kind: StatementKind) -> bool {
    matches!(
        kind,
        StatementKind::BitcoinSpv
            | StatementKind::EvmLightClient
            | StatementKind::CosmosTendermint
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStatement {
    pub corridor_id: u32,
    pub dest_chain_id: u32,
    pub nonce: u64,
    pub kind: StatementKind,
    pub anchor: [u8; ANCHOR_LEN],
    pub event: EventClaim,
    pub finality_depth: u32,
}

impl ProofStatement {
    pub const ENCODED_LEN: usize = 4 + 4 + 8 + 1 + ANCHOR_LEN + EventClaim::ENCODED_LEN + 4;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.corridor_id.to_le_bytes());
        out.extend_from_slice(&self.dest_chain_id.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.push(self.kind.tag());
        out.extend_from_slice(&self.anchor);
        self.event.encode_into(&mut out);
        out.extend_from_slice(&self.finality_depth.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<ProofStatement> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let corridor_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let dest_chain_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let nonce = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let kind = StatementKind::from_tag(bytes[16])?;
        if !is_proof_corridor(kind) {
            return None;
        }
        let mut anchor = [0u8; ANCHOR_LEN];
        anchor.copy_from_slice(&bytes[17..49]);
        let event = EventClaim::decode_from(&bytes[49..145])?;
        let finality_depth = u32::from_le_bytes([bytes[145], bytes[146], bytes[147], bytes[148]]);
        Some(ProofStatement {
            corridor_id,
            dest_chain_id,
            nonce,
            kind,
            anchor,
            event,
            finality_depth,
        })
    }

    pub fn to_stark_statement(&self, public_input_digest: [u8; 32]) -> StarkStatement {
        StarkStatement {
            corridor_id: self.corridor_id,
            dest_chain_id: self.dest_chain_id,
            nonce: self.nonce,
            kind: self.kind,
            public_input_digest,
        }
    }
}

pub fn bitcoin_spv(
    corridor_id: u32,
    dest_chain_id: u32,
    nonce: u64,
    anchor: [u8; ANCHOR_LEN],
    event: EventClaim,
    confirmations: u32,
) -> ProofStatement {
    ProofStatement {
        corridor_id,
        dest_chain_id,
        nonce,
        kind: StatementKind::BitcoinSpv,
        anchor,
        event,
        finality_depth: confirmations,
    }
}

pub fn evm_light_client(
    corridor_id: u32,
    dest_chain_id: u32,
    nonce: u64,
    anchor: [u8; ANCHOR_LEN],
    event: EventClaim,
    finality_depth: u32,
) -> ProofStatement {
    ProofStatement {
        corridor_id,
        dest_chain_id,
        nonce,
        kind: StatementKind::EvmLightClient,
        anchor,
        event,
        finality_depth,
    }
}

pub fn cosmos_tendermint(
    corridor_id: u32,
    dest_chain_id: u32,
    nonce: u64,
    anchor: [u8; ANCHOR_LEN],
    event: EventClaim,
    finality_depth: u32,
) -> ProofStatement {
    ProofStatement {
        corridor_id,
        dest_chain_id,
        nonce,
        kind: StatementKind::CosmosTendermint,
        anchor,
        event,
        finality_depth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: u32 = 4801;
    const NONCE: u64 = 990_001;

    fn sample_event() -> EventClaim {
        EventClaim {
            source_ref: [0x11u8; 32],
            asset_id: [0x22u8; 16],
            amount: 123_456_789_000_000_000_000u128,
            recipient: [0x33u8; 32],
        }
    }

    #[test]
    fn public_inputs_are_fixed_width_with_no_room_for_foreign_material() {
        assert_eq!(ProofStatement::ENCODED_LEN, 4 + 4 + 8 + 1 + 32 + 96 + 4);
        let s = bitcoin_spv(0, DEST, NONCE, [0u8; 32], sample_event(), 6);
        assert_eq!(s.encode().len(), ProofStatement::ENCODED_LEN);
    }

    #[test]
    fn each_corridor_builder_pins_its_own_kind() {
        assert_eq!(
            bitcoin_spv(0, DEST, NONCE, [0u8; 32], sample_event(), 6).kind,
            StatementKind::BitcoinSpv
        );
        assert_eq!(
            evm_light_client(1, DEST, NONCE, [0u8; 32], sample_event(), 64).kind,
            StatementKind::EvmLightClient
        );
        assert_eq!(
            cosmos_tendermint(8, DEST, NONCE, [0u8; 32], sample_event(), 2).kind,
            StatementKind::CosmosTendermint
        );
    }

    #[test]
    fn every_proof_corridor_round_trips() {
        for s in [
            bitcoin_spv(0, DEST, NONCE, [0xa0u8; 32], sample_event(), 6),
            evm_light_client(1, DEST, NONCE, [0xa1u8; 32], sample_event(), 64),
            cosmos_tendermint(8, DEST, NONCE, [0xa2u8; 32], sample_event(), 2),
        ] {
            assert_eq!(ProofStatement::decode(&s.encode()), Some(s));
        }
    }

    #[test]
    fn the_kind_is_bound_into_the_public_inputs() {
        let btc = bitcoin_spv(5, DEST, NONCE, [0u8; 32], sample_event(), 6);
        let evm = evm_light_client(5, DEST, NONCE, [0u8; 32], sample_event(), 6);
        assert_ne!(btc.encode(), evm.encode());
    }

    #[test]
    fn the_amount_is_bound_into_the_public_inputs() {
        let a = bitcoin_spv(0, DEST, NONCE, [0u8; 32], sample_event(), 6);
        let mut ev = sample_event();
        ev.amount += 1;
        let b = bitcoin_spv(0, DEST, NONCE, [0u8; 32], ev, 6);
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn the_destination_chain_and_nonce_are_bound_into_the_public_inputs() {
        let base = bitcoin_spv(5, DEST, NONCE, [0u8; 32], sample_event(), 6);
        let other_chain = bitcoin_spv(5, DEST + 1, NONCE, [0u8; 32], sample_event(), 6);
        let replay = bitcoin_spv(5, DEST, NONCE + 1, [0u8; 32], sample_event(), 6);
        assert_ne!(other_chain.encode(), base.encode());
        assert_ne!(replay.encode(), base.encode());
    }

    #[test]
    fn a_generic_kind_is_not_a_proof_corridor_statement() {
        assert!(!is_proof_corridor(StatementKind::HeaderChain));
        assert!(!is_proof_corridor(StatementKind::LightClientStep));
        let mut bytes = bitcoin_spv(0, DEST, NONCE, [0u8; 32], sample_event(), 6).encode();
        bytes[16] = StatementKind::HeaderChain.tag();
        assert_eq!(ProofStatement::decode(&bytes), None);
    }

    #[test]
    fn a_trailing_foreign_hash_breaks_the_length_gate() {
        let mut bytes = bitcoin_spv(0, DEST, NONCE, [0u8; 32], sample_event(), 6).encode();
        bytes.extend_from_slice(&[0x99u8; 32]);
        assert_eq!(ProofStatement::decode(&bytes), None);
    }

    #[test]
    fn lowering_carries_the_corridor_kind_destination_and_nonce() {
        let s = cosmos_tendermint(8, DEST, NONCE, [0u8; 32], sample_event(), 2);
        let lowered = s.to_stark_statement([7u8; 32]);
        assert_eq!(lowered.corridor_id, 8);
        assert_eq!(lowered.dest_chain_id, DEST);
        assert_eq!(lowered.nonce, NONCE);
        assert_eq!(lowered.kind, StatementKind::CosmosTendermint);
        assert_eq!(lowered.public_input_digest, [7u8; 32]);
    }
}
