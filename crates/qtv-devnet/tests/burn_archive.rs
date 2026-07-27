// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_block::{
    empty_transaction_root, event_root, header_from_bytes, prove_inclusion, verify_inclusion,
    Header,
};
use qtv_codec::{to_bytes, Encoder};
use qtv_node::fee::FeeParams;
use qtv_node::ledger::{
    bridge_burn_ref, BlockEvent, EVENT_BRIDGE_BURN, EVENT_TRANSFER, NATIVE_EVENT_SOURCE,
};
use qtv_node::node::GenesisAccount;
use qtv_store::{BurnArchive, BurnArchiveEntry};

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

fn burn_event(
    asset_id: &[u8; 16],
    holder: &[u8; 32],
    amount: u128,
    destination: &[u8; 32],
    chain_id: u64,
    sender_nonce: u64,
    event_index: u64,
) -> BlockEvent {
    let burn_ref = bridge_burn_ref(
        chain_id,
        asset_id,
        holder,
        amount,
        destination,
        sender_nonce,
        event_index,
    );
    let mut encoder = Encoder::new();
    encoder.put_bytes(asset_id);
    encoder.put_bytes(holder);
    encoder.put_u128(amount);
    encoder.put_bytes(destination);
    encoder.put_u64(chain_id);
    encoder.put_u64(sender_nonce);
    encoder.put_u64(event_index);
    encoder.put_bytes(&burn_ref);
    BlockEvent::native(EVENT_BRIDGE_BURN, encoder.into_bytes())
}

fn carries_burn(events: &[BlockEvent]) -> bool {
    events
        .iter()
        .any(|event| event.selector == EVENT_BRIDGE_BURN && event.contract == NATIVE_EVENT_SOURCE)
}

fn archive_path(name: &str) -> std::path::PathBuf {
    let mut base = unique_base(name);
    base.push("burns.log");
    std::fs::create_dir_all(base.parent().unwrap()).unwrap();
    base
}

#[test]
fn the_finalize_hook_runs_and_skips_a_finalized_block_with_no_burn() {
    let base = unique_base("no-burn");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized");

    let node = devnet.node(0);
    assert_eq!(node.finalized_head(), 1, "one block was finalized");
    assert!(
        !node.events_at(1).is_empty(),
        "the finalized transfer recorded a block event, so the hook saw a non empty event log"
    );
    assert!(
        node.burn_heights_after(0).is_empty(),
        "a block with events but no bridge burn is not archived"
    );
    assert!(node.burn_block(1).is_none());
}

#[test]
fn a_stored_burn_block_recomputes_its_event_root_and_an_inclusion_proof_verifies() {
    let path = archive_path("burn-inclusion");
    let asset_id = [7u8; 16];
    let holder = [9u8; 32];
    let destination = [0xEEu8; 32];

    let events = vec![
        BlockEvent::native(EVENT_TRANSFER, vec![1, 2, 3]),
        burn_event(&asset_id, &holder, 100_000, &destination, 42, 0, 1),
        BlockEvent::native(EVENT_TRANSFER, vec![4, 5]),
    ];
    assert!(carries_burn(&events));
    let burn_index = 1usize;
    let leaves: Vec<Vec<u8>> = events.iter().map(BlockEvent::encode).collect();
    let root = event_root(&leaves);
    let header = Header::new(
        1,
        [0u8; 32],
        [0u8; 32],
        empty_transaction_root(),
        root,
        [0u8; 32],
        "qtv1proposer".to_string(),
        1_700_000_000_000,
    );

    let entry = BurnArchiveEntry {
        height: header.height(),
        header_bytes: to_bytes(&header),
        certificate: vec![0xABu8; 16],
        events: leaves.clone(),
    };
    {
        let mut archive = BurnArchive::open(&path).unwrap();
        archive.append(entry.clone()).unwrap();
    }

    let archive = BurnArchive::open(&path).unwrap();
    let stored = archive.entry(1).expect("the burn block survived the reopen");
    assert_eq!(stored, &entry);

    let decoded_header = header_from_bytes(&stored.header_bytes).expect("the header decodes");
    assert_eq!(
        event_root(&stored.events),
        *decoded_header.event_root(),
        "the stored leaves recompute the header event root"
    );

    let proof = prove_inclusion(&stored.events, burn_index).expect("a proof for the burn leaf");
    assert!(
        verify_inclusion(
            decoded_header.event_root(),
            &stored.events[burn_index],
            &proof
        ),
        "the burn inclusion proof verifies against the header event root"
    );
    assert!(
        !verify_inclusion(decoded_header.event_root(), b"not-the-burn-leaf", &proof),
        "a wrong leaf does not verify under the same proof"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_block_with_no_burn_leaf_is_not_treated_as_a_burn() {
    let events = vec![
        BlockEvent::native(EVENT_TRANSFER, vec![1, 2, 3]),
        BlockEvent::native(EVENT_TRANSFER, vec![4, 5, 6]),
    ];
    assert!(!carries_burn(&events), "a transfer only block carries no burn");
}

#[test]
fn burn_heights_enumerate_in_order_after_a_cursor() {
    let path = archive_path("burn-cursor");
    let asset_id = [7u8; 16];
    let holder = [9u8; 32];
    let destination = [0xEEu8; 32];
    let mut archive = BurnArchive::open(&path).unwrap();
    for &height in &[14u64, 3, 27, 8] {
        let events = vec![burn_event(&asset_id, &holder, 1, &destination, 42, 0, 0)];
        let leaves: Vec<Vec<u8>> = events.iter().map(BlockEvent::encode).collect();
        archive
            .append(BurnArchiveEntry {
                height,
                header_bytes: vec![height as u8; 4],
                certificate: vec![0u8; 4],
                events: leaves,
            })
            .unwrap();
    }
    assert_eq!(archive.heights_after(0), vec![3, 8, 14, 27]);
    assert_eq!(archive.heights_after(8), vec![14, 27]);
    assert_eq!(archive.heights_after(27), Vec::<u64>::new());
    std::fs::remove_file(&path).ok();
}
