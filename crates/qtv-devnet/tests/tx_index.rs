//! The transaction index answers whether a transaction landed and where, and it
//! survives a restart by rebuilding from the store.

mod support;

use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

#[test]
fn the_transaction_index_answers_after_finality_and_survives_a_restart() {
    let base = unique_base("tx-index");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    // Submit and finalize one transfer, capturing its id before it moves into submit.
    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    let tx_id = tx.id();
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized");

    // The height that just finalized, one below the next height the node will produce.
    let height = devnet.node(0).height() - 1;

    // The node indexes the transaction at the height it finalized.
    assert_eq!(devnet.node(0).finalized_height(&tx_id), Some(height));
    // A transaction the node never finalized is absent, not guessed at.
    assert_eq!(devnet.node(0).finalized_height("qtx1neverfinalised"), None);

    // A restarted node rebuilds the index from its store, so it still answers for a
    // transaction it finalized before it was reopened.
    let index = devnet.len() - 1;
    assert_eq!(devnet.node(index).finalized_height(&tx_id), Some(height));
    devnet.restart_node(index).expect("reopened from the store");
    assert_eq!(
        devnet.node(index).finalized_height(&tx_id),
        Some(height),
        "the transaction index did not survive a restart"
    );
}
