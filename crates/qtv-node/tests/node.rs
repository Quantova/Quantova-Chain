//! Integration tests for the node state transition and finalization loop. They
//! exercise execution, multi height finalization, rejection, an offline
//! validator, and determinism end to end over the composed stack.

use qtv_account::{derive, Account};
use qtv_node::execution::{transfer_call, TRANSFER_METER};
use qtv_node::fee::FeeParams;
use qtv_node::mempool::Reject;
use qtv_node::node::{Finalized, Genesis, GenesisAccount, Node, ProduceError, ValidatorSpec};
use qtv_tx::{sign, Body, Wrapper};

const USER_SEED: [u8; 32] = [11u8; 32];
const GENESIS_TIME: u64 = 1_700_000_000_000;
const VALIDATOR_STAKE: u64 = 2_000;

fn user(index: u64) -> Account {
    derive(&USER_SEED, index)
}

fn validators(online: &[bool]) -> Vec<ValidatorSpec> {
    online
        .iter()
        .enumerate()
        .map(|(i, &on)| {
            let id = i as u64 + 1;
            ValidatorSpec::from_secret(
                id,
                VALIDATOR_STAKE,
                on,
                &qtv_node::keys::fixture_secret(id),
                qtv_node::consensus::DEFAULT_SLOTS,
            )
        })
        .collect()
}

fn genesis(accounts: Vec<GenesisAccount>, online: &[bool]) -> Genesis {
    Genesis {
        fee_params: FeeParams::devnet(),
        accounts,
        validators: validators(online),
        genesis_time: GENESIS_TIME,
    }
}

/// Boot a node from genesis, supplying each validator's own fixture secret as the
/// simulation roster. The genesis carries only commitments; the secrets are the test
/// only fixtures the committed bond addresses were derived from.
fn boot(genesis: Genesis) -> Node {
    let secrets = genesis
        .validators
        .iter()
        .map(|v| (v.id, qtv_node::keys::fixture_secret(v.id)))
        .collect::<std::collections::BTreeMap<_, _>>();
    Node::new(genesis, &secrets)
}

fn transfer(from: &Account, to: &str, amount: u64, nonce: u64, params: &FeeParams) -> Wrapper {
    let call = transfer_call(to, amount);
    let body = Body::new(
        from.address(),
        nonce,
        TRANSFER_METER,
        u128::from(params.transfer_fee()),
        call,
    );
    sign(from, &body)
}

fn tampered(mut wrapper: Wrapper) -> Wrapper {
    let mut signature = wrapper.signature().to_vec();
    signature[0] ^= 1;
    wrapper = Wrapper::new(wrapper.body().clone(), wrapper.scheme(), signature);
    wrapper
}

#[test]
fn a_signed_transfer_executes_lands_in_a_block_and_moves_state() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let mut node = boot(genesis(
        vec![GenesisAccount::from_account(&alice, 1_000_000)],
        &[true, true, true, true],
    ));

    let amount = 5_000;
    let tx = transfer(&alice, &bob.address(), amount, 0, &params);
    let tx_id = tx.id();
    node.submit(tx).expect("admitted");

    let fee = params.transfer_fee();
    node.produce().expect("finalized");
    let finalized = node.chain().last().expect("a finalized block");

    // The transaction landed in the finalized body.
    assert!(finalized.transaction_ids().contains(&tx_id));
    // The post execution state root sits in the finalized header.
    assert_eq!(*finalized.header().state_root(), node.ledger().state_root());
    // The finalized header binds the certificate over the real header.
    assert!(finalized.reconciles());
    assert_eq!(finalized.header().height(), 1);

    // State moved: the sender paid the amount and the fee, the recipient received
    // the amount.
    assert_eq!(
        node.ledger().balance(&alice.address()),
        1_000_000 - amount - fee
    );
    assert_eq!(node.ledger().balance(&bob.address()), amount);
    assert_eq!(node.ledger().nonce(&alice.address()), 1);
}

#[test]
fn an_equivocator_is_banned_in_chain_state_and_excluded_from_the_next_committee() {
    let alice = user(0);
    let mut node = boot(genesis(
        vec![GenesisAccount::from_account(&alice, 1_000_000)],
        &[true, true, true, true],
    ));

    let culprit = 2u64;
    let address = qtv_node::node::validator_address(culprit);
    assert!(
        node.ledger().staked_weight(&address) > 0,
        "the validator is bonded at genesis"
    );

    node.force_equivocation(culprit);
    node.produce().expect("the first block finalizes");

    assert!(
        node.slashed().contains(&culprit),
        "the double signer is recorded in the slashed set"
    );
    assert!(
        !node.slashed().contains(&1),
        "an honest validator is never slashed"
    );
    assert!(
        node.ledger().is_validator_banned(&address),
        "the equivocator is banned in chain state"
    );
    assert_eq!(
        node.ledger().staked_weight(&address),
        0,
        "the slashed bond carries no committee weight"
    );

    node.produce()
        .expect("the next block finalizes without the banned validator");
    let latest = node.chain().last().expect("a finalized block");
    assert!(
        !latest.members.contains(&culprit),
        "the banned validator is excluded from the next committee"
    );
    assert_eq!(latest.header().height(), 2);
}

#[test]
fn the_committee_finalizes_a_run_of_heights_in_order() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let mut node = boot(genesis(
        vec![GenesisAccount::from_account(&alice, 1_000_000)],
        &[true, true, true, true],
    ));

    let amount = 1_000;
    let heights = 5u64;
    for nonce in 0..heights {
        let tx = transfer(&alice, &bob.address(), amount, nonce, &params);
        node.submit(tx).expect("admitted");
        node.produce().expect("finalized");
    }

    let chain = node.chain();
    assert_eq!(chain.len(), heights as usize);
    for (i, finalized) in chain.iter().enumerate() {
        assert_eq!(finalized.header().height(), i as u64 + 1);
        assert!(finalized.reconciles());
        let expected_parent = if i == 0 {
            [0u8; 32]
        } else {
            chain[i - 1].header_hash()
        };
        assert_eq!(*finalized.header().parent_hash(), expected_parent);
    }
    assert_eq!(node.height(), heights + 1);

    let fee = params.transfer_fee();
    assert_eq!(
        node.ledger().balance(&alice.address()),
        1_000_000 - heights * (amount + fee)
    );
    assert_eq!(node.ledger().balance(&bob.address()), heights * amount);
}

#[test]
fn a_bad_signature_or_insufficient_balance_is_rejected_and_never_finalized() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let poor = user(1);
    let bob = user(2);
    let mut node = boot(genesis(
        vec![
            GenesisAccount::from_account(&alice, 1_000_000),
            GenesisAccount::from_account(&poor, 10),
        ],
        &[true, true, true, true],
    ));

    // A forged signature is refused at the edge.
    let forged = tampered(transfer(&alice, &bob.address(), 5_000, 0, &params));
    assert_eq!(node.submit(forged), Err(Reject::BadSignature));

    // A sender that cannot cover the amount and the fee is refused.
    let unaffordable = transfer(&poor, &bob.address(), 5_000, 0, &params);
    assert_eq!(node.submit(unaffordable), Err(Reject::InsufficientFunds));

    // Neither reached the pool, so neither can be finalized.
    assert_eq!(node.mempool_len(), 0);
    node.produce().expect("empty block still finalizes");
    let finalized = node.chain().last().expect("a finalized block");
    assert!(finalized.transaction_ids().is_empty());

    // No state moved for either sender.
    assert_eq!(node.ledger().balance(&alice.address()), 1_000_000);
    assert_eq!(node.ledger().balance(&poor.address()), 10);
    assert_eq!(node.ledger().balance(&bob.address()), 0);
}

#[test]
fn an_offline_validator_lowers_the_count_without_stalling_and_is_never_slashed() {
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    // Four validators, the fourth offline. A supermajority of four is three.
    let mut node = boot(genesis(
        vec![GenesisAccount::from_account(&alice, 1_000_000)],
        &[true, true, true, false],
    ));

    let tx = transfer(&alice, &bob.address(), 2_000, 0, &params);
    node.submit(tx).expect("admitted");
    node.produce().expect("finalized despite an absence");

    {
        let finalized = node.chain().last().expect("a finalized block");
        // The offline member is still on the committee but did not attest, so the
        // count is lower yet a supermajority still formed.
        assert_eq!(finalized.committee_size, 4);
        assert_eq!(finalized.attesters, vec![1, 2, 3]);
        assert!(!finalized.attesters.contains(&4));
    }

    // The offline validator is never slashed, and the chain kept moving.
    assert!(node.slashed().is_empty());

    // A second height still finalizes with the same absence.
    let tx = transfer(&alice, &bob.address(), 2_000, 1, &params);
    node.submit(tx).expect("admitted");
    node.produce().expect("finalized again");
    assert!(node.slashed().is_empty());
    assert_eq!(node.chain().len(), 2);
}

/// A per block digest of the finalized chain: the block id, the header hash, the
/// state root, the certificate digest, and the attesters.
type BlockPrint = (String, [u8; 32], [u8; 32], [u8; 32], Vec<u64>);

fn fingerprint(node: &Node) -> Vec<BlockPrint> {
    node.chain()
        .iter()
        .map(|f: &Finalized| {
            (
                f.id(),
                f.header_hash(),
                *f.header().state_root(),
                f.certificate.digest(),
                f.attesters.clone(),
            )
        })
        .collect()
}

fn run_scripted(params: &FeeParams) -> Result<Node, ProduceError> {
    let alice = user(0);
    let carol = user(1);
    let dave = user(2);
    let mut node = boot(genesis(
        vec![
            GenesisAccount::from_account(&alice, 1_000_000),
            GenesisAccount::from_account(&carol, 500_000),
        ],
        &[true, true, true, true],
    ));

    let script = [
        (&alice, dave.address(), 3_000u64, 0u64),
        (&carol, dave.address(), 1_500, 0),
        (&alice, carol.address(), 700, 1),
    ];
    for (from, to, amount, nonce) in script {
        let tx = transfer(from, &to, amount, nonce, params);
        node.submit(tx).expect("admitted");
        node.produce()?;
    }
    Ok(node)
}

#[test]
fn the_same_inputs_give_the_same_finalized_chain() {
    let params = FeeParams::devnet();
    let one = run_scripted(&params).expect("first run");
    let two = run_scripted(&params).expect("second run");

    assert_eq!(fingerprint(&one), fingerprint(&two));
    assert_eq!(one.ledger().state_root(), two.ledger().state_root());
    assert_eq!(one.height(), two.height());
}

/// A node running a block of many senders and recipients, mixing independent
/// transfers and ones that share an account, at the given core count. The block
/// is submitted at one height so the executor sees the whole block at once. Each
/// sender appears once, since the mempool admits only the next nonce of a sender,
/// so the conflicts come from a shared recipient and from one transfer paying an
/// account that another transfer spends from.
fn run_batch(params: &FeeParams, threads: usize) -> Node {
    let funders: Vec<Account> = (0..24).map(user).collect();
    let accounts: Vec<GenesisAccount> = funders
        .iter()
        .map(|a| GenesisAccount::from_account(a, 10_000_000))
        .collect();
    let mut node =
        boot(genesis(accounts, &[true, true, true, true])).with_parallelism(threads);

    // Ten independent transfers, each from its own sender to a recipient nobody
    // else touches.
    for i in 0..10u64 {
        let tx = transfer(
            &funders[i as usize],
            &user(12 + i).address(),
            1_000 + i,
            0,
            params,
        );
        node.submit(tx).expect("admitted");
    }
    // Two more senders pay the same recipient, a write write conflict on that
    // account that must serialise in block order.
    node.submit(transfer(&funders[10], &user(23).address(), 500, 0, params))
        .expect("admitted");
    node.submit(transfer(&funders[11], &user(23).address(), 400, 0, params))
        .expect("admitted");
    // A transfer that pays account twelve, which is itself a sender above, a read
    // write conflict across the two.
    node.submit(transfer(&funders[13], &user(12).address(), 300, 0, params))
        .expect("admitted");

    node.produce().expect("finalized");
    node
}

#[test]
fn a_parallel_node_finalizes_the_identical_chain_as_the_sequential_node() {
    let params = FeeParams::devnet();
    let sequential = run_batch(&params, 1);
    let parallel = run_batch(&params, 8);

    // The whole finalized chain, including every header hash, state root, and
    // certificate digest, is bit identical, so parallel execution changed nothing
    // an observer of the chain can see.
    assert_eq!(fingerprint(&sequential), fingerprint(&parallel));
    assert_eq!(
        sequential.ledger().state_root(),
        parallel.ledger().state_root()
    );
    // Every account landed on the same balance and nonce under both paths.
    for i in 0..24u64 {
        let address = user(i).address();
        assert_eq!(
            sequential.ledger().balance(&address),
            parallel.ledger().balance(&address)
        );
        assert_eq!(
            sequential.ledger().nonce(&address),
            parallel.ledger().nonce(&address)
        );
    }
}

#[test]
fn a_validator_is_hard_wired_to_use_at_least_half_its_cores() {
    use qtv_node::node::min_validator_cores;
    let machine = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // The floor is half the machine's cores, rounded down, and never below one.
    assert_eq!(min_validator_cores(), (machine / 2).max(1));
    assert!(min_validator_cores() >= 1);

    let alice = user(1);
    let build = || {
        boot(genesis(
            vec![GenesisAccount::from_account(&alice, 1_000_000)],
            &[true, true, true, true],
        ))
    };

    // A default validator already executes at the floor.
    assert!(build().exec_cores() >= min_validator_cores());
    // Configuring fewer cores than the floor cannot lower a validator below it.
    assert_eq!(
        build().with_parallelism(1).exec_cores(),
        min_validator_cores(),
        "a validator cannot run below the core floor"
    );
    // Configuring more than the floor is honoured.
    assert_eq!(
        build().with_parallelism(4096).exec_cores(),
        4096,
        "a validator may use more than the floor"
    );
}
