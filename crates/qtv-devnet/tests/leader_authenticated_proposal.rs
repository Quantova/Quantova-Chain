// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod support;

use qtv_attest::Attestation;
use qtv_node::consensus::header_value;
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_block::Block as ChainBlock;
use qtv_devnet::coded::{
    code_block, code_proposal, ProposalAssembler, GLOBAL_SOURCE, PREPIN_TOKENS_PER_TICK,
};
use qtv_devnet::config::DevnetConfig;
use qtv_devnet::node::{leader_for, DevNode};
use qtv_devnet::wire::{CodedProposal, Message, Proposal};
use qtv_devnet::Devnet;

use support::{config, transfer, unique_base, user};

fn open_nodes(config: &DevnetConfig) -> Vec<DevNode> {
    let mut nodes: Vec<DevNode> = config
        .nodes
        .iter()
        .map(|node| DevNode::open(node, config).expect("node opens"))
        .collect();
    let notes: Vec<_> = nodes
        .iter()
        .filter_map(|node| node.own_reveal_note())
        .collect();
    for node in &mut nodes {
        for note in &notes {
            node.collect_reveal(note.clone());
        }
    }
    nodes
}

fn idx(config: &DevnetConfig, id: u64) -> usize {
    config
        .nodes
        .iter()
        .position(|node| node.id == id)
        .expect("a node holds the id")
}

fn prevote_of(messages: &[Message]) -> Option<Attestation> {
    messages.iter().find_map(|message| match message {
        Message::Prevote(att) => Some((**att).clone()),
        _ => None,
    })
}

fn leader_and_stranger(
    config: &DevnetConfig,
    nodes: &[DevNode],
    committee: usize,
) -> (u64, usize, usize) {
    let selection = nodes[0].select().expect("committee");
    assert_eq!(selection.members.len(), committee, "committee draw differs");
    let leader = leader_for(&selection, 0);
    let leader_idx = idx(config, leader);
    let stranger = (0..nodes.len())
        .find(|&i| i != leader_idx)
        .expect("a non leader member");
    (leader, leader_idx, stranger)
}

fn only_a_leader_signed_proposal_is_prevoted(committee: usize, online: &[bool]) {
    let base = unique_base(&format!("leader_auth_{committee}"));
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, online, accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let (leader, leader_idx, stranger_idx) = leader_and_stranger(&config, &nodes, committee);

    let genuine = nodes[leader_idx].build_proposal(&selection);
    let counterfeit = nodes[stranger_idx].build_proposal(&selection);

    assert_eq!(
        header_value(&genuine.header.hash()),
        header_value(&counterfeit.header.hash()),
        "the stranger reproduces the same block, so only the signature separates them"
    );
    assert_eq!(
        genuine.auth.from, leader,
        "the leader signs under its own identity"
    );
    assert_ne!(
        counterfeit.auth.from, leader,
        "the stranger cannot sign as the elected leader"
    );

    let victim = (0..nodes.len())
        .find(|&i| i != leader_idx && i != stranger_idx)
        .expect("a distinct victim");
    let refused = nodes[victim].on_proposal(&selection, leader, counterfeit.clone());
    assert!(
        prevote_of(&refused).is_none(),
        "a proposal not signed by the elected leader must not be prevoted"
    );
    assert_eq!(
        nodes[victim].staged_view(),
        None,
        "an unauthenticated proposal must not be staged"
    );

    let grafted = Proposal {
        auth: counterfeit.auth.clone(),
        ..genuine.clone()
    };
    let refused = nodes[victim].on_proposal(&selection, leader, grafted);
    assert!(
        prevote_of(&refused).is_none(),
        "a leader header re signed by another member must not be prevoted"
    );
    assert_eq!(nodes[victim].staged_view(), None);

    let accepted = nodes[victim].on_proposal(&selection, leader, genuine);
    assert!(
        prevote_of(&accepted).is_some(),
        "the genuine leader signed proposal is prevoted"
    );
    assert_eq!(nodes[victim].staged_view(), Some(0));
}

#[test]
fn a_non_leader_proposal_is_refused_at_a_four_node_committee() {
    only_a_leader_signed_proposal_is_prevoted(4, &[true, true, true, true]);
}

#[test]
fn a_non_leader_proposal_is_refused_at_a_seven_node_committee() {
    only_a_leader_signed_proposal_is_prevoted(7, &[true, true, true, true, true, true, true]);
}

#[test]
fn a_genuine_leader_signed_proposal_finalizes() {
    let base = unique_base("leader_auth_finalize");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let mut devnet =
        Devnet::over_duplex(config(&base, &[true, true, true, true], accounts)).expect("devnet");

    let tx = transfer(&alice, &bob.address(), 1_000, 0, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet
        .step()
        .expect("the committee finalized a leader signed height");

    for i in 0..devnet.len() {
        assert_eq!(
            devnet.node(i).chain().len(),
            1,
            "node {i} did not finalize the leader signed block"
        );
    }
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 1_000);
}

#[test]
fn a_replayed_justification_flood_verifies_within_the_committee_bound() {
    let base = unique_base("justification_flood");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    assert_eq!(selection.members.len(), 7);
    let tau = selection.tau;

    let l0 = leader_for(&selection, 0);
    let l0_idx = idx(&config, l0);
    let l2 = leader_for(&selection, 2);
    let l2_idx = idx(&config, l2);

    let proposal_x = nodes[l0_idx].build_proposal(&selection);
    let mut prevotes: Vec<Attestation> = Vec::new();
    for i in 0..nodes.len() {
        if let Some(prevote) = prevote_of(&nodes[i].on_proposal(&selection, l0, proposal_x.clone()))
        {
            prevotes.push(prevote);
        }
    }
    for i in 0..nodes.len() {
        for prevote in &prevotes {
            let _ = nodes[i].on_prevote(&selection, prevote.clone());
        }
    }

    let mut records = Vec::new();
    for i in 0..nodes.len() {
        if i == l2_idx {
            continue;
        }
        let record = nodes[i].make_view_change(2);
        nodes[l2_idx].collect_view_change(&selection, record.clone());
        records.push(record);
    }
    let justified = nodes[l2_idx]
        .build_justified_proposal(&selection, 2)
        .expect("a quorum of view changes justifies a proposal");
    let genuine = justified.justification;
    let distinct = genuine.len();
    assert!(
        distinct as u64 >= tau,
        "the genuine justification carries at least a quorum"
    );
    let _ = records;

    let mut flood = genuine.clone();
    while flood.len() < selection.members.len() {
        flood.push(genuine[flood.len() % distinct].clone());
    }
    assert!(
        flood.len() > distinct,
        "the flood carries more records than there are distinct signers"
    );

    let observer = (0..nodes.len())
        .find(|&i| i != l2_idx)
        .expect("an observer that did not assemble the justification");

    let (valid, first) = nodes[observer].measure_justification(&selection, &flood, 2);
    assert!(valid, "the genuine higher polka is still accepted");
    assert_eq!(
        first, distinct as u64,
        "each distinct signer is verified once, the replayed copies add no verifications"
    );
    assert!(
        first < flood.len() as u64,
        "verification does not scale with the size of the flood"
    );
    assert!(
        first <= 4 * qtv_sampler::params::COMMITTEE_BUDGET,
        "verifications stay within the committee budget cap"
    );

    let mut later: u64 = 0;
    for _ in 0..64 {
        let (still_valid, count) = nodes[observer].measure_justification(&selection, &flood, 2);
        assert!(
            still_valid,
            "the cached justification stays valid on replay"
        );
        later += count;
    }
    assert_eq!(
        later, 0,
        "a replayed justification is not verified a second time"
    );
}

#[test]
fn a_forged_auth_shard_does_not_stall_coded_reassembly() {
    let base = unique_base("coded_auth_grief");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let mut nodes = open_nodes(&config);

    let selection = nodes[0].select().expect("committee");
    let leader = leader_for(&selection, 0);
    let leader_idx = idx(&config, leader);
    let victim = (0..nodes.len())
        .find(|&i| i != leader_idx)
        .expect("a distinct victim");

    let genuine = nodes[leader_idx].build_proposal(&selection);
    let shards = code_proposal(&genuine).expect("code the genuine proposal");
    assert!(
        shards.len() > shards[0].commitment.k,
        "the proposal codes into several shards"
    );

    let mut forged = shards[0].clone();
    forged.auth = support::dummy_auth();

    assert!(
        !nodes[victim].coded_auth_ok(&selection, &forged),
        "a shard carrying a garbage auth fails admit verification"
    );
    assert!(
        nodes[victim].coded_auth_ok(&selection, &shards[0]),
        "a genuine shard passes admit verification"
    );

    let mut assembler = ProposalAssembler::new();
    let mut reassembled = None;
    let feed = std::iter::once(forged).chain(shards.iter().cloned());
    for shard in feed {
        if let Some(result) = assembler.admit(shard, GLOBAL_SOURCE, |c| {
            nodes[victim].coded_auth_ok(&selection, c)
        }) {
            reassembled = Some(result);
        }
    }
    let proposal = reassembled
        .expect("the genuine shards reassemble despite the forged first shard")
        .expect("reassembly succeeds");
    assert_eq!(
        proposal.auth.from, leader,
        "the reassembled proposal carries the leader auth"
    );

    let out = nodes[victim].on_proposal(&selection, leader, proposal);
    assert!(
        prevote_of(&out).is_some(),
        "the reassembled genuine proposal is prevoted"
    );
    assert_eq!(nodes[victim].staged_view(), Some(0));
}

fn fabricated_shard(genuine: &Proposal, salt: u16) -> CodedProposal {
    let mut header = genuine.header.clone();
    let _ = header.set_extra_data(vec![(salt & 0xff) as u8, (salt >> 8) as u8]);
    let block = ChainBlock::new(header, Vec::new(), genuine.body.clone());
    let coded = code_block(&block, 2, 4).expect("code the fabricated bytes");
    let (shard, proof) = coded.piece(0).expect("a fabricated shard");
    CodedProposal {
        view: genuine.view,
        header: genuine.header.clone(),
        commitment: coded.commitment().clone(),
        justification: Vec::new(),
        shard,
        proof,
        auth: genuine.auth.clone(),
    }
}

fn coded_fixture(
    config: &DevnetConfig,
) -> (
    Vec<DevNode>,
    usize,
    u64,
    usize,
    Proposal,
    Vec<CodedProposal>,
) {
    let mut nodes = open_nodes(config);
    let selection = nodes[0].select().expect("committee");
    let leader = leader_for(&selection, 0);
    let leader_idx = idx(config, leader);
    let victim = (0..nodes.len())
        .find(|&i| i != leader_idx)
        .expect("a distinct victim");
    let genuine = nodes[leader_idx].build_proposal(&selection);
    let shards = code_proposal(&genuine).expect("code the genuine proposal");
    (nodes, victim, leader, leader_idx, genuine, shards)
}

#[test]
fn a_fabricated_root_burst_before_the_leader_still_finalizes() {
    let base = unique_base("adversarial_ordering");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let (nodes, victim, leader, _leader_idx, genuine, shards) = coded_fixture(&config);
    let selection = nodes[0].select().expect("committee");
    let k = shards[0].commitment.k;

    let attacker: u64 = 999;
    let honest: u64 = 7;
    assert_ne!(attacker, GLOBAL_SOURCE);

    let mut assembler = ProposalAssembler::new();
    let mut verifies = 0usize;

    let burst: u16 = 2200;
    let mut spent = 0u32;
    for salt in 0..burst {
        if spent >= PREPIN_TOKENS_PER_TICK {
            assembler.tick();
            spent = 0;
        }
        let before = verifies;
        let fake = fabricated_shard(&genuine, salt);
        assert!(!nodes[victim].coded_auth_ok(&selection, &fake));
        let _ = assembler.admit(fake, attacker, |c| {
            verifies += 1;
            nodes[victim].coded_auth_ok(&selection, c)
        });
        if verifies > before {
            spent += 1;
        }
    }
    assert!(
        verifies >= 2000,
        "the attacker burst really drove past the old fixed pool"
    );

    assembler.tick();
    let mut reassembled = None;
    for shard in shards.iter().take(k).cloned() {
        if let Some(result) = assembler.admit(shard, honest, |c| {
            nodes[victim].coded_auth_ok(&selection, c)
        }) {
            reassembled = Some(result);
        }
    }
    let proposal = reassembled
        .expect("the genuine proposal still authenticates after the burst, no halt")
        .expect("reassembly succeeds");
    assert_eq!(
        proposal.auth.from, leader,
        "only the genuine leader root reassembles into an accepted proposal"
    );
}

#[test]
fn a_fabricated_flood_does_not_consume_the_honest_peer_budget() {
    let base = unique_base("per_peer_isolation");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let (nodes, victim, _leader, _leader_idx, genuine, shards) = coded_fixture(&config);
    let selection = nodes[0].select().expect("committee");
    let k = shards[0].commitment.k;

    let attacker: u64 = 1;
    let honest: u64 = 2;
    let mut assembler = ProposalAssembler::new();

    for salt in 0..(PREPIN_TOKENS_PER_TICK * 3) as u16 {
        let _ = assembler.admit(fabricated_shard(&genuine, salt), attacker, |c| {
            nodes[victim].coded_auth_ok(&selection, c)
        });
    }

    let mut reassembled = None;
    for shard in shards.iter().take(k).cloned() {
        if let Some(result) = assembler.admit(shard, honest, |c| {
            nodes[victim].coded_auth_ok(&selection, c)
        }) {
            reassembled = Some(result);
        }
    }
    assert!(
        reassembled.map(|r| r.is_ok()).unwrap_or(false),
        "the honest peer pins the genuine root in the same tick the attacker exhausted its own bucket"
    );
}

#[test]
fn a_replayed_genuine_shard_is_verified_once() {
    let base = unique_base("coded_pin_memo");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let (nodes, victim, _leader, _leader_idx, _genuine, shards) = coded_fixture(&config);
    let selection = nodes[0].select().expect("committee");
    assert!(shards[0].commitment.k > 1, "one shard must not complete");

    let mut verifies = 0usize;
    let mut assembler = ProposalAssembler::new();
    for _ in 0..256 {
        let _ = assembler.admit(shards[0].clone(), 5, |c| {
            verifies += 1;
            nodes[victim].coded_auth_ok(&selection, c)
        });
    }
    assert_eq!(
        verifies, 1,
        "a genuine shard replayed many times is verified once because its root is pinned"
    );
}

#[test]
fn a_full_fabricated_set_is_never_accepted() {
    let base = unique_base("coded_safety");
    let alice = user(0);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let config = config(&base, &[true, true, true, true], accounts);
    let (nodes, victim, _leader, _leader_idx, genuine, shards) = coded_fixture(&config);
    let selection = nodes[0].select().expect("committee");

    let mut header = genuine.header.clone();
    let _ = header.set_extra_data(vec![0xa5, 0x5a]);
    let block = ChainBlock::new(header, Vec::new(), genuine.body.clone());
    let coded = code_block(&block, 2, 4).expect("code the fabricated block");
    assert_ne!(coded.commitment().root, shards[0].commitment.root);

    let mut assembler = ProposalAssembler::new();
    let mut produced = None;
    for i in 0..4usize {
        let (shard, proof) = coded.piece(i).expect("a fabricated piece");
        let fake = CodedProposal {
            view: genuine.view,
            header: genuine.header.clone(),
            commitment: coded.commitment().clone(),
            justification: Vec::new(),
            shard,
            proof,
            auth: genuine.auth.clone(),
        };
        assert!(
            !nodes[victim].coded_auth_ok(&selection, &fake),
            "no fabricated root authenticates under the leader key"
        );
        if let Some(result) =
            assembler.admit(fake, 3, |c| nodes[victim].coded_auth_ok(&selection, c))
        {
            produced = Some(result);
        }
    }
    assert!(
        produced.is_none(),
        "a full set of fabricated shards never pins and never yields an accepted block"
    );

    let mut poisoned = shards[0].clone();
    if let Some(byte) = poisoned.shard.bytes.first_mut() {
        *byte ^= 0xff;
    }
    let mut fresh = ProposalAssembler::new();
    assert!(
        fresh
            .admit(poisoned, 3, |c| nodes[victim].coded_auth_ok(&selection, c))
            .is_none(),
        "a poisoned shard is rejected before it can pin or reassemble"
    );
}
