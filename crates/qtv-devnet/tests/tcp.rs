//! The devnet runs over real localhost TCP channels, not only the in memory
//! duplex, and still reaches the same finalized block on every node.

mod support;

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::thread;

use qtv_net::{Channel, Identity};
use qtv_node::fee::FeeParams;
use qtv_node::node::GenesisAccount;

use qtv_devnet::node::net_identity;
use qtv_devnet::{Devnet, Mesh};

use support::{config, encoded_chain, transfer, unique_base, user};

/// Stand up a full mesh over localhost TCP, one pinned channel per pair.
fn tcp_mesh(identities: &[Identity]) -> Mesh<TcpStream> {
    let n = identities.len();
    let mut links = BTreeMap::new();
    for i in 0..n {
        for j in (i + 1)..n {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let address = listener.local_addr().expect("addr");
            let id_far = identities[j].clone();
            let peer_near = identities[i].peer_id();
            let accepting = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept");
                Channel::accept_pinned(stream, &id_far, &peer_near).expect("responder handshake")
            });
            let stream = TcpStream::connect(address).expect("connect");
            let channel_i =
                Channel::connect_pinned(stream, &identities[i], &identities[j].peer_id())
                    .expect("initiator handshake");
            let channel_j = accepting.join().expect("accept thread");
            links.insert((i, j), channel_i);
            links.insert((j, i), channel_j);
        }
    }
    Mesh::from_links(n, links)
}

#[test]
fn the_devnet_reaches_finality_over_localhost_tcp() {
    let base = unique_base("tcp");
    let params = FeeParams::devnet();
    let alice = user(0);
    let bob = user(1);
    let accounts = vec![GenesisAccount::from_account(&alice, 1_000_000)];
    let cfg = config(&base, &[true, true, true], accounts);

    let identities: Vec<Identity> = cfg.nodes.iter().map(|n| net_identity(n.id)).collect();
    let mesh = tcp_mesh(&identities);
    let mut devnet = Devnet::from_parts(cfg, mesh).expect("devnet over tcp");

    let tx = transfer(&alice, &bob.address(), 2_000, 0, &params);
    devnet.submit(0, tx).expect("admitted");
    devnet.step().expect("finalized over tcp");

    let reference = encoded_chain(devnet.node(0));
    assert_eq!(reference.len(), 1);
    for i in 1..devnet.len() {
        assert_eq!(
            encoded_chain(devnet.node(i)),
            reference,
            "node {i} finalized a different block over tcp"
        );
    }
    assert_eq!(devnet.node(0).ledger().balance(&bob.address()), 2_000);
}
