//! quantovad, the standalone Quantova validator daemon.
//!
//! One process, one validator. It reads a node config file and the shared genesis
//! file both nodes of a network open from, opens the node against its on disk stores,
//! stands up the real qtv-net post quantum mesh to its peers, and drives a continuous
//! production round that finalises blocks and persists each one before advancing. A
//! restart reopens the stores and resumes from the last finalised block. A committee
//! of one is its own supermajority, so a single quantovad is a live chain on its own,
//! which is the front door the rest of the stack, the RPC and everything a person
//! touches, is then built on.
//!
//! KEY MODEL AND THE GUARD. This build derives every validator's identity from its
//! numeric id, so whoever holds the genesis controls every validator. That is a chain
//! one party owns entirely, fine on one operator's own boxes and unacceptable once a
//! second party runs a node. The daemon refuses to start under this model unless the
//! local development flag is set, so the shortcut cannot leave by accident. See the
//! note in the genesis loader for why, and replace it with operator held keys before
//! the network leaves one pair of hands.

mod config;
mod driver;
mod genesis;
mod mesh;
mod util;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qtv_devnet::config::{DevnetConfig, NodeConfig, FULL_FANOUT};
use qtv_devnet::DevNode;

fn main() {
    match run() {
        Ok(()) => {}
        Err(reason) => {
            util::log(&format!("quantovad stopped: {reason}"));
            std::process::exit(1);
        }
    }
}

/// Parse the command line, refuse a non development start under the derived key
/// model, load the config and genesis, open the node, stand up the mesh, and drive
/// the round until a clean stop or a boundary the daemon cannot cross.
fn run() -> Result<(), String> {
    let args = Args::parse()?;
    guard_derived_keys(args.dev);

    let settings = config::NodeSettings::load(&args.config)?;
    let genesis_file = genesis::GenesisFile::load(&settings.genesis_path)?;

    // The validator set from genesis is the committee. This build derives identity
    // from the id and the mesh indexes a peer by id minus one, so the ids must be the
    // contiguous set one to n. A gap or a duplicate is a build simplification not yet
    // lifted, refused with a clear message rather than mis indexed.
    let mut ids: Vec<u64> = genesis_file
        .genesis
        .validators
        .iter()
        .map(|v| v.id)
        .collect();
    ids.sort_unstable();
    let n = ids.len();
    let expected: Vec<u64> = (1..=n as u64).collect();
    if ids != expected {
        return Err(format!(
            "the genesis validator ids must be the contiguous set 1..={n}, found {ids:?}. \
             numbering validators from one is a current build simplification, since a \
             validator's identity derives from its id"
        ));
    }

    let my_id = settings.id;
    let my_stake = genesis_file
        .genesis
        .validators
        .iter()
        .find(|v| v.id == my_id)
        .map(|v| v.stake)
        .ok_or_else(|| format!("this node's id {my_id} is not in the genesis validator set"))?;
    let idx = (my_id - 1) as usize;

    let devnet = build_devnet(&genesis_file);
    let my_node = NodeConfig {
        id: my_id,
        stake: my_stake,
        online: true,
        store_dir: settings.store_dir.clone(),
        bootstrap: settings.peers.iter().map(|(id, _)| *id).collect(),
        address: settings.listen.clone(),
    };

    let node = DevNode::open(&my_node, &devnet).map_err(|e| format!("opening the node: {e:?}"))?;

    // Place each configured peer's dial address at its validator index. A peer that is
    // this node, or not a genesis validator, is a config error caught here.
    let mut peer_addrs: Vec<Option<String>> = vec![None; n];
    for (pid, addr) in &settings.peers {
        if *pid == my_id {
            return Err(format!("a peer names this node's own id {pid}"));
        }
        if *pid < 1 || *pid as usize > n {
            return Err(format!("peer id {pid} is not a genesis validator, expected 1..={n}"));
        }
        peer_addrs[(*pid - 1) as usize] = Some(addr.clone());
    }

    let port = port_of(&settings.listen)?;
    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|e| format!("binding the transport port {port}: {e}"))?;
    let identity = node.identity().clone();

    log_startup(&settings, &genesis_file, my_id, n, idx, port, &node);

    util::log("standing up the mesh, waiting for any configured peers");
    let mesh = mesh::build_mesh(listener, &peer_addrs, idx, n, &identity, genesis_file.hash);
    util::log("mesh up, driving the round");

    let stop_path = settings.store_dir.join("STOP");
    util::log(&format!(
        "to stop cleanly between blocks, create the file {}",
        stop_path.display()
    ));
    let stopped = Arc::new(AtomicBool::new(false));
    spawn_stop_watcher(stop_path, stopped.clone());

    let mut driver = driver::Driver::new(node, idx, mesh);

    // Stand up the RPC gateway when the config asks for it. It binds its own port and
    // feeds client requests to the round loop over a channel, so the node stays the
    // single owner of its state and the gateway only asks it.
    if let Some(rpc_addr) = settings.rpc_listen.clone() {
        let rpc_listener = TcpListener::bind(&rpc_addr)
            .map_err(|e| format!("binding the RPC address {rpc_addr}: {e}"))?;
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let context = qtv_gateway::NodeContext {
            chain_id: genesis_file.chain_id.clone(),
            genesis_hash_hex: util::hex(&genesis_file.hash),
            fee_params: genesis_file.genesis.fee_params,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        driver.attach_rpc(context, requests_rx);
        qtv_gateway::serve(rpc_listener, requests_tx);
        util::log(&format!("RPC gateway serving on {rpc_addr}"));
    } else {
        util::log("no RPC configured, the node runs with no client facing surface");
    }

    driver.run(
        Duration::from_millis(settings.block_interval_ms),
        Duration::from_millis(settings.view_timeout_ms),
        &stopped,
    )?;

    util::log("stop requested, shut down cleanly");
    Ok(())
}

/// Build the devnet configuration from the parsed genesis. Its genesis reconstructs
/// the parsed one field for field, so every node that opens from the same file funds
/// the same accounts and draws the same committee. The per node store and address
/// fields here are unused, since the running node's own config carries them.
fn build_devnet(genesis_file: &genesis::GenesisFile) -> DevnetConfig {
    let mut validators = genesis_file.genesis.validators.clone();
    validators.sort_by_key(|v| v.id);
    let nodes: Vec<NodeConfig> = validators
        .iter()
        .map(|v| NodeConfig {
            id: v.id,
            stake: v.stake,
            online: v.online,
            store_dir: PathBuf::new(),
            bootstrap: Vec::new(),
            address: String::new(),
        })
        .collect();
    DevnetConfig {
        fee_params: genesis_file.genesis.fee_params,
        accounts: genesis_file.genesis.accounts.clone(),
        nodes,
        genesis_time: genesis_file.genesis.genesis_time,
        fanout: FULL_FANOUT,
        slots: genesis_file.slots,
    }
}

/// Write the startup summary an operator reads to confirm the node came up on the
/// network it meant, at the height it meant, under the key model it meant.
fn log_startup(
    settings: &config::NodeSettings,
    genesis_file: &genesis::GenesisFile,
    my_id: u64,
    n: usize,
    idx: usize,
    port: u16,
    node: &DevNode,
) {
    util::log("starting quantovad");
    util::log(&format!("chain_id {}", genesis_file.chain_id));
    util::log(&format!("genesis_hash {}", util::hex(&genesis_file.hash)));
    util::log(&format!("node id {my_id} of {n} validators, index {idx}"));
    util::log(&format!("stores {}", settings.store_dir.display()));
    util::log(&format!(
        "listen {}, binding port {port} on every interface",
        settings.listen
    ));
    let stored = node.stored_blocks();
    if stored == 0 {
        util::log(&format!("fresh genesis, first height {}", node.height()));
    } else {
        util::log(&format!(
            "resuming from disk, {stored} blocks stored, next height {}",
            node.height()
        ));
    }
    util::log(&format!(
        "slot budget {}, the heights before the one time sortition keys are spent",
        genesis_file.slots
    ));
    util::log(&format!(
        "block interval {} ms, view timeout {} ms",
        settings.block_interval_ms, settings.view_timeout_ms
    ));
    util::log("dev mode on, validator identities are derived from their ids");
    if settings.peers.is_empty() {
        util::log("no peers configured, this node is a committee of one and its own supermajority");
    } else {
        util::log(&format!("{} peers configured", settings.peers.len()));
    }
}

/// The port of a `host:port` address, the one this process binds on every interface.
fn port_of(addr: &str) -> Result<u16, String> {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| format!("listen address '{addr}' is not host:port with a numeric port"))
}

/// Poll for the stop file and set the stop flag when it appears, so an operator stops
/// the daemon cleanly between blocks by creating that file. An abrupt kill is also
/// safe, since the store commits after every finalised block and recovers a torn
/// tail, so the graceful path is a convenience and not a correctness requirement.
fn spawn_stop_watcher(path: PathBuf, stopped: Arc<AtomicBool>) {
    thread::spawn(move || loop {
        if path.exists() {
            stopped.store(true, Ordering::SeqCst);
            return;
        }
        if stopped.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    });
}

/// The hard guard on the derived key model. This build derives every validator's
/// identity from its id, so the daemon refuses to start unless the local development
/// flag is set, and it stops rather than let the shortcut slide into a posture where a
/// second party trusts an identity the first party can forge.
fn guard_derived_keys(dev: bool) {
    if dev {
        return;
    }
    eprintln!(
        "\nquantovad refuses to start.\n\n\
         This build derives every validator's identity from its numeric id. Whoever holds\n\
         this genesis can name a validator id and so controls that validator's identity. It\n\
         is a chain one party owns entirely, which is fine on that party's own machines and\n\
         unacceptable the moment a second party runs a node, because the second party's\n\
         identity would be one the first can forge.\n\n\
         Pass --dev to run under this derived key model on your own boxes. Operator held\n\
         keys, one secret per validator that no one else can derive, are the required next\n\
         step before the network leaves one pair of hands.\n\n\
         Stopping rather than letting this slide because it happens to work.\n"
    );
    std::process::exit(1);
}

/// The parsed command line.
struct Args {
    config: PathBuf,
    dev: bool,
}

impl Args {
    /// Parse `quantovad --config <path> [--dev]`, accepting `--config=<path>` too.
    fn parse() -> Result<Args, String> {
        let mut config: Option<PathBuf> = None;
        let mut dev = false;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--dev" => dev = true,
                "--config" => {
                    let path = args.next().ok_or("--config needs a path")?;
                    config = Some(PathBuf::from(path));
                }
                "--help" | "-h" => {
                    println!("usage: quantovad --config <path> [--dev]");
                    std::process::exit(0);
                }
                other => match other.strip_prefix("--config=") {
                    Some(path) => config = Some(PathBuf::from(path)),
                    None => {
                        return Err(format!(
                            "unknown argument '{other}'. usage: quantovad --config <path> [--dev]"
                        ))
                    }
                },
            }
        }
        let config = config
            .ok_or("missing --config <path>. usage: quantovad --config <path> [--dev]")?;
        Ok(Args { config, dev })
    }
}
