
mod config;
mod driver;
mod genesis;
mod mesh;
mod util;

use std::collections::HashMap;
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

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    guard_derived_keys(args.dev);

    let settings = config::NodeSettings::load(&args.config)?;
    let genesis_file = genesis::GenesisFile::load(&settings.genesis_path)?;

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

    let mut node =
        DevNode::open(&my_node, &devnet).map_err(|e| format!("opening the node: {e:?}"))?;

    if let Some(msg_path) = &settings.block_messages_path {
        let messages = load_block_messages(msg_path)?;
        util::log(&format!(
            "loaded {} header notes from {}, stamped into the blocks this node proposes",
            messages.len(),
            msg_path.display()
        ));
        node.set_block_messages(messages);
    }

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
    driver.set_budget(genesis_file.slots);

    if let Some(rpc_addr) = settings.rpc_listen.clone() {
        let rpc_listener = TcpListener::bind(&rpc_addr)
            .map_err(|e| format!("binding the RPC address {rpc_addr}: {e}"))?;
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let context = qtv_gateway::NodeContext {
            chain_id: genesis_file.chain_id.clone(),
            genesis_hash_hex: util::hex(&genesis_file.hash),
            asset: genesis_file.asset.clone(),
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
    if !genesis_file.message.is_empty() {
        util::log(&format!("genesis message, {}", genesis_file.message));
    }
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
        "fee band five hundredths to one tenth of a cent, native ceiling {} base units",
        genesis_file.genesis.fee_params.max_fee_native
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

fn load_block_messages(path: &PathBuf) -> Result<HashMap<u64, Vec<u8>>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading block messages {}: {e}", path.display()))?;
    let mut messages = HashMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        let number = index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, '|');
        if parts.next() != Some("QTV") {
            return Err(format!(
                "block messages line {number} is not 'QTV|<height>|<note>': {line}"
            ));
        }
        let height: u64 = parts
            .next()
            .ok_or_else(|| format!("block messages line {number} has no height"))?
            .trim()
            .parse()
            .map_err(|_| format!("block messages line {number} has a non numeric height"))?;
        let note = line.as_bytes().to_vec();
        if note.len() > qtv_block::MAX_EXTRA_DATA {
            return Err(format!(
                "block messages line {number} is {} bytes, over the {} byte header limit",
                note.len(),
                qtv_block::MAX_EXTRA_DATA
            ));
        }
        messages.insert(height, note);
    }
    Ok(messages)
}

fn port_of(addr: &str) -> Result<u16, String> {
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| format!("listen address '{addr}' is not host:port with a numeric port"))
}

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

struct Args {
    config: PathBuf,
    dev: bool,
}

impl Args {
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
