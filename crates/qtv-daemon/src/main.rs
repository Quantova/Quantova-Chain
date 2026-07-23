
mod config;
mod driver;
mod genesis;
mod mesh;
mod util;

use std::collections::HashMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qtv_devnet::config::{DevnetConfig, NodeConfig, FULL_FANOUT};
use qtv_devnet::node::peer_id_of;
use qtv_devnet::DevNode;
use qtv_net::PeerId;
use qtv_node::consensus::ValidatorRegistration;
use qtv_node::node::ValidatorSpec;

fn main() {
    let outcome = match Command::parse() {
        Ok(Command::Run { config }) => run(&config),
        Ok(Command::Register(args)) => register(args),
        Err(reason) => Err(reason),
    };
    if let Err(reason) = outcome {
        util::log(&format!("quantovad stopped: {reason}"));
        std::process::exit(1);
    }
}

fn run(config_path: &Path) -> Result<(), String> {
    let settings = config::NodeSettings::load(config_path)?;
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
             the id is only this build's index into the peer and address tables, not a source \
             of any key material, and numbering from one is a current build simplification"
        ));
    }

    let my_id = settings.id;
    let my_spec = genesis_file
        .genesis
        .validators
        .iter()
        .find(|v| v.id == my_id)
        .cloned()
        .ok_or_else(|| format!("this node's id {my_id} is not in the genesis validator set"))?;
    let idx = (my_id - 1) as usize;

    let secret = qtv_node::keys::load_or_generate(&settings.keystore_path).map_err(|e| {
        format!("reading the keystore {}: {e}", settings.keystore_path.display())
    })?;

    let own = ValidatorSpec::from_secret(
        my_id,
        my_spec.stake,
        my_spec.online,
        &secret,
        genesis_file.slots,
    );
    if own != my_spec {
        return Err(format!(
            "the keystore {} does not hold the secret behind this node's genesis registration \
             for id {my_id}. Regenerate the genesis line from this keystore with 'quantovad \
             register', or point the config at the keystore that produced the published line",
            settings.keystore_path.display()
        ));
    }

    let devnet = build_devnet(&genesis_file);
    let my_node = NodeConfig {
        id: my_id,
        stake: my_spec.stake,
        online: true,
        store_dir: settings.store_dir.clone(),
        bootstrap: settings.peers.iter().map(|(id, _)| *id).collect(),
        address: settings.listen.clone(),
        secret,
    };

    let mut node =
        DevNode::open(&my_node, &devnet).map_err(|e| format!("opening the node: {e:?}"))?;

    if let Some((height, value)) = settings.checkpoint {
        node.set_checkpoint(qtv_devnet::Checkpoint { height, value });
        util::log(&format!(
            "carrying weak subjectivity checkpoint at height {height}, refusing any sync that \
             conflicts with it",
        ));
    }

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

    let mut peer_ids: Vec<Option<PeerId>> = vec![None; n];
    for v in &genesis_file.genesis.validators {
        peer_ids[(v.id - 1) as usize] = Some(peer_id_of(&v.p2p_public));
    }

    let port = port_of(&settings.listen)?;
    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|e| format!("binding the transport port {port}: {e}"))?;
    let identity = node.identity().clone();

    log_startup(&settings, &genesis_file, my_id, n, idx, port, &node);

    util::log("standing up the mesh, waiting for any configured peers");
    let mesh = mesh::build_mesh(
        listener,
        &peer_addrs,
        &peer_ids,
        idx,
        n,
        &identity,
        genesis_file.hash,
    );
    util::log("mesh up, driving the round");

    let stop_path = settings.store_dir.join("STOP");
    util::log(&format!(
        "to stop cleanly between blocks, create the file {}",
        stop_path.display()
    ));
    let stopped = Arc::new(AtomicBool::new(false));
    spawn_stop_watcher(stop_path, stopped.clone());

    let mut driver = driver::Driver::new(node, idx, mesh);

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
    let roster: Vec<ValidatorRegistration> = genesis_file
        .genesis
        .validators
        .iter()
        .map(ValidatorRegistration::from_spec)
        .collect();
    DevnetConfig {
        fee_params: genesis_file.genesis.fee_params,
        accounts: genesis_file.genesis.accounts.clone(),
        nodes: Vec::new(),
        genesis_time: genesis_file.genesis.genesis_time,
        fanout: FULL_FANOUT,
        slots: genesis_file.slots,
        published_roster: Some(roster),
    }
}

fn register(args: RegisterArgs) -> Result<(), String> {
    let secret = qtv_node::keys::load_or_generate(&args.keystore)
        .map_err(|e| format!("reading the keystore {}: {e}", args.keystore.display()))?;
    let spec = ValidatorSpec::from_secret(args.id, args.stake, args.online, &secret, args.slots);
    let online = if spec.online { "online" } else { "offline" };
    println!(
        "validator = {} {} {} {} {} {} {}",
        spec.id,
        spec.stake,
        online,
        spec.bond_address,
        util::hex(&spec.root.digest),
        util::hex(&spec.attest_pk),
        util::hex(&spec.p2p_public),
    );
    Ok(())
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
    util::log(&format!("keystore {}", settings.keystore_path.display()));
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
        "epoch length {} heights, the validators rotate their one time keys on each boundary and run on",
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
    util::log(
        "the node holds only its own secret from its keystore and reads every peer's public \
         registration from genesis; the committee forms from the reveals each validator publishes",
    );
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

enum Command {
    Run { config: PathBuf },
    Register(RegisterArgs),
}

struct RegisterArgs {
    keystore: PathBuf,
    id: u64,
    stake: u64,
    online: bool,
    slots: u64,
}

const USAGE: &str = "usage: quantovad --config <path>\n       quantovad register --keystore <path> \
                     --id <id> --stake <stake> [--online|--offline] --slots <slots>";

impl Command {
    fn parse() -> Result<Command, String> {
        let mut args = std::env::args().skip(1);
        let first = args.next();
        if first.as_deref() == Some("register") {
            return Ok(Command::Register(RegisterArgs::parse(args)?));
        }
        let mut config: Option<PathBuf> = None;
        let mut current = first;
        while let Some(arg) = current.take() {
            match arg.as_str() {
                "--config" => {
                    let path = args.next().ok_or("--config needs a path")?;
                    config = Some(PathBuf::from(path));
                }
                "--help" | "-h" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                other => match other.strip_prefix("--config=") {
                    Some(path) => config = Some(PathBuf::from(path)),
                    None => return Err(format!("unknown argument '{other}'. {USAGE}")),
                },
            }
            current = args.next();
        }
        let config = config.ok_or_else(|| format!("missing --config <path>. {USAGE}"))?;
        Ok(Command::Run { config })
    }
}

impl RegisterArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<RegisterArgs, String> {
        let mut keystore: Option<PathBuf> = None;
        let mut id: Option<u64> = None;
        let mut stake: Option<u64> = None;
        let mut online = true;
        let mut slots: Option<u64> = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--keystore" => keystore = Some(PathBuf::from(need(&mut args, "--keystore")?)),
                "--id" => id = Some(parse_u64(&mut args, "--id")?),
                "--stake" => stake = Some(parse_u64(&mut args, "--stake")?),
                "--slots" => slots = Some(parse_u64(&mut args, "--slots")?),
                "--online" => online = true,
                "--offline" => online = false,
                other => return Err(format!("unknown register argument '{other}'. {USAGE}")),
            }
        }
        Ok(RegisterArgs {
            keystore: keystore.ok_or("register needs --keystore <path>")?,
            id: id.ok_or("register needs --id <id>")?,
            stake: stake.ok_or("register needs --stake <stake>")?,
            online,
            slots: slots.ok_or("register needs --slots <slots>")?,
        })
    }
}

fn need(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_u64(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<u64, String> {
    need(args, flag)?
        .parse()
        .map_err(|_| format!("{flag} needs a whole number"))
}
