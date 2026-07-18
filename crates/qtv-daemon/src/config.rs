//! The per node config file and the shared `key = value` parser both this file and
//! the genesis file are read with.
//!
//! The config is what makes one process this validator rather than that one: its
//! id, where its stores live, the address it binds, the genesis it opens from, how
//! fast it paces blocks, and the peers it dials. Everything the whole network must
//! agree on, the fee schedule, the fund, the validator set and their stakes, lives
//! in the genesis, not here, so there is one source of truth for consensus and this
//! file only carries what is local to the box.

use std::path::{Path, PathBuf};

/// One parsed `key = value` line, carrying its source location so a malformed value
/// is reported against the exact line an operator can open and fix.
pub struct Field {
    pub key: String,
    pub value: String,
    pub file: String,
    pub line: usize,
}

impl Field {
    /// A parse error against this field's source line.
    pub fn error(&self, message: &str) -> String {
        format!("{}:{}: {message}", self.file, self.line)
    }

    /// This field's value as a u64, or a message naming the line.
    pub fn u64(&self, name: &str) -> Result<u64, String> {
        self.value
            .trim()
            .parse()
            .map_err(|_| self.error(&format!("'{name}' is not a whole number")))
    }

    /// This field's value as a u128, for the fee schedule figures.
    pub fn u128(&self, name: &str) -> Result<u128, String> {
        self.value
            .trim()
            .parse()
            .map_err(|_| self.error(&format!("'{name}' is not a whole number")))
    }
}

/// Parse a `key = value` text into fields, in file order, keeping repeated keys so a
/// caller can collect the many `validator`, `account`, and `peer` lines. A blank
/// line and everything after a `#` is a comment. A line with no `=` is a malformed
/// line reported against its number rather than silently skipped.
pub fn parse_kv(text: &str, path: &Path) -> Result<Vec<Field>, String> {
    let file = path.display().to_string();
    let mut fields = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let content = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        }
        .trim();
        if content.is_empty() {
            continue;
        }
        let Some((key, value)) = content.split_once('=') else {
            return Err(format!("{file}:{line}: a line is not 'key = value'"));
        };
        fields.push(Field {
            key: key.trim().to_string(),
            value: value.trim().to_string(),
            file: file.clone(),
            line,
        });
    }
    Ok(fields)
}

/// The default block interval in milliseconds, the cadence a healthy leader proposes
/// at. A live chain proposes on a clock rather than waiting for traffic that may
/// never come, so an idle chain still advances with empty blocks and a busy one
/// carries whatever the mempool holds.
pub const DEFAULT_BLOCK_INTERVAL_MS: u64 = 1000;

/// The default view timeout in milliseconds, the wall clock a view is given before a
/// node moves to route around a silent or dropped leader. It sits above the block
/// interval so a healthy leader that is merely a little late is never rotated.
pub const DEFAULT_VIEW_TIMEOUT_MS: u64 = 2000;

/// The parsed node config: everything local to this box.
pub struct NodeSettings {
    /// This node's consensus id. It must be one of the genesis validators.
    pub id: u64,
    /// Where this node's block and state stores live. A restart reopens them and
    /// resumes the chain from the last finalised block.
    pub store_dir: PathBuf,
    /// The address this node binds and peers dial, `host:port`. Only the port is
    /// bound, on every interface; the host part is how peers reach this box.
    pub listen: String,
    /// The genesis file every node in the network opens from, shared and identical.
    pub genesis_path: PathBuf,
    /// The block cadence in milliseconds.
    pub block_interval_ms: u64,
    /// The view timeout in milliseconds.
    pub view_timeout_ms: u64,
    /// The peers this node dials, each a genesis validator id and its socket address.
    /// A single node network lists none and is its own supermajority.
    pub peers: Vec<(u64, String)>,
    /// The address the RPC gateway binds, `host:port`, when the node should serve the
    /// RPC. Absent leaves the node running with no client facing surface, the posture
    /// item one shipped in.
    pub rpc_listen: Option<String>,
    /// An optional local file of header notes to stamp by height, one line per
    /// block as `QTV|<height>|<note>`. The whole line is the note. It stays a local
    /// operator file and is never part of the genesis or any repository, so its
    /// contents reach the chain only through the blocks this node produces.
    pub block_messages_path: Option<PathBuf>,
}

impl NodeSettings {
    /// Load and parse a node config file. A relative genesis path is resolved against
    /// the config file's own directory, so a config and its genesis can travel
    /// together as a pair.
    pub fn load(path: &Path) -> Result<NodeSettings, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading config file {}: {e}", path.display()))?;
        let fields = parse_kv(&text, path)?;

        let mut id: Option<u64> = None;
        let mut store_dir: Option<PathBuf> = None;
        let mut listen: Option<String> = None;
        let mut genesis_path: Option<PathBuf> = None;
        let mut block_interval_ms = DEFAULT_BLOCK_INTERVAL_MS;
        let mut view_timeout_ms = DEFAULT_VIEW_TIMEOUT_MS;
        let mut peers: Vec<(u64, String)> = Vec::new();
        let mut rpc_listen: Option<String> = None;
        let mut block_messages_path: Option<PathBuf> = None;

        for field in &fields {
            match field.key.as_str() {
                "id" => id = Some(field.u64("id")?),
                "store_dir" => store_dir = Some(PathBuf::from(&field.value)),
                "listen" => listen = Some(field.value.clone()),
                "genesis" => genesis_path = Some(PathBuf::from(&field.value)),
                "block_interval_ms" => block_interval_ms = field.u64("block_interval_ms")?,
                "view_timeout_ms" => view_timeout_ms = field.u64("view_timeout_ms")?,
                "peer" => peers.push(parse_peer(field)?),
                "rpc" => rpc_listen = Some(field.value.clone()),
                "block_messages" => block_messages_path = Some(PathBuf::from(&field.value)),
                other => return Err(field.error(&format!("unknown config key '{other}'"))),
            }
        }

        let genesis_path = genesis_path.ok_or("the config is missing 'genesis'")?;
        let genesis_path = resolve(path, genesis_path);
        let block_messages_path = block_messages_path.map(|p| resolve(path, p));

        Ok(NodeSettings {
            id: id.ok_or("the config is missing 'id'")?,
            store_dir: store_dir.ok_or("the config is missing 'store_dir'")?,
            listen: listen.ok_or("the config is missing 'listen'")?,
            genesis_path,
            block_interval_ms,
            view_timeout_ms,
            peers,
            rpc_listen,
            block_messages_path,
        })
    }
}

/// Parse a peer line, `peer = <id>@<host:port>`, naming a genesis validator and the
/// address this node dials it at.
fn parse_peer(field: &Field) -> Result<(u64, String), String> {
    let Some((id, addr)) = field.value.split_once('@') else {
        return Err(field.error("a peer is '<id>@<host:port>'"));
    };
    let id: u64 = id
        .trim()
        .parse()
        .map_err(|_| field.error("the peer id is not a number"))?;
    let addr = addr.trim().to_string();
    if addr.is_empty() {
        return Err(field.error("the peer address is empty"));
    }
    Ok((id, addr))
}

/// Resolve a possibly relative path against the directory of the config file it was
/// read from, so a genesis named relative to the config is found wherever the pair
/// is placed.
fn resolve(config_path: &Path, target: PathBuf) -> PathBuf {
    if target.is_absolute() {
        return target;
    }
    match config_path.parent() {
        Some(dir) => dir.join(target),
        None => target,
    }
}
