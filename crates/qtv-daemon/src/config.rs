// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::{Path, PathBuf};

use crate::util::from_hex;

pub struct Field {
    pub key: String,
    pub value: String,
    pub file: String,
    pub line: usize,
}

impl Field {
    pub fn error(&self, message: &str) -> String {
        format!("{}:{}: {message}", self.file, self.line)
    }

    pub fn u64(&self, name: &str) -> Result<u64, String> {
        self.value
            .trim()
            .parse()
            .map_err(|_| self.error(&format!("'{name}' is not a whole number")))
    }

    pub fn u128(&self, name: &str) -> Result<u128, String> {
        self.value
            .trim()
            .parse()
            .map_err(|_| self.error(&format!("'{name}' is not a whole number")))
    }

    pub fn u32(&self, name: &str) -> Result<u32, String> {
        self.value
            .trim()
            .parse()
            .map_err(|_| self.error(&format!("'{name}' is not a whole number")))
    }
}

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

pub const DEFAULT_BLOCK_INTERVAL_MS: u64 = 1000;

pub const DEFAULT_VIEW_TIMEOUT_MS: u64 = 2000;

pub struct NodeSettings {
    pub id: u64,
    pub store_dir: PathBuf,
    pub listen: String,
    pub genesis_path: PathBuf,
    pub keystore_path: PathBuf,
    pub block_interval_ms: u64,
    pub view_timeout_ms: u64,
    pub peers: Vec<(u64, String)>,
    pub rpc_listen: Option<String>,
    pub rpc_allow: Vec<String>,
    pub block_messages_path: Option<PathBuf>,
    pub checkpoint: Option<(u64, [u8; 32])>,
}

impl NodeSettings {
    pub fn load(path: &Path) -> Result<NodeSettings, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading config file {}: {e}", path.display()))?;
        let fields = parse_kv(&text, path)?;

        let mut id: Option<u64> = None;
        let mut store_dir: Option<PathBuf> = None;
        let mut listen: Option<String> = None;
        let mut genesis_path: Option<PathBuf> = None;
        let mut keystore_path: Option<PathBuf> = None;
        let mut block_interval_ms = DEFAULT_BLOCK_INTERVAL_MS;
        let mut view_timeout_ms = DEFAULT_VIEW_TIMEOUT_MS;
        let mut peers: Vec<(u64, String)> = Vec::new();
        let mut rpc_listen: Option<String> = None;
        let mut rpc_allow: Vec<String> = Vec::new();
        let mut block_messages_path: Option<PathBuf> = None;
        let mut checkpoint: Option<(u64, [u8; 32])> = None;

        for field in &fields {
            match field.key.as_str() {
                "id" => id = Some(field.u64("id")?),
                "store_dir" => store_dir = Some(PathBuf::from(&field.value)),
                "listen" => listen = Some(field.value.clone()),
                "genesis" => genesis_path = Some(PathBuf::from(&field.value)),
                "keystore" => keystore_path = Some(PathBuf::from(&field.value)),
                "block_interval_ms" => block_interval_ms = field.u64("block_interval_ms")?,
                "view_timeout_ms" => view_timeout_ms = field.u64("view_timeout_ms")?,
                "peer" => peers.push(parse_peer(field)?),
                "rpc" => rpc_listen = Some(field.value.clone()),
                "rpc_allow" => {
                    let mut addrs = Vec::new();
                    for entry in field
                        .value
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                    {
                        if entry.parse::<std::net::IpAddr>().is_err() {
                            return Err(field.error(&format!(
                                "'rpc_allow' entry '{entry}' is not a bare IP address; \
                                 list comma separated IPs, not a CIDR range or a hostname"
                            )));
                        }
                        addrs.push(entry.to_string());
                    }
                    rpc_allow = addrs;
                }
                "block_messages" => block_messages_path = Some(PathBuf::from(&field.value)),
                "checkpoint" => checkpoint = Some(parse_checkpoint(field)?),
                other => return Err(field.error(&format!("unknown config key '{other}'"))),
            }
        }

        let genesis_path = genesis_path.ok_or("the config is missing 'genesis'")?;
        let genesis_path = resolve(path, genesis_path);
        let block_messages_path = block_messages_path.map(|p| resolve(path, p));
        let store_dir = store_dir.ok_or("the config is missing 'store_dir'")?;
        let keystore_path = match keystore_path {
            Some(p) => resolve(path, p),
            None => store_dir.join("keystore"),
        };

        Ok(NodeSettings {
            id: id.ok_or("the config is missing 'id'")?,
            store_dir,
            listen: listen.ok_or("the config is missing 'listen'")?,
            genesis_path,
            keystore_path,
            block_interval_ms,
            view_timeout_ms,
            peers,
            rpc_listen,
            rpc_allow,
            block_messages_path,
            checkpoint,
        })
    }
}

fn parse_checkpoint(field: &Field) -> Result<(u64, [u8; 32]), String> {
    let parts: Vec<&str> = field.value.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(field.error("a checkpoint is '<height> <value_hex>'"));
    }
    let height: u64 = parts[0]
        .parse()
        .map_err(|_| field.error("the checkpoint height is not a number"))?;
    let bytes =
        from_hex(parts[1]).map_err(|e| field.error(&format!("the checkpoint value {e}")))?;
    let value = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| field.error("the checkpoint value must be thirty two bytes"))?;
    Ok((height, value))
}

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

fn resolve(config_path: &Path, target: PathBuf) -> PathBuf {
    if target.is_absolute() {
        return target;
    }
    match config_path.parent() {
        Some(dir) => dir.join(target),
        None => target,
    }
}
