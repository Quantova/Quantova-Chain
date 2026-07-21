
use std::path::{Path, PathBuf};

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
    pub block_interval_ms: u64,
    pub view_timeout_ms: u64,
    pub peers: Vec<(u64, String)>,
    pub rpc_listen: Option<String>,
    pub block_messages_path: Option<PathBuf>,
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
