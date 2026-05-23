use rand::RngCore;
use std::path::PathBuf;
use std::sync::OnceLock;

pub const ENV_NAME: &str = "SENTINELLA_IPC_SECRET";

static IPC_SECRET: OnceLock<String> = OnceLock::new();

pub fn secret() -> &'static str {
    IPC_SECRET.get_or_init(load_or_create_secret)
}

fn load_or_create_secret() -> String {
    if let Ok(secret) = std::env::var(ENV_NAME) {
        if secret.len() >= 32 {
            persist_if_missing(&secret);
            return secret;
        }
    }

    let path = secret_path();
    if let Ok(secret) = std::fs::read_to_string(&path) {
        let trimmed = secret.trim().to_string();
        if trimmed.len() >= 32 {
            return trimmed;
        }
    }

    let secret = generate_secret();
    persist_secret(&secret);
    secret
}

fn secret_path() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        for dir in cwd.ancestors() {
            if dir.join("crates").join("sentinelld").exists() {
                return dir.join("runtime").join("state").join("ipc_secret");
            }
        }
        for dir in cwd.ancestors() {
            let candidate = dir.join("runtime").join("state").join("ipc_secret");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("runtime/state/ipc_secret")
}

fn persist_if_missing(secret: &str) {
    let path = secret_path();
    if !path.exists() {
        persist_secret(secret);
    }
}

fn persist_secret(secret: &str) {
    let path = secret_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, secret);
}

fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
