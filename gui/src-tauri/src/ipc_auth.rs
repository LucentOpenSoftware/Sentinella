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
            eprintln!("[ipc_auth] loaded secret from env var");
            return secret;
        }
    }

    let path = secret_path();
    eprintln!("[ipc_auth] secret_path resolved to: {}", path.display());
    if let Ok(secret) = std::fs::read_to_string(&path) {
        let trimmed = secret.trim().to_string();
        if trimmed.len() >= 32 {
            eprintln!("[ipc_auth] loaded secret from file ({} chars)", trimmed.len());
            return trimmed;
        }
    }

    eprintln!("[ipc_auth] WARNING: generating NEW secret (daemon will reject!)");
    let secret = generate_secret();
    persist_secret(&secret);
    secret
}

fn secret_path() -> PathBuf {
    // Dev mode: walk up from CWD to find project root (has crates/sentinelld).
    if let Ok(cwd) = std::env::current_dir() {
        for dir in cwd.ancestors() {
            if dir.join("crates").join("sentinelld").exists() {
                return dir.join("runtime").join("state").join("ipc_secret");
            }
        }
    }
    // Installed mode: walk up from exe location.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for ancestor in dir.ancestors() {
                if ancestor.join("crates").join("sentinelld").exists() {
                    return ancestor.join("runtime").join("state").join("ipc_secret");
                }
            }
        }
    }
    // Fallback: ProgramData or CWD-relative.
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let installed = PathBuf::from(&pd).join("Sentinella").join("state").join("ipc_secret");
    if installed.exists() {
        return installed;
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
