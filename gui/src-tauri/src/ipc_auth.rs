use std::path::PathBuf;
use std::sync::Mutex;

pub const ENV_NAME: &str = "SENTINELLA_IPC_SECRET";

/// Cached secret as a leaked &'static str — only set after we've actually
/// read the daemon's file. Until then, each call re-checks so we pick up
/// the secret once the daemon writes it.
static CACHED_SECRET: Mutex<Option<&'static str>> = Mutex::new(None);
/// Empty static string returned when the daemon hasn't written its secret yet.
/// Calls using this will fail validation server-side; caller should retry.
const EMPTY_SECRET: &str = "";

pub fn secret() -> &'static str {
    // Fast path: if we already have it cached, return.
    {
        let guard = CACHED_SECRET.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = *guard {
            return s;
        }
    }

    // Try to load now.
    if let Some(loaded) = try_load_secret() {
        // Box::leak gives us a true 'static reference. We never free it — the
        // secret lives for the lifetime of the process, which is correct.
        let leaked: &'static str = Box::leak(loaded.into_boxed_str());
        let mut guard = CACHED_SECRET.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(leaked);
        return leaked;
    }

    // Daemon hasn't written secret yet. Return empty — call will fail server-side
    // with a meaningful error. NEVER generate our own secret (would create split-brain).
    EMPTY_SECRET
}

/// Force-reload from disk (clears cache).
/// Useful after detecting auth failures — daemon may have rotated the secret.
#[allow(dead_code)]
pub fn invalidate_cache() {
    let mut guard = CACHED_SECRET.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn try_load_secret() -> Option<String> {
    // 1. Environment variable (highest priority — set by supervisor for spawned daemons).
    if let Ok(secret) = std::env::var(ENV_NAME) {
        if secret.len() >= 32 {
            return Some(secret);
        }
    }

    // 2. Read from disk — try all candidate paths.
    for path in secret_path_candidates() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let trimmed = content.trim().to_string();
            if trimmed.len() >= 32 {
                return Some(trimmed);
            }
        }
    }

    // Daemon hasn't written it yet. Don't generate — would never match.
    None
}

fn secret_path_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // 1. Installed mode (most common): ProgramData.
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    candidates.push(PathBuf::from(&pd).join("Sentinella").join("state").join("ipc_secret"));

    // 2. Dev mode: walk up from CWD to find project root.
    if let Ok(cwd) = std::env::current_dir() {
        for dir in cwd.ancestors() {
            if dir.join("crates").join("sentinelld").exists() {
                candidates.push(dir.join("runtime").join("state").join("ipc_secret"));
                break;
            }
        }
    }

    // 3. Dev mode: walk up from exe location.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for ancestor in dir.ancestors() {
                if ancestor.join("crates").join("sentinelld").exists() {
                    candidates.push(ancestor.join("runtime").join("state").join("ipc_secret"));
                    break;
                }
            }
        }
    }

    candidates
}
