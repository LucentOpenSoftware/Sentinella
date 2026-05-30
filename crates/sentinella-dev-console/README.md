# Sentinella Dev Console

**Internal tool — not shipped in the public installer.** Single-binary native
GUI (`eframe`+`egui`, no webview) for the Sentinella developer center to
provision Developer Mode and run the ARGUS hardware-parity benchmark
against a locally-installed `SentinellaDaemon`.

## What it does

Two tabs in v1:

### Setup
- Detects the installed `SentinellaDaemon` service (`sc query` state).
- Reads `<ProgramData>\Sentinella\config\sentinelld.toml` to show the live
  `[developer]` section: provisioned? enabled? telemetry?
- **Provision + enable**: takes a plaintext password, shows the
  lowercase-hex SHA-256 live, writes it into the TOML via `toml_edit`
  (preserves all comments and existing formatting), then `sc stop` +
  `sc start` so the daemon picks up the new hash.
- **Enable / Disable / Revoke**: toggle without rewriting the password
  hash. Revoke clears the hash AND disables.
- Atomic write: `sentinelld.toml.tmp` → `fsync` → rename. Mirrors the
  daemon's own R3 durability pattern.

### Benchmark
- Finds `argusd.exe` next to the installed daemon
  (`<Program Files>\Sentinella\daemon\argusd.exe` etc.).
- Spawns `argusd.exe benchmark --json --passes N` with
  `CREATE_NO_WINDOW` (no flashing console).
- Renders the report: **Performance Index**, files/sec, MB/sec, p50/p95/
  max/mean per-file µs, logical cores, SIMD flags, extra fields verbatim.
- "Save raw JSON…" drops a timestamped report into `%TEMP%` for cross-
  machine comparisons.

## Build + run

```cmd
cargo build --release -p sentinella-dev-console
target\release\sentinella-dev-console.exe
```

Service operations (the Provision / Enable / Disable / Revoke buttons and
the `sc stop/start` they wrap) need an elevated process. The footer shows
a warning if the dev console isn't running elevated.

Benchmark works without elevation — it just shells out to `argusd.exe`.

## Threat model

This tool is **not** an auth boundary; it's a convenience around the
existing `[developer]` config section. Anyone with admin on a machine
that has `sentinelld` installed can flip developer mode by hand — the
dev console just makes it ergonomic.

The IPC client (used for the `health` lookup that shows daemon version +
uptime) reads the same world-readable IPC secret file as the production
GUI, gated by the same daemon-side auth checks. No bypasses.

## Distribution

Built locally by each developer; not bundled in the NSIS installer. If
the team wants a shared signed copy later, add a step to whatever
release pipeline produces the public Tauri bundle — the binary is
~5 MB and statically links everything it needs.
