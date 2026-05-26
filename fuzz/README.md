# Sentinella Fuzz Testing

Offensive fuzzing infrastructure for ASTRA engine resilience.

## Philosophy

Sentinella fuzzing focuses on:
- **Bounded behavior** — no input produces unbounded allocation, runtime, or score
- **Parser resilience** — every parser handles malformed input without panic
- **Convergence integrity** — scoring is deterministic, capped, and consistent
- **Deterministic failure** — crashes are reproducible, not heisenbug
- **Graceful degradation** — partial/corrupt input produces safe defaults, not UB

The goal is not only crash prevention, but protection against
**adversarial malformed input** — the kind an attacker crafts deliberately.

## Setup

```bash
# Linux / WSL2 (required for cargo-fuzz):
rustup install nightly
cargo install cargo-fuzz
```

### Platform Requirements

**cargo fuzz requires Linux.** Windows has fundamental toolchain limitations:
- MSVC: missing SanCov section symbols (`__start___sancov_*`)
- GNU/MinGW: libFuzzer C++ source fails to compile with MinGW g++
- Both: ASan runtime library not bundled with Rust nightly on Windows

These are documented honestly — not hidden. Future maintainers:
do not waste time trying to make `cargo fuzz` work on Windows MSVC.

```bash
# WSL2 / Linux (required for fuzzing):
cd /mnt/c/Users/Nicolas/Desktop/sentinella/fuzz
cargo +nightly fuzz run fuzz_convergence -- -max_total_time=900

# Windows (CI alternative — 389 deterministic tests):
cargo test --workspace
```

### Coverage-Only Mode

Even without ASan/UBSan, coverage-guided fuzzing still finds:
- Parser panics (unwrap, index out of bounds)
- Infinite recursion / stack overflow
- Hangs and timeouts
- Score inconsistencies (assertion failures)
- Allocation amplification (small input → huge allocation)
- Malformed state transitions

**No sanitizer ≠ useless fuzzing.** Coverage feedback alone discovers
the majority of parser bugs. Sanitizers add memory-safety detection
on top of that.

## Fuzz Targets

| Target | What It Tests | Priority |
|---|---|---|
| `fuzz_ipc_frame` | JSON-RPC frame parsing, method dispatch validation | Critical |
| `fuzz_argus_pe` | PE analysis, entropy, imports, structural heuristics | Critical |
| `fuzz_convergence` | Score aggregation, verdict consistency, cap enforcement | High |
| `fuzz_etw_parser` | ETW event data parsing, UTF-16, path extraction | High |
| `fuzz_paths` | Path parsing, skip logic, exclusion matching, Unicode | High |

## Running

```bash
cd fuzz/

# Run a specific target (15 minutes, recommended smoke duration)
cargo +nightly fuzz run fuzz_argus_pe -- \
  -max_total_time=900 \
  -timeout=10 \
  -rss_limit_mb=2048 \
  -max_len=65536

# Run all targets sequentially (1 hour each)
for target in fuzz_ipc_frame fuzz_argus_pe fuzz_convergence fuzz_etw_parser fuzz_paths; do
  cargo +nightly fuzz run $target -- \
    -max_total_time=3600 \
    -timeout=10 \
    -rss_limit_mb=2048 \
    -max_len=65536
done
```

### Recommended Flags

| Flag | Value | Why |
|---|---|---|
| `-timeout=10` | 10 seconds | Catches hangs without waiting forever |
| `-rss_limit_mb=2048` | 2 GB | Catches allocation amplification |
| `-max_len=65536` | 64 KB | Reasonable input size for most parsers |
| `-max_total_time=900` | 15 min | Smoke test duration |
| `-fork=4` | 4 processes | Parallel fuzzing (optional) |

## Corpus

Seed corpus lives in `corpus/<target>/`. Crash reproductions go
in `artifacts/<target>/`.

```
corpus/
  ipc/          # JSON-RPC frames (5 seeds)
  argus/        # PE/binary samples (3 seeds)
  convergence/  # Structured fuzzer input (2 seeds)
  etw/          # ETW event payloads (2 seeds)
  paths/        # Adversarial path strings (3 seeds)
```

## Reproducing Crashes

Crash artifacts are saved by libFuzzer under `artifacts/<target>/`.

```bash
# Replay a specific crash:
cargo +nightly fuzz run fuzz_argus_pe artifacts/fuzz_argus_pe/crash-* -- -runs=1

# Minimize a crash (find smallest input that still triggers it):
cargo +nightly fuzz tmin fuzz_argus_pe artifacts/fuzz_argus_pe/crash-abc123

# After minimization, copy to regression corpus:
cp artifacts/fuzz_argus_pe/crash-abc123.min corpus/argus/crashes/
```

## Oracles

- **Panics**: Any panic = bug (libFuzzer catches these automatically)
- **Assertions**: Score > 100, verdict inconsistency
- **Timeouts**: Hang > 10s = potential DoS vector
- **OOM**: Allocation > RSS limit from small input = amplification bug

## Expected Findings

### Expected early findings (normal, fix and move on):
- Parser panics on edge-case input
- Unicode path normalization edge cases
- Deeply nested JSON recursion
- Convergence assertion mismatches on extreme inputs
- Pathological PE structures triggering unwrap

### Unexpected / high-severity findings (investigate immediately):
- Memory corruption (with ASan)
- Unbounded allocation from small input
- Privilege-affecting IPC behavior
- Convergence cap bypass (score > 100)
- Deterministic hang (infinite loop)

## CI Integration

**Do NOT run live fuzzers in CI.** Only replay previously-found crashes:

```bash
# Regression replay — replay all known crash inputs (no new fuzzing):
for target in fuzz_ipc_frame fuzz_argus_pe fuzz_convergence fuzz_etw_parser fuzz_paths; do
  corpus_dir="corpus/${target#fuzz_}"
  if [ -d "$corpus_dir" ]; then
    cargo +nightly fuzz run $target $corpus_dir -- -runs=0
  fi
done
```

This is the mature model: fuzz offline, replay in CI.

## Threat Model

These harnesses target the adversarial attack surface identified in the
offensive security audit. Each harness covers one or more audit findings:

| Finding | Harness | Attack |
|---|---|---|
| C2 | `fuzz_ipc_frame` | Malformed JSON-RPC → daemon crash |
| H4 | `fuzz_argus_pe` | Pathological PE → budget exhaustion |
| H6 | `fuzz_argus_pe` | Crafted PE metadata → reputation spoofing |
| ETW OOB | `fuzz_etw_parser` | Malformed event data → OOB read |
| Path bypass | `fuzz_paths` | Adversarial paths → skip logic escape |
| Convergence | `fuzz_convergence` | Extreme findings → cap/score bypass |

## Deferred Targets

| Target | Why Deferred | Risk |
|---|---|---|
| ClamAV FFI | Requires DLL, subprocess isolation | HIGH |
| YARA runtime | Requires compiled rules, complex setup | HIGH |
| Quarantine vault | Requires key setup, stateful | MEDIUM |
| Trust graph SQLite | Requires DB setup, stateful | MEDIUM |
| Full IPC dispatch | Requires AppState, too many deps | HIGH |

These need integration-level harnesses or subprocess-based fuzzing.
Defer to pre-production milestone.
