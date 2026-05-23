param(
    [string]$CleanFile = "Cargo.toml"
)

$ErrorActionPreference = "Stop"

cargo run -p argusd -- self-test
cargo run -p argusd -- rules
cargo run -p argusd -- scan-file $CleanFile --json
