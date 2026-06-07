# sentinel-agent

**On-device daemon for Sentinel Labs.** Rust library + CLI that generates and persists an Ed25519 device identity, signs attestation claims with a canonical-JSON digest (wire-compatible with [`sentinel-core`](https://github.com/Sentinels-Today/sentinel-core)), and talks to [`sentinel-cloud`](https://github.com/Sentinels-Today/sentinel-cloud).

[![ci](https://github.com/Sentinels-Today/sentinel-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Sentinels-Today/sentinel-agent/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![rust](https://img.shields.io/badge/rust-1.75%2B-orange)

## CLI

```sh
cargo install --path .

sentinel-agent whoami
sentinel-agent register --cloud http://localhost:8787
sentinel-agent heartbeat
sentinel-agent attest --sha256 deadbeef...
sentinel-agent trust
```

The key file (`sentinel-agent.key.json` by default, override with `--key`) holds the Ed25519 secret hex. Generated automatically on first run.

## Library

```rust
use sentinel_agent::{AgentClient, Claim, ClaimBody, ClaimKind, DeviceIdentity};

let id = DeviceIdentity::load_or_create("/var/lib/sentinel-agent.key.json".as_ref())?;
let body = ClaimBody {
    kind: ClaimKind::FirmwareHash,
    subject: id.did().clone(),
    issued_at: chrono::Utc::now(),
    nonce: "boot-1".into(),
    payload: serde_json::json!({"sha256": "..."}),
};
let claim = Claim::sign(&id, body)?;
let client = AgentClient::new("https://api.sentinels.today");
client.submit_claim(&claim)?;
```

## Develop

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same on ubuntu/macos/windows.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
