use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sentinel_agent::{AgentClient, Claim, ClaimBody, ClaimKind, DeviceIdentity};

#[derive(Parser)]
#[command(
    name = "sentinel-agent",
    version,
    about = "Sentinel Labs on-device daemon"
)]
struct Cli {
    /// Path to the device key file.
    #[arg(long, default_value = "sentinel-agent.key.json", global = true)]
    key: PathBuf,

    /// sentinel-cloud base URL.
    #[arg(long, default_value = "http://localhost:8787", global = true)]
    cloud: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the device DID + public key, generating a key file if needed.
    Whoami,
    /// Register this device with sentinel-cloud.
    Register,
    /// Send a single signed heartbeat / telemetry event.
    Heartbeat {
        #[arg(long)]
        anomaly: bool,
    },
    /// Submit a firmware-hash attestation claim.
    Attest {
        #[arg(long)]
        sha256: String,
    },
    /// Fetch the current trust score for this device.
    Trust,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let identity = DeviceIdentity::load_or_create(&cli.key)?;

    match cli.cmd {
        Cmd::Whoami => {
            println!("did: {}", identity.did());
            println!("public_key_hex: {}", identity.public_key_hex());
            println!("key_file: {}", cli.key.display());
        }
        Cmd::Register => {
            let client = AgentClient::new(&cli.cloud);
            client.register(
                identity.did().as_str(),
                &identity.public_key_hex(),
                serde_json::json!({}),
            )?;
            println!("registered {} with {}", identity.did(), cli.cloud);
        }
        Cmd::Heartbeat { anomaly } => {
            let client = AgentClient::new(&cli.cloud);
            client.send_heartbeat(identity.did().as_str(), anomaly)?;
            println!("heartbeat sent (anomaly={anomaly})");
        }
        Cmd::Attest { sha256 } => {
            let body = ClaimBody {
                kind: ClaimKind::FirmwareHash,
                subject: identity.did().clone(),
                issued_at: chrono::Utc::now(),
                nonce: uuid_like(),
                payload: serde_json::json!({"sha256": sha256}),
            };
            let claim = Claim::sign(&identity, body)?;
            let client = AgentClient::new(&cli.cloud);
            let res = client.submit_claim(&claim)?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Cmd::Trust => {
            let client = AgentClient::new(&cli.cloud);
            let score = client.get_trust(identity.did().as_str())?;
            println!("score: {} ({})", score.score, score.level);
        }
    }

    Ok(())
}

/// Tiny nonce generator (NOT a real UUID) so the binary doesn't pull the
/// `uuid` crate in just for this.
fn uuid_like() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}
