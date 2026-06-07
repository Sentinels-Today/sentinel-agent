//! `sentinel-agent` library: on-device identity persistence, claim signing,
//! and a small HTTP client for `sentinel-cloud`.
//!
//! The binary `sentinel-agent` wraps this library with a clap-based CLI.

pub mod claim;
pub mod client;
pub mod identity;

pub use claim::{Claim, ClaimBody, ClaimKind};
pub use client::{AgentClient, ClientError, TrustScore};
pub use identity::{DeviceIdentity, Did, IdentityError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
