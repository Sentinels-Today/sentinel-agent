use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid secret length: expected 32, got {0}")]
    InvalidSecret(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub const PREFIX: &'static str = "did:sentinel:";

    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pk.as_bytes());
        let digest = hasher.finalize();
        Did(format!("{}{}", Self::PREFIX, hex::encode(digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    secret_hex: String,
}

pub struct DeviceIdentity {
    signing: SigningKey,
    did: Did,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let did = Did::from_public_key(&signing.verifying_key());
        Self { signing, did }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidSecret(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let signing = SigningKey::from_bytes(&arr);
        let did = Did::from_public_key(&signing.verifying_key());
        Ok(Self { signing, did })
    }

    /// Load an identity from JSON on disk, generating + saving a fresh one if absent.
    pub fn load_or_create(path: &Path) -> Result<Self, IdentityError> {
        if path.exists() {
            let raw = fs::read_to_string(path)?;
            let stored: StoredKey = serde_json::from_str(&raw)?;
            let bytes = hex::decode(&stored.secret_hex)?;
            return Self::from_secret_bytes(&bytes);
        }
        let id = Self::generate();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let stored = StoredKey {
            secret_hex: hex::encode(id.signing.to_bytes()),
        };
        fs::write(path, serde_json::to_string_pretty(&stored)?)?;
        Ok(id)
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }

    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.signing.sign(payload)
    }

    pub fn sign_hex(&self, payload: &[u8]) -> String {
        hex::encode(self.sign(payload).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn did_format() {
        let id = DeviceIdentity::generate();
        assert!(id.did().as_str().starts_with(Did::PREFIX));
        assert_eq!(id.did().as_str().len(), Did::PREFIX.len() + 64);
    }

    #[test]
    fn load_or_create_persists_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.json");
        let a = DeviceIdentity::load_or_create(&path).unwrap();
        let b = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(a.did(), b.did());
        assert_eq!(a.public_key_hex(), b.public_key_hex());
        assert!(path.exists());
    }

    #[test]
    fn generates_unique_keys() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        assert_ne!(a.did(), b.did());
    }

    #[test]
    fn signature_is_64_bytes() {
        let id = DeviceIdentity::generate();
        let sig = id.sign_hex(b"hello");
        assert_eq!(sig.len(), 128); // 64 bytes hex-encoded
    }
}
