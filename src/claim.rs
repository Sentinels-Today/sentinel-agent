use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::{DeviceIdentity, Did};

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    FirmwareHash,
    MeasuredBoot,
    SoftwareBom,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimBody {
    pub kind: ClaimKind,
    pub subject: Did,
    pub issued_at: DateTime<Utc>,
    pub nonce: String,
    pub payload: serde_json::Value,
}

impl ClaimBody {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        let v = serde_json::to_value(self)?;
        Ok(canonicalize(&v).into_bytes())
    }

    pub fn digest_hex(&self) -> Result<String, ClaimError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex::encode(hasher.finalize()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub body: ClaimBody,
    pub signature_hex: String,
    pub public_key_hex: String,
}

impl Claim {
    pub fn sign(identity: &DeviceIdentity, body: ClaimBody) -> Result<Self, ClaimError> {
        let bytes = body.canonical_bytes()?;
        Ok(Self {
            signature_hex: identity.sign_hex(&bytes),
            public_key_hex: identity.public_key_hex(),
            body,
        })
    }
}

fn canonicalize(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = entries
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonicalize(val)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", inner.join(","))
        }
        _ => serde_json::to_string(v).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_signs_with_stable_digest() {
        let id = DeviceIdentity::generate();
        let body = ClaimBody {
            kind: ClaimKind::FirmwareHash,
            subject: id.did().clone(),
            issued_at: Utc::now(),
            nonce: "n".into(),
            payload: serde_json::json!({"b": 1, "a": 2}),
        };
        let other = ClaimBody {
            payload: serde_json::json!({"a": 2, "b": 1}),
            ..body.clone()
        };
        assert_eq!(body.digest_hex().unwrap(), other.digest_hex().unwrap());
        let claim = Claim::sign(&id, body).unwrap();
        assert_eq!(claim.public_key_hex, id.public_key_hex());
        assert_eq!(claim.signature_hex.len(), 128);
    }
}
