use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::claim::Claim;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("http error: {0}")]
    Http(#[from] Box<ureq::Error>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustScore {
    pub score: u8,
    pub level: String,
}

#[derive(Clone, Debug, Serialize)]
struct RegisterBody<'a> {
    did: &'a str,
    public_key_hex: &'a str,
    metadata: serde_json::Value,
}

pub struct AgentClient {
    base_url: String,
}

impl AgentClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn register(
        &self,
        did: &str,
        public_key_hex: &str,
        metadata: serde_json::Value,
    ) -> Result<(), ClientError> {
        let url = format!("{}/v1/devices", self.base_url);
        let body = RegisterBody {
            did,
            public_key_hex,
            metadata,
        };
        let res = ureq::post(&url).send_json(serde_json::to_value(body)?);
        check(res)?;
        Ok(())
    }

    pub fn submit_claim(&self, claim: &Claim) -> Result<serde_json::Value, ClientError> {
        let url = format!("{}/v1/attestations", self.base_url);
        let res = ureq::post(&url).send_json(serde_json::to_value(claim)?);
        let value = check(res)?.into_json::<serde_json::Value>()?;
        Ok(value)
    }

    pub fn send_heartbeat(&self, did: &str, anomaly: bool) -> Result<(), ClientError> {
        let url = format!("{}/v1/devices/{}/telemetry", self.base_url, did);
        let res = ureq::post(&url).send_json(serde_json::json!({"anomaly_detected": anomaly}));
        check(res)?;
        Ok(())
    }

    pub fn get_trust(&self, did: &str) -> Result<TrustScore, ClientError> {
        let url = format!("{}/v1/devices/{}/trust", self.base_url, did);
        let res = ureq::get(&url).call();
        let value = check(res)?.into_json::<TrustScore>()?;
        Ok(value)
    }
}

fn check(result: Result<ureq::Response, ureq::Error>) -> Result<ureq::Response, ClientError> {
    match result {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(status, response)) => Err(ClientError::Status {
            status,
            body: response.into_string().unwrap_or_default(),
        }),
        Err(e) => Err(ClientError::Http(Box::new(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_trailing_slash_from_base_url() {
        let c = AgentClient::new("https://api.example.com//");
        // We can only inspect the stored URL through behaviour; build manually.
        assert!(format!("{}/v1/devices", c.base_url) == "https://api.example.com/v1/devices");
    }
}
