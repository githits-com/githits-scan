//! Native audit decoding; only consumed typed evidence is retained.
use super::{ApiError, MAX_RESPONSE_BYTES};
use serde::Deserialize;

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only native lifecycle DTOs"
)]
pub(crate) mod lifecycle;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only consumed remediation facts"
)]
pub(crate) mod remediation;
#[expect(clippy::redundant_pub_crate, reason = "crate-only native report DTOs")]
pub(crate) mod report;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only recorded dependency DTOs"
)]
pub(crate) mod trace;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only consumed wire helpers"
)]
pub(crate) mod wire;

pub(crate) const SCHEMA_VERSION: u64 = 3;

/// A decoded native audit response.
#[derive(Debug)]
pub struct Report {
    pub(crate) data: report::Data,
}

#[derive(Deserialize)]
struct Envelope {
    schema_version: u64,
    #[serde(flatten)]
    _additional: wire::Additional,
}

impl Report {
    /// Decode native evidence without interpreting unsupported producer versions.
    ///
    /// # Errors
    /// Returns an API error for oversized bodies, invalid JSON, unsupported versions
    /// or malformed consumed fields. Semantic accounting belongs to pure assessment.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge);
        }
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|_| ApiError::protocol("invalid audit report version"))?;
        if envelope.schema_version != SCHEMA_VERSION {
            return Err(ApiError::UnsupportedAuditVersion {
                version: envelope.schema_version,
                request_id: None,
            });
        }
        let data = serde_json::from_slice(bytes)
            .map_err(|_| ApiError::protocol("invalid native lifecycle audit report"))?;
        Ok(Self { data })
    }
}

#[cfg(test)]
mod tests;
