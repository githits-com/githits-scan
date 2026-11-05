//! Version-aware audit report decoding; only useful typed data is retained.

use serde::Deserialize;

use super::{ApiError, MAX_RESPONSE_BYTES};

#[expect(
    clippy::redundant_pub_crate,
    reason = "explicit crate-only DTO visibility satisfies unreachable_pub without exporting wire types"
)]
pub(crate) mod wire;

#[expect(clippy::redundant_pub_crate, reason = "crate-only versioned wire DTOs")]
pub(crate) mod v2;

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only consumed remediation facts"
)]
pub(crate) mod remediation;

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only recorded dependency DTOs"
)]
pub(crate) mod trace;

/// A typed audit response with its producer-owned version.
#[derive(Debug)]
pub struct Report {
    pub(crate) body: Body,
}

#[derive(Debug)]
pub(crate) enum Body {
    V1(Box<wire::V1>),
    V2(Box<v2::V2>),
    Future(u64),
}

#[derive(Deserialize)]
struct Envelope {
    schema_version: u64,
    #[serde(flatten)]
    _additional: wire::Additional,
}

impl Report {
    /// Decode known v1/v2 structure; identify future versions without interpreting them.
    ///
    /// # Errors
    ///
    /// Returns an API error for oversized bodies, invalid JSON/version or malformed known reports.
    /// Semantic accounting belongs to the pure consumer, not wire decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge);
        }
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|_| ApiError::protocol("invalid audit report version"))?;
        let body = match envelope.schema_version {
            0 => return Err(ApiError::protocol("invalid audit report version")),
            1 => Body::V1(
                serde_json::from_slice(bytes)
                    .map_err(|_| ApiError::protocol("invalid version-one audit report"))?,
            ),
            2 => Body::V2(
                serde_json::from_slice(bytes)
                    .map_err(|_| ApiError::protocol("invalid version-two audit report"))?,
            ),
            version => Body::Future(version),
        };
        Ok(Self { body })
    }

    /// The producer's schema version, never replaced with the consumer's version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        match &self.body {
            Body::V1(_) => 1,
            Body::V2(_) => 2,
            Body::Future(version) => *version,
        }
    }
}

#[cfg(test)]
mod tests;
