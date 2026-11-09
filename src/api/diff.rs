//! Paired dependency analysis. The service owns comparison; JSON remains exact.
use std::io;

use serde::Deserialize;
use serde_json::value::RawValue;

use super::{ApiError, MAX_RESPONSE_BYTES, ProgressEvent};

mod input;
pub use input::{Input, UnlockedManifests};

#[expect(
    clippy::redundant_pub_crate,
    reason = "display DTOs remain crate-private"
)]
pub(crate) mod view;

/// Public paired-input submission path, without query controls.
pub const PATH: &str = "/v1/experimental/dependency-diffs";

/// One admitted comparison, observed through the existing job transport.
pub trait DiffApi {
    /// Compare selected files and return the service's unchanged report.
    ///
    /// # Errors
    /// Returns admission, transport, progress, size or report-validation errors.
    fn diff(
        &self,
        input: Input,
        progress: &mut dyn FnMut(&ProgressEvent) -> io::Result<()>,
    ) -> Result<Report, ApiError>;
}

/// An immutable producer report plus its supported presentation projection.
pub struct Report {
    bytes: Vec<u8>,
    version: u64,
    view: Option<view::View>,
}

impl Report {
    /// Validate JSON and the supported display structure without rewriting bytes.
    /// Positive future schemas remain exportable, but cannot be rendered as v1.
    ///
    /// # Errors
    /// Returns a safe protocol error for malformed data, or a size error.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApiError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge);
        }
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
            return Err(invalid());
        }
        let header: Header = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if header.schema_version == 0 {
            return Err(invalid());
        }
        let view = if header.schema_version == 1 && header.kind == "diff" {
            let view: view::View = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            view.validate()?;
            Some(view)
        } else {
            None
        };
        Ok(Self {
            bytes,
            version: header.schema_version,
            view,
        })
    }

    /// Original bytes, including additive and unfamiliar evidence.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn view(&self) -> Option<&view::View> {
        self.view.as_ref()
    }
    pub(crate) const fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Deserialize)]
struct Header {
    schema_version: u64,
    kind: String,
}

const fn invalid() -> ApiError {
    ApiError::protocol("invalid dependency-diff report")
}

/// A section's open status controls whether its current data shape is understood.
#[derive(Deserialize)]
pub(crate) struct Section {
    pub status: String,
    pub data: Option<Box<RawValue>>,
    pub coverage: Option<Box<RawValue>>,
    pub reason: Option<String>,
}

impl Section {
    pub(crate) fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<Option<T>, ApiError> {
        if !matches!(self.status.as_str(), "complete" | "partial") {
            return Ok(None);
        }
        let raw = self.data.as_ref().ok_or_else(invalid)?;
        serde_json::from_str(raw.get())
            .map(Some)
            .map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests;
