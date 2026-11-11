//! Bounded, versioned persistence of consumed facts, without a stored verdict.
use std::collections::BTreeSet;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::MAX_RESPONSE_BYTES;
use crate::api::audit::{
    Report, SCHEMA_VERSION as PRODUCER_SCHEMA_VERSION, report::Data, wire::Additional,
};

const FORMAT: &str = "githits-scan-analysis";
const SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("analysis exceeds the {MAX_RESPONSE_BYTES}-byte limit")]
    TooLarge,
    #[error(
        "not a valid saved audit analysis; this Scan requires analysis format 2 with audit report version 3"
    )]
    Invalid,
    #[error(
        "unsupported saved analysis version {version} (written by Scan {writer}); this Scan requires analysis format 2. Use the recorded writer for compatible offline replay"
    )]
    Version { version: u64, writer: String },
    #[error(
        "saved analysis contains audit report version {version}; this Scan requires version 3. Use its recorded writer for compatible offline replay"
    )]
    ProducerVersion { version: u64 },
    #[error("cannot encode saved audit analysis")]
    Encoding,
}

pub(crate) struct Analysis {
    pub report: Report,
    pub selected_manifests: BTreeSet<String>,
    pub provenance: Provenance,
    pub audit_policy: crate::config::Audit,
}

#[derive(Debug, Serialize)]
pub(crate) struct Provenance {
    pub archive_schema_version: u8,
    pub writer_version: String,
    pub producer_schema_version: u64,
    pub generated_at: String,
}

#[derive(Serialize)]
struct Envelope<'a> {
    format: &'static str,
    schema_version: u8,
    writer_version: &'static str,
    producer_report: Producer<'a>,
    selected_manifests: &'a BTreeSet<String>,
    #[serde(skip_serializing_if = "crate::config::Audit::is_empty")]
    audit_policy: &'a crate::config::Audit,
}

#[derive(Serialize)]
struct Producer<'a> {
    schema_version: u64,
    #[serde(flatten)]
    report: &'a Data,
}

#[derive(Deserialize)]
struct Header {
    #[serde(flatten)]
    _additional: Additional,
    format: String,
    schema_version: u64,
    #[serde(default)]
    writer_version: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Input {
    #[serde(flatten)]
    _additional: Additional,
    writer_version: String,
    producer_report: serde_json::Value,
    selected_manifests: BTreeSet<String>,
    #[serde(default)]
    audit_policy: crate::config::Audit,
}

pub(crate) fn encode(
    report: &Report,
    manifests: &BTreeSet<String>,
    policy: &crate::config::Audit,
) -> Result<Vec<u8>, Error> {
    let body = &report.data;
    let envelope = Envelope {
        format: FORMAT,
        schema_version: SCHEMA_VERSION,
        writer_version: env!("CARGO_PKG_VERSION"),
        producer_report: Producer {
            schema_version: PRODUCER_SCHEMA_VERSION,
            report: body,
        },
        selected_manifests: manifests,
        audit_policy: policy,
    };
    let mut output = Limited {
        bytes: Vec::new(),
        oversized: false,
    };
    if serde_json::to_writer(&mut output, &envelope).is_err() {
        return Err(if output.oversized {
            Error::TooLarge
        } else {
            Error::Encoding
        });
    }
    Ok(output.bytes)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Analysis, Error> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::TooLarge);
    }
    let header: Header = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if header.format != FORMAT {
        return Err(Error::Invalid);
    }
    if header.schema_version != u64::from(SCHEMA_VERSION) {
        let writer = header
            .writer_version
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .unwrap_or("writer not recorded");
        return Err(Error::Version {
            version: header.schema_version,
            writer: writer.escape_default().to_string(),
        });
    }
    let input: Input = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    input.audit_policy.validate().map_err(|_| Error::Invalid)?;
    let producer = serde_json::to_vec(&input.producer_report).map_err(|_| Error::Invalid)?;
    drop(input.producer_report);
    let report = Report::from_bytes(&producer).map_err(|error| match error {
        crate::api::ApiError::UnsupportedAuditVersion { version, .. } => {
            Error::ProducerVersion { version }
        }
        _ => Error::Invalid,
    })?;
    let generated_at = report.data.generated_at.clone();
    Ok(Analysis {
        provenance: Provenance {
            archive_schema_version: SCHEMA_VERSION,
            writer_version: input.writer_version,
            producer_schema_version: PRODUCER_SCHEMA_VERSION,
            generated_at,
        },
        report,
        selected_manifests: input.selected_manifests,
        audit_policy: input.audit_policy,
    })
}

struct Limited {
    bytes: Vec<u8>,
    oversized: bool,
}
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES - self.bytes.len() {
            self.oversized = true;
            return Err(io::Error::other("saved analysis limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
