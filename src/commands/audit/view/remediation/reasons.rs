//! Resolved checked effects shared by human output and compact/explanation JSON.
use super::{Finding, resolve};
use crate::api::audit::{
    remediation::{Reason as WireReason, reasons::Request},
    report::Vulnerability,
    wire::Coordinate,
};
use serde::{Serialize, Serializer, ser::SerializeMap as _};

/// A checked effect with resolved user-facing identities and no report indices.
pub(in crate::commands::audit) enum Reason {
    /// A changed release addresses the cited findings.
    Advisory { findings: Vec<Finding> },
    /// Replacement requests accept the stated canonical target.
    Enables {
        dependency: Coordinate,
        path: String,
        original_requests: Vec<Request>,
        replacement_requests: Vec<Request>,
    },
    /// A changed parent removes a represented route to the stated dependency.
    Removes {
        dependency: Coordinate,
        path: String,
        original_requests: Vec<Request>,
    },
    /// The service did not establish a supported effect.
    Unavailable,
    /// A future code is retained without interpreting its evidence.
    Unknown { code: String },
}
impl Reason {
    /// Resolve consumed findings once; omit all unused wire indices.
    pub(super) fn new(reason: &WireReason, findings: &[Vulnerability]) -> Self {
        match reason {
            WireReason::Advisory(data) => Self::Advisory {
                findings: resolve(&data.finding_refs, findings),
            },
            WireReason::Enables(data) => Self::Enables {
                dependency: data.dependency.clone(),
                path: data.path.clone(),
                original_requests: data.original_requests.clone(),
                replacement_requests: data.replacement_requests.clone(),
            },
            WireReason::Removes(data) => Self::Removes {
                dependency: data.dependency.clone(),
                path: data.path.clone(),
                original_requests: data.original_requests.clone(),
            },
            WireReason::Unavailable => Self::Unavailable,
            WireReason::Unknown { .. } => Self::Unknown {
                code: reason.code().to_owned(),
            },
        }
    }
    /// Whether a reason supplies an interpretable nonempty effect.
    pub(in crate::commands::audit) const fn known(&self) -> bool {
        match self {
            Self::Advisory { findings } => !findings.is_empty(),
            Self::Enables { .. } | Self::Removes { .. } => true,
            Self::Unavailable | Self::Unknown { .. } => false,
        }
    }
    fn code(&self) -> &str {
        match self {
            Self::Advisory { .. } => "advisory_remediation",
            Self::Enables { .. } => "enables_dependency_target",
            Self::Removes { .. } => "removes_dependency_route",
            Self::Unavailable => "unavailable",
            Self::Unknown { code } => code,
        }
    }
}
impl Serialize for Reason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("code", self.code())?;
        match self {
            Self::Advisory { findings } => map.serialize_entry("findings", findings)?,
            Self::Enables {
                dependency,
                path,
                original_requests,
                replacement_requests,
            } => {
                map.serialize_entry("dependency", dependency)?;
                map.serialize_entry("path", path)?;
                map.serialize_entry("original_requests", original_requests)?;
                map.serialize_entry("replacement_requests", replacement_requests)?;
            }
            Self::Removes {
                dependency,
                path,
                original_requests,
            } => {
                map.serialize_entry("dependency", dependency)?;
                map.serialize_entry("path", path)?;
                map.serialize_entry("original_requests", original_requests)?;
            }
            Self::Unavailable | Self::Unknown { .. } => {}
        }
        map.end()
    }
}
