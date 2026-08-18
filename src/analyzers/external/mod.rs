//! Confined process runtime shared by File Guardian's closed first-party
//! external scanner adapters.
//!
//! This module deliberately does not expose a command/argument extension
//! point. Gitleaks and TruffleHog are the only launch shapes in schema 3.

mod adapter;
mod gitleaks;
mod protocol;
mod runner;
mod sandbox;
mod trufflehog;

pub use adapter::{
    FirstPartyScannerAdapter, ScannerAdapterContext, ScannerAdapterError, ScannerCapability,
    ScannerVersion, ScannerVersionRequirement,
};
pub use gitleaks::{GitleaksAdapter, GITLEAKS_FINDINGS_EXIT, GITLEAKS_VERSION_REQUIREMENT};

pub use protocol::{
    AssignmentDisposition, NormalizedScannerOccurrence, ScannerAssignment,
    ScannerAssignmentSurface, ScannerCompletion, ScannerCoveredSurface, ScannerKind,
    ScannerProtocolError,
};
pub use runner::{
    ExternalScannerRunner, FirstPartyScannerInvocation, NativeExit, ScannerCancellation,
    ScannerRunError, ScannerRunLimits, ScannerRunOutput,
};
pub use sandbox::{
    ExecutableIdentity, PreparedProtectedFile, PreparedScannerExecutable, PreparedScannerSandbox,
    ScannerSandboxError, ScannerSandboxSpec,
};
pub use trufflehog::{TrufflehogAdapter, TRUFFLEHOG_FINDINGS_EXIT, TRUFFLEHOG_VERSION_REQUIREMENT};
