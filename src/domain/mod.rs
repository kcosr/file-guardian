//! Stable values shared by capture, analyzers, policy, and reporting.

mod artifact;
mod coverage;
mod digest;
mod id;
mod issue;
mod logical_path;
mod manifest;
mod observation;

pub use artifact::{
    Artifact, ArtifactKind, FileTimestamp, PhysicalSubject, Provenance, SourceFileType,
    SourceIdentity,
};
pub use coverage::{
    AnalyzerCoverage, CoverageError, CoverageStatus, InspectionPhase, PhaseCoverage,
    PhaseCoverageStatus, RunCoverage,
};
pub use digest::{Digest, DigestParseError};
pub use id::{ArtifactId, CandidateId, ObjectId, ObservationId, OpaqueIdError, RunId, SubjectId};
pub use issue::{InspectionIssue, IssueCode, SanitizedMessage, SanitizedMessageError};
pub use logical_path::{LogicalPath, LogicalPathError, PathSegment};
pub use manifest::{ArtifactManifest, ManifestError};
pub use observation::{
    AnalyzerId, Classification, ClassificationCode, ClassificationScope, ConfiguredConfidence,
    Finding, FindingCategory, IdentifierError, NormalizedObservation, ReasonCode, RuleId,
    SafeEvidence, Severity, ValidatedLocation, ValidatedLocationError,
};
