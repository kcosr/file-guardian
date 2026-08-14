//! One-shot authorization workspace and immutable source capture.

mod analyzer_view;
mod snapshot;
mod workspace;

pub use analyzer_view::{
    AnalyzerView, AnalyzerViewBuilder, AnalyzerViewEntry, AnalyzerViewError, AnalyzerViewLimits,
    AnalyzerViewNode, AnalyzerViewQuota,
};
pub use snapshot::{CaptureError, CaptureLimits, Snapshot, SnapshotInputKind, Snapshotter};
pub(crate) use workspace::AnalyzerEndpointDirectory;
pub use workspace::{InvocationWorkspace, ObjectStore, StoredObject, WorkspaceError};
