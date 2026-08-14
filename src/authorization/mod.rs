//! One-shot authorization workspace and immutable source capture.

mod snapshot;
mod workspace;

pub use snapshot::{CaptureError, CaptureLimits, Snapshot, SnapshotInputKind, Snapshotter};
pub(crate) use workspace::AnalyzerEndpointDirectory;
pub use workspace::{InvocationWorkspace, ObjectStore, StoredObject, WorkspaceError};
