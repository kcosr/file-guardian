//! One-shot authorization workspace and immutable source capture.

mod snapshot;
mod workspace;

pub use snapshot::{CaptureError, CaptureLimits, Snapshot, Snapshotter};
pub use workspace::{InvocationWorkspace, ObjectStore, StoredObject, WorkspaceError};
