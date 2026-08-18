//! Deterministic whole-file action planning and durable action journaling.
//!
//! The planner consumes typed, normalized processing evidence and immutable
//! stage-subject metadata. The executor applies only the resulting whole-file
//! targets beneath job-owned descriptors, with durable recovery and reverse
//! rollback. The journal records only bounded identifiers and integrity
//! metadata; no component accepts analyzer-supplied operating-system paths or
//! matched content as a mutation target.

pub mod executor;
pub mod journal;
pub mod plan;

pub use executor::*;
pub use journal::*;
pub use plan::*;
