use super::{ArtifactId, Digest, LogicalPath, ObjectId, SubjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFileType {
    RegularFile,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FileTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl FileTimestamp {
    pub fn new(seconds: i64, nanoseconds: u32) -> Option<Self> {
        (nanoseconds < 1_000_000_000).then_some(Self {
            seconds,
            nanoseconds,
        })
    }
}

/// Identity observed on the live source before and after immutable capture.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceIdentity {
    pub device: u64,
    pub inode: u64,
    pub file_type: SourceFileType,
    pub byte_len: u64,
    pub link_count: u64,
    pub modified: Option<FileTimestamp>,
    pub changed: Option<FileTimestamp>,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PhysicalSubject {
    pub id: SubjectId,
    pub relative_path: LogicalPath,
    pub source_identity: SourceIdentity,
    pub object_id: ObjectId,
    pub byte_len: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    PhysicalFile,
    ArchiveContainer,
    ArchiveMember,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Physical {
        logical_path: LogicalPath,
    },
    Derived {
        parent_artifact_id: ArtifactId,
        member_path: LogicalPath,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub subject_id: SubjectId,
    pub object_id: ObjectId,
    pub kind: ArtifactKind,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub provenance: Provenance,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::PathSegment;

    #[test]
    fn timestamps_reject_invalid_nanoseconds() {
        assert!(FileTimestamp::new(1, 999_999_999).is_some());
        assert!(FileTimestamp::new(1, 1_000_000_000).is_none());
    }

    #[test]
    fn physical_provenance_never_contains_an_os_path() {
        let provenance = Provenance::Physical {
            logical_path: LogicalPath::new(vec![PathSegment::utf8("file.txt").unwrap()]).unwrap(),
        };
        let json = serde_json::to_value(provenance).unwrap();
        assert_eq!(json["kind"], "physical");
        assert!(json["logical_path"].get("segments").is_some());
    }
}
