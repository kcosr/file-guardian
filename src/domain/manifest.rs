use super::{Artifact, ArtifactId, ArtifactKind, Digest, PhysicalSubject, Provenance, SubjectId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactManifest {
    pub identity: Digest,
    subjects: Vec<PhysicalSubject>,
    artifacts: Vec<Artifact>,
}

impl ArtifactManifest {
    pub fn new(
        mut subjects: Vec<PhysicalSubject>,
        mut artifacts: Vec<Artifact>,
    ) -> Result<Self, ManifestError> {
        subjects.sort_by(|left, right| {
            left.relative_path
                .cmp(&right.relative_path)
                .then_with(|| left.id.cmp(&right.id))
        });
        artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        validate(&subjects, &artifacts)?;
        let identity = manifest_identity(&subjects, &artifacts)?;
        Ok(Self {
            identity,
            subjects,
            artifacts,
        })
    }

    pub fn subjects(&self) -> &[PhysicalSubject] {
        &self.subjects
    }

    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    pub fn artifact(&self, id: &ArtifactId) -> Option<&Artifact> {
        self.artifacts
            .binary_search_by(|artifact| artifact.id.cmp(id))
            .ok()
            .map(|index| &self.artifacts[index])
    }
}

#[derive(Debug, Serialize)]
struct ManifestIdentityInput<'a> {
    schema: &'static str,
    entries: Vec<ManifestIdentityEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct ManifestIdentityEntry<'a> {
    logical_path: &'a super::LogicalPath,
    byte_len: u64,
    content_digest: Digest,
}

fn manifest_identity(
    subjects: &[PhysicalSubject],
    _artifacts: &[Artifact],
) -> Result<Digest, ManifestError> {
    // This identity describes the captured publication bytes, not the live
    // filesystem objects or the invocation-local correlation identifiers.
    // Subjects are already sorted by their byte-preserving logical paths.
    let entries = subjects
        .iter()
        .map(|subject| ManifestIdentityEntry {
            logical_path: &subject.relative_path,
            byte_len: subject.byte_len,
            content_digest: subject.source_identity.content_digest,
        })
        .collect();
    let bytes = serde_json::to_vec(&ManifestIdentityInput {
        schema: "file-guardian-artifact-manifest/1",
        entries,
    })
    .map_err(ManifestError::IdentitySerialization)?;
    Ok(Digest::sha256(bytes))
}

fn validate(subjects: &[PhysicalSubject], artifacts: &[Artifact]) -> Result<(), ManifestError> {
    let mut subject_ids = BTreeSet::new();
    let mut subject_paths = BTreeSet::new();
    let mut by_subject = BTreeMap::new();
    for subject in subjects {
        if !subject_ids.insert(&subject.id) {
            return Err(ManifestError::DuplicateSubject(subject.id.clone()));
        }
        if !subject_paths.insert(&subject.relative_path) {
            return Err(ManifestError::DuplicatePath);
        }
        if subject.byte_len != subject.source_identity.byte_len {
            return Err(ManifestError::SubjectSize(subject.id.clone()));
        }
        by_subject.insert(&subject.id, subject);
    }

    let mut artifact_ids = BTreeSet::new();
    for artifact in artifacts {
        if !artifact_ids.insert(&artifact.id) {
            return Err(ManifestError::DuplicateArtifact(artifact.id.clone()));
        }
        let subject = by_subject
            .get(&artifact.subject_id)
            .ok_or_else(|| ManifestError::UnknownSubject(artifact.subject_id.clone()))?;
        if artifact.kind == ArtifactKind::PhysicalFile {
            if artifact.object_id != subject.object_id
                || artifact.byte_len != subject.byte_len
                || artifact.content_digest != subject.source_identity.content_digest
            {
                return Err(ManifestError::PhysicalArtifactMismatch(artifact.id.clone()));
            }
            match &artifact.provenance {
                Provenance::Physical { logical_path } if logical_path == &subject.relative_path => {
                }
                _ => return Err(ManifestError::PhysicalArtifactMismatch(artifact.id.clone())),
            }
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("duplicate physical subject {0}")]
    DuplicateSubject(SubjectId),
    #[error("duplicate physical subject logical path")]
    DuplicatePath,
    #[error("duplicate artifact {0}")]
    DuplicateArtifact(ArtifactId),
    #[error("artifact references unknown subject {0}")]
    UnknownSubject(SubjectId),
    #[error("physical subject {0} has inconsistent byte lengths")]
    SubjectSize(SubjectId),
    #[error("physical artifact {0} does not match its source subject")]
    PhysicalArtifactMismatch(ArtifactId),
    #[error("could not serialize manifest identity: {0}")]
    IdentitySerialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        FileTimestamp, LogicalPath, ObjectId, PathSegment, SourceFileType, SourceIdentity,
    };

    fn pair(suffix: &str, path: &str, bytes: &[u8]) -> (PhysicalSubject, Artifact) {
        let subject_id = SubjectId::from_suffix(suffix).unwrap();
        let object_id = ObjectId::from_suffix(suffix).unwrap();
        let artifact_id = ArtifactId::from_suffix(suffix).unwrap();
        let logical_path = LogicalPath::new(vec![PathSegment::utf8(path).unwrap()]).unwrap();
        let digest = Digest::sha256(bytes);
        let source_identity = SourceIdentity {
            device: 1,
            inode: suffix.as_bytes()[0] as u64,
            file_type: SourceFileType::RegularFile,
            byte_len: bytes.len() as u64,
            link_count: 1,
            modified: None,
            changed: None,
            content_digest: digest,
        };
        let subject = PhysicalSubject {
            id: subject_id.clone(),
            relative_path: logical_path.clone(),
            source_identity,
            object_id: object_id.clone(),
            byte_len: bytes.len() as u64,
        };
        let artifact = Artifact {
            id: artifact_id,
            subject_id,
            object_id,
            kind: ArtifactKind::PhysicalFile,
            byte_len: bytes.len() as u64,
            content_digest: digest,
            provenance: Provenance::Physical { logical_path },
        };
        (subject, artifact)
    }

    #[test]
    fn identity_and_order_do_not_depend_on_discovery_order() {
        let (subject_a, artifact_a) = pair("a", "a.txt", b"a");
        let (subject_b, artifact_b) = pair("b", "b.txt", b"b");
        let forward = ArtifactManifest::new(
            vec![subject_a.clone(), subject_b.clone()],
            vec![artifact_a.clone(), artifact_b.clone()],
        )
        .unwrap();
        let reverse =
            ArtifactManifest::new(vec![subject_b, subject_a], vec![artifact_b, artifact_a])
                .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.subjects()[0].relative_path.to_string(), "a.txt");
    }

    #[test]
    fn identity_excludes_live_metadata_and_invocation_local_ids() {
        let (first_subject, first_artifact) = pair("first", "same.txt", b"same");
        let (mut second_subject, mut second_artifact) = pair("second", "same.txt", b"same");
        second_subject.source_identity.device = 99;
        second_subject.source_identity.inode = 123_456;
        second_subject.source_identity.modified = FileTimestamp::new(42, 7);
        second_artifact.object_id = second_subject.object_id.clone();

        let first = ArtifactManifest::new(vec![first_subject], vec![first_artifact]).unwrap();
        let second = ArtifactManifest::new(vec![second_subject], vec![second_artifact]).unwrap();

        assert_eq!(first.identity, second.identity);
        assert_ne!(first, second);
    }

    #[test]
    fn physical_artifact_must_match_subject() {
        let (subject, mut artifact) = pair("a", "a.txt", b"a");
        artifact.byte_len += 1;
        assert!(matches!(
            ArtifactManifest::new(vec![subject], vec![artifact]),
            Err(ManifestError::PhysicalArtifactMismatch(_))
        ));
    }
}
