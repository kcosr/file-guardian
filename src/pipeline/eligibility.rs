use std::collections::BTreeSet;

use globset::{Candidate, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Serialize;
use thiserror::Error;

use crate::domain::{
    AnalyzerId, Artifact, ArtifactId, ArtifactKind, ArtifactManifest, CandidateId, LogicalPath,
    Provenance,
};

/// One immutable artifact presentation assigned to an analyzer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAssignment {
    pub candidate_id: CandidateId,
    pub artifact_id: ArtifactId,
}

/// The complete, canonically ordered set of artifacts eligible for an analyzer.
///
/// Artifacts outside the compiled selector are outside the eligible set. They
/// are not analyzer applicability decisions and must not increment a
/// `not_applicable` coverage
/// counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSelection {
    pub assignments: Vec<ArtifactAssignment>,
}

impl ArtifactSelection {
    pub fn assignments(&self) -> &[ArtifactAssignment] {
        &self.assignments
    }

    pub fn eligible_count(&self) -> u64 {
        self.assignments.len() as u64
    }
}

#[derive(Clone, Debug)]
pub struct EligibilitySelector {
    include: GlobSet,
    exclude: GlobSet,
    artifact_kinds: BTreeSet<ArtifactKind>,
}

impl EligibilitySelector {
    pub fn compile(
        include: &[String],
        exclude: &[String],
        artifact_kinds: impl IntoIterator<Item = ArtifactKind>,
    ) -> Result<Self, EligibilityError> {
        if include.is_empty() {
            return Err(EligibilityError::EmptyInclude);
        }
        let artifact_kinds = artifact_kinds.into_iter().collect::<BTreeSet<_>>();
        if artifact_kinds.is_empty() {
            return Err(EligibilityError::EmptyArtifactKinds);
        }
        Ok(Self {
            include: compile_globs(include)?,
            exclude: compile_globs(exclude)?,
            artifact_kinds,
        })
    }

    /// Freeze an analyzer assignment from the immutable manifest.
    pub fn assign(
        &self,
        analyzer_id: &AnalyzerId,
        manifest: &ArtifactManifest,
    ) -> Result<ArtifactSelection, EligibilityError> {
        let mut selected = manifest
            .artifacts()
            .iter()
            .filter(|artifact| self.artifact_kinds.contains(&artifact.kind))
            .filter_map(|artifact| {
                let path = artifact_logical_path(artifact);
                let bytes = logical_path_bytes(path);
                let candidate = Candidate::from_bytes(&bytes);
                (self.include.is_match_candidate(&candidate)
                    && !self.exclude.is_match_candidate(&candidate))
                .then_some((bytes, artifact))
            })
            .collect::<Vec<_>>();

        // Artifact IDs are the manifest's canonical analyzer assignment key.
        // Paths are used only for byte-exact selector matching.
        selected.sort_by(|(_, left), (_, right)| left.id.cmp(&right.id));

        let assignments = selected
            .into_iter()
            .map(|(_, artifact)| {
                Ok(ArtifactAssignment {
                    candidate_id: candidate_id(analyzer_id, &artifact.id)?,
                    artifact_id: artifact.id.clone(),
                })
            })
            .collect::<Result<Vec<_>, EligibilityError>>()?;
        Ok(ArtifactSelection { assignments })
    }
}

#[derive(Debug, Error)]
pub enum EligibilityError {
    #[error("an eligibility selector must contain at least one include glob")]
    EmptyInclude,
    #[error("an eligibility selector must contain at least one artifact kind")]
    EmptyArtifactKinds,
    #[error("invalid eligibility glob '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("could not construct a canonical candidate identifier: {0}")]
    CandidateId(#[source] crate::domain::OpaqueIdError),
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet, EligibilityError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
            .map_err(|source| EligibilityError::InvalidGlob {
                pattern: pattern.clone(),
                source,
            })?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|source| EligibilityError::InvalidGlob {
            pattern: "<combined-glob-set>".to_string(),
            source,
        })
}

fn artifact_logical_path(artifact: &Artifact) -> &LogicalPath {
    match &artifact.provenance {
        Provenance::Physical { logical_path } => logical_path,
        Provenance::Derived { member_path, .. } => member_path,
    }
}

fn logical_path_bytes(path: &LogicalPath) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, segment) in path.segments().iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(segment.as_slice());
    }
    bytes
}

fn candidate_id(
    analyzer_id: &AnalyzerId,
    artifact_id: &ArtifactId,
) -> Result<CandidateId, EligibilityError> {
    let mut identity = Vec::with_capacity(
        "file-guardian-candidate-v1".len()
            + analyzer_id.as_str().len()
            + artifact_id.as_str().len()
            + 2,
    );
    identity.extend_from_slice(b"file-guardian-candidate-v1\0");
    identity.extend_from_slice(analyzer_id.as_str().as_bytes());
    identity.push(0);
    identity.extend_from_slice(artifact_id.as_str().as_bytes());
    let digest = crate::domain::Digest::sha256(identity);
    let suffix = digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    CandidateId::from_suffix(suffix).map_err(EligibilityError::CandidateId)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Digest, ObjectId, PathSegment, PhysicalSubject, SourceFileType, SourceIdentity, SubjectId,
    };

    fn physical(suffix: &str, segments: Vec<PathSegment>) -> (PhysicalSubject, Artifact) {
        let subject_id = SubjectId::from_suffix(suffix).unwrap();
        let object_id = ObjectId::from_suffix(suffix).unwrap();
        let logical_path = LogicalPath::new(segments).unwrap();
        let digest = Digest::sha256(suffix.as_bytes());
        let source_identity = SourceIdentity {
            device: 1,
            inode: 1,
            file_type: SourceFileType::RegularFile,
            byte_len: 1,
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
            byte_len: 1,
        };
        let artifact = Artifact {
            id: ArtifactId::from_suffix(suffix).unwrap(),
            subject_id,
            object_id,
            kind: ArtifactKind::PhysicalFile,
            byte_len: 1,
            content_digest: digest,
            provenance: Provenance::Physical { logical_path },
        };
        (subject, artifact)
    }

    #[test]
    fn matches_canonical_path_bytes_and_exclusion_wins() {
        let (keep_subject, keep) = physical(
            "keep",
            vec![
                PathSegment::utf8("src").unwrap(),
                PathSegment::from_bytes([0xff, b'.', b'r', b's']).unwrap(),
            ],
        );
        let (deny_subject, deny) = physical(
            "deny",
            vec![
                PathSegment::utf8("src").unwrap(),
                PathSegment::utf8("generated.rs").unwrap(),
            ],
        );
        let manifest =
            ArtifactManifest::new(vec![deny_subject, keep_subject], vec![deny, keep]).unwrap();
        let selector = EligibilitySelector::compile(
            &["src/**".into()],
            &["src/generated.rs".into()],
            [ArtifactKind::PhysicalFile],
        )
        .unwrap();

        let selection = selector
            .assign(&AnalyzerId::new("scanner").unwrap(), &manifest)
            .unwrap();
        assert_eq!(selection.eligible_count(), 1);
        assert_eq!(selection.assignments()[0].artifact_id.as_str(), "a_keep");
    }

    #[test]
    fn kind_and_glob_misses_are_not_coverage_exclusions() {
        let (subject_a, artifact_a) =
            physical("a", vec![PathSegment::utf8("included.txt").unwrap()]);
        let (subject_b, artifact_b) =
            physical("b", vec![PathSegment::utf8("outside.bin").unwrap()]);
        let manifest =
            ArtifactManifest::new(vec![subject_a, subject_b], vec![artifact_a, artifact_b])
                .unwrap();
        let selector =
            EligibilitySelector::compile(&["*.txt".into()], &[], [ArtifactKind::PhysicalFile])
                .unwrap();
        let selection = selector
            .assign(&AnalyzerId::new("scanner").unwrap(), &manifest)
            .unwrap();

        assert_eq!(selection.eligible_count(), 1);
        // The API intentionally exposes no selector-derived exclusion count.
        assert_eq!(selection.assignments().len(), 1);
    }

    #[test]
    fn assignments_and_candidate_ids_are_canonical_and_repeatable() {
        let (subject_z, artifact_z) = physical("z", vec![PathSegment::utf8("z.txt").unwrap()]);
        let (subject_a, artifact_a) = physical("a", vec![PathSegment::utf8("a.txt").unwrap()]);
        let manifest =
            ArtifactManifest::new(vec![subject_z, subject_a], vec![artifact_z, artifact_a])
                .unwrap();
        let selector =
            EligibilitySelector::compile(&["**".into()], &[], [ArtifactKind::PhysicalFile])
                .unwrap();
        let analyzer = AnalyzerId::new("scanner").unwrap();

        let first = selector.assign(&analyzer, &manifest).unwrap();
        let second = selector.assign(&analyzer, &manifest).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.assignments()[0].artifact_id.as_str(), "a_a");
        assert_ne!(
            first.assignments()[0].candidate_id,
            first.assignments()[1].candidate_id
        );
    }

    #[test]
    fn invalid_or_empty_selectors_fail_at_compile_time() {
        assert!(matches!(
            EligibilitySelector::compile(&[], &[], [ArtifactKind::PhysicalFile]),
            Err(EligibilityError::EmptyInclude)
        ));
        assert!(matches!(
            EligibilitySelector::compile(&["[".into()], &[], [ArtifactKind::PhysicalFile]),
            Err(EligibilityError::InvalidGlob { .. })
        ));
        assert!(matches!(
            EligibilitySelector::compile(&["**".into()], &[], []),
            Err(EligibilityError::EmptyArtifactKinds)
        ));
    }
}
