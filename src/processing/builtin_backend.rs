//! Schema-3 adapter for the in-process deterministic rules analyzer.

use std::sync::Arc;

use crate::analyzers::ArtifactReadError;
use crate::analyzers::{
    BuiltinAssignmentDisposition, BuiltinProcessingAssignment, BuiltinProcessingError,
    BuiltinProcessingReader, BuiltinRulesAnalyzer,
};
use crate::domain::ArtifactId;
use crate::processing::executor::{
    AnalyzerBackendError, AnalyzerBackendOutput, AnalyzerInvocation, AssignmentDisposition,
    AssignmentOutcome, BackendFuture, BuiltinProcessingBackend,
};
use crate::processing::external_backend::{ProcessingArtifactReadError, ProcessingArtifactReader};

/// Executes deterministic rules only against the immutable captured object
/// manifest and reader. The live source and mutable stage are never consulted.
pub struct CapturedBuiltinProcessingBackend<R> {
    reader: Arc<R>,
}

impl<R> CapturedBuiltinProcessingBackend<R> {
    pub fn new(reader: Arc<R>) -> Self {
        Self { reader }
    }
}

impl<R> BuiltinProcessingBackend for CapturedBuiltinProcessingBackend<R>
where
    R: ProcessingArtifactReader + Send + Sync + 'static,
{
    fn execute<'a>(
        &'a self,
        runtime: &'a BuiltinRulesAnalyzer,
        invocation: AnalyzerInvocation,
    ) -> BackendFuture<'a> {
        Box::pin(async move {
            if invocation.analyzer_id != *runtime.id() {
                return Err(AnalyzerBackendError::InvalidOutput);
            }
            let assignments = invocation
                .assignments
                .iter()
                .map(|assignment| BuiltinProcessingAssignment {
                    artifact_id: assignment.artifact_id.clone(),
                    logical_path: assignment.logical_path.clone(),
                    byte_len: assignment.byte_len,
                    content_digest: assignment.content_digest,
                })
                .collect::<Vec<_>>();
            let reader = ProcessingReader(self.reader.as_ref());
            let result = runtime
                .analyze_processing(invocation.phase, &assignments, &reader)
                .map_err(map_processing_error)?;

            let assignments = invocation
                .assignments
                .iter()
                .zip(result.assignment_outcomes)
                .map(|(assigned, completed)| {
                    if assigned.artifact_id != completed.artifact_id {
                        return Err(AnalyzerBackendError::InvalidOutput);
                    }
                    Ok(AssignmentOutcome {
                        candidate_id: assigned.candidate_id.clone(),
                        disposition: match completed.disposition {
                            BuiltinAssignmentDisposition::Completed => {
                                AssignmentDisposition::Completed
                            }
                            BuiltinAssignmentDisposition::NotApplicable => {
                                AssignmentDisposition::NotApplicable
                            }
                        },
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(AnalyzerBackendOutput {
                assignments,
                observations: result.observations,
                evidence: Vec::new(),
                scanner_version: None,
                pi_analysis: None,
            })
        })
    }
}

struct ProcessingReader<'a, R>(&'a R);

impl<R: ProcessingArtifactReader> BuiltinProcessingReader for ProcessingReader<'_, R> {
    fn open_artifact(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Box<dyn std::io::Read + '_>, ArtifactReadError> {
        let reader = self
            .0
            .open(artifact_id)
            .map_err(|ProcessingArtifactReadError::Unavailable| ArtifactReadError::Unavailable)?;
        Ok(reader)
    }
}

fn map_processing_error(error: BuiltinProcessingError) -> AnalyzerBackendError {
    match error {
        BuiltinProcessingError::Unavailable => AnalyzerBackendError::Unavailable,
        BuiltinProcessingError::BudgetExceeded => AnalyzerBackendError::BudgetExceeded,
        BuiltinProcessingError::Assignment | BuiltinProcessingError::InvalidContent => {
            AnalyzerBackendError::InvalidOutput
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};
    use std::str::FromStr;

    use regex::Regex;

    use super::*;
    use crate::analyzers::{
        BuiltinAnalyzerLimits, BuiltinContentApplicability, RequiredTextMatcher,
    };
    use crate::domain::{
        ArtifactId, CandidateId, Digest, InspectionPhase, LogicalPath, PathSegment,
    };
    use crate::pipeline::{PriorObservationMode, PriorObservationProjection, ProjectionLimits};
    use crate::processing::config::AnalyzerArtifactKind;
    use crate::processing::executor::{
        ProcessingArtifact, ProcessingArtifactCatalog, ProcessingArtifactSurface,
    };
    use crate::processing::findings::NormalizedPhaseFindings;
    use crate::processing::{
        GitBlobMode, GitBlobOccurrence, GitHistoryScope, GitObjectId, GitProvenance,
    };
    use crate::rules::{CompiledRule, RuleSource};

    #[derive(Default)]
    struct MemoryReader(BTreeMap<ArtifactId, Vec<u8>>);

    impl ProcessingArtifactReader for MemoryReader {
        fn open(
            &self,
            artifact_id: &ArtifactId,
        ) -> Result<Box<dyn Read + Send>, ProcessingArtifactReadError> {
            self.0
                .get(artifact_id)
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read + Send>)
                .ok_or(ProcessingArtifactReadError::Unavailable)
        }
    }

    fn fixture(
        max_content_bytes: u64,
        history: bool,
    ) -> (BuiltinRulesAnalyzer, Arc<MemoryReader>, AnalyzerInvocation) {
        let analyzer = BuiltinRulesAnalyzer::new(
            "rules",
            vec![CompiledRule {
                name: "credential".into(),
                filename_glob: None,
                content_regex: Some(Regex::new("needle").unwrap()),
                source: RuleSource::new("<test>"),
            }],
            BuiltinAnalyzerLimits {
                max_content_bytes,
                max_findings: 100,
                content_applicability: BuiltinContentApplicability::default(),
            },
        )
        .unwrap();
        let entries: [(&str, &[u8]); 2] = [("binary.bin", &[0xff]), ("text.txt", b"needle needle")];
        let mut catalog = Vec::new();
        let mut reader = MemoryReader::default();
        for (index, (name, bytes)) in entries.into_iter().enumerate() {
            let suffix = format!("{:04}", index + 1);
            let artifact_id = ArtifactId::from_suffix(&suffix).unwrap();
            let path = LogicalPath::new(vec![PathSegment::utf8(name).unwrap()]).unwrap();
            let content_digest = Digest::sha256(bytes);
            let surface = if history {
                let blob = GitObjectId::from_str(&format!("sha1:{}", "1".repeat(40))).unwrap();
                let commit =
                    GitObjectId::from_str(&format!("sha1:{}", format!("{}", index + 2).repeat(40)))
                        .unwrap();
                ProcessingArtifactSurface::GitHistory {
                    repository_identity: Digest::sha256(b"repository"),
                    history_scope: GitHistoryScope::Reachable,
                    provenance: GitProvenance::new(
                        blob,
                        GitBlobMode::Regular,
                        vec![GitBlobOccurrence {
                            commit_id: commit,
                            path: path.clone(),
                            refs: Vec::new(),
                        }],
                    )
                    .unwrap(),
                }
            } else {
                ProcessingArtifactSurface::WorkingTree
            };
            catalog.push(ProcessingArtifact {
                artifact_id: artifact_id.clone(),
                logical_path: path.clone(),
                kind: if history {
                    AnalyzerArtifactKind::RepositoryBlob
                } else {
                    AnalyzerArtifactKind::PhysicalFile
                },
                byte_len: bytes.len() as u64,
                content_digest,
                surface,
            });
            reader.0.insert(artifact_id, bytes.to_vec());
        }
        let catalog = Arc::new(ProcessingArtifactCatalog::new(catalog).unwrap());
        let assignments = catalog
            .artifacts()
            .iter()
            .enumerate()
            .map(
                |(index, artifact)| crate::processing::executor::ProcessingAssignment {
                    candidate_id: CandidateId::from_suffix(format!("{:04}", index + 1)).unwrap(),
                    artifact_id: artifact.artifact_id.clone(),
                    logical_path: artifact.logical_path.clone(),
                    kind: artifact.kind,
                    byte_len: artifact.byte_len,
                    content_digest: artifact.content_digest,
                    surface: artifact.surface.clone(),
                },
            )
            .collect::<Vec<_>>();
        let prior = PriorObservationProjection::build(
            PriorObservationMode::None,
            &[],
            ProjectionLimits::new(10, 1_000).unwrap(),
        )
        .unwrap();
        let invocation = AnalyzerInvocation {
            phase: InspectionPhase::Initial,
            analyzer_id: analyzer.id().clone(),
            assignments: assignments.into(),
            artifacts: catalog,
            prior: Arc::new(prior),
            prior_findings: Arc::new(NormalizedPhaseFindings {
                occurrences: Vec::new(),
                findings: Vec::new(),
                correlations: Vec::new(),
                observation_to_finding: BTreeMap::new(),
            }),
            prior_coverage: Arc::from([]),
        };
        (analyzer, Arc::new(reader), invocation)
    }

    #[tokio::test]
    async fn preserves_exact_mixed_assignment_dispositions() {
        let (analyzer, reader, invocation) = fixture(1_000, false);
        let backend = CapturedBuiltinProcessingBackend::new(reader);

        let result = backend.execute(&analyzer, invocation).await.unwrap();

        assert_eq!(result.assignments.len(), 2);
        assert_eq!(
            result.assignments[0].disposition,
            AssignmentDisposition::NotApplicable
        );
        assert_eq!(
            result.assignments[1].disposition,
            AssignmentDisposition::Completed
        );
        assert_eq!(result.observations.len(), 2);
    }

    #[tokio::test]
    async fn incomplete_builtin_analysis_is_a_backend_failure() {
        let (analyzer, reader, invocation) = fixture(1, false);
        let backend = CapturedBuiltinProcessingBackend::new(reader);

        assert_eq!(
            backend.execute(&analyzer, invocation).await,
            Err(AnalyzerBackendError::BudgetExceeded)
        );
    }

    #[tokio::test]
    async fn repository_blobs_are_scanned_without_fabricating_physical_artifacts() {
        let (_, reader, invocation) = fixture(1_000, true);
        let analyzer = BuiltinRulesAnalyzer::new(
            "rules",
            vec![
                CompiledRule {
                    name: "credential".into(),
                    filename_glob: None,
                    content_regex: Some(Regex::new("needle").unwrap()),
                    source: RuleSource::new("<test>"),
                },
                CompiledRule {
                    name: "text-name".into(),
                    filename_glob: Some(glob::Pattern::new("*.txt").unwrap()),
                    content_regex: None,
                    source: RuleSource::new("<test>"),
                },
            ],
            BuiltinAnalyzerLimits {
                max_content_bytes: 1_000,
                max_findings: 100,
                content_applicability: BuiltinContentApplicability::default(),
            },
        )
        .unwrap();
        assert!(invocation.assignments.iter().all(|assignment| matches!(
            assignment.surface,
            ProcessingArtifactSurface::GitHistory {
                history_scope: GitHistoryScope::Reachable,
                ..
            }
        )));
        let backend = CapturedBuiltinProcessingBackend::new(reader);

        let result = backend.execute(&analyzer, invocation).await.unwrap();

        assert_eq!(result.assignments.len(), 2);
        assert_eq!(result.observations.len(), 3);
        let findings = result
            .observations
            .iter()
            .map(|observation| {
                let crate::domain::NormalizedObservation::Finding(finding) = observation else {
                    panic!("built-in rules emit findings");
                };
                finding
            })
            .collect::<Vec<_>>();
        assert!(findings
            .iter()
            .all(|finding| finding.artifact_id == ArtifactId::from_suffix("0002").unwrap()));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id.as_str() == "credential")
                .count(),
            2
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id.as_str() == "text-name")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn symbolic_link_assignment_scans_its_frozen_target_bytes() {
        let (analyzer, reader, mut invocation) = fixture(1_000, false);
        let mut assignments = invocation.assignments.to_vec();
        assignments[1].kind = AnalyzerArtifactKind::SymbolicLink;
        invocation.assignments = assignments.into();
        let backend = CapturedBuiltinProcessingBackend::new(reader);

        let result = backend.execute(&analyzer, invocation).await.unwrap();

        assert_eq!(result.observations.len(), 2);
        assert_eq!(
            result.assignments[1].disposition,
            AssignmentDisposition::Completed
        );
    }

    #[tokio::test]
    async fn required_text_policy_fails_closed_for_history_binary_content() {
        let (_, reader, invocation) = fixture(1_000, true);
        let analyzer = BuiltinRulesAnalyzer::new(
            "rules",
            vec![CompiledRule {
                name: "credential".into(),
                filename_glob: None,
                content_regex: Some(Regex::new("needle").unwrap()),
                source: RuleSource::new("<test>"),
            }],
            BuiltinAnalyzerLimits {
                max_content_bytes: 1_000,
                max_findings: 100,
                content_applicability: BuiltinContentApplicability {
                    required_text: RequiredTextMatcher::compile(&["binary.bin".to_owned()])
                        .unwrap(),
                },
            },
        )
        .unwrap();
        let backend = CapturedBuiltinProcessingBackend::new(reader);

        assert_eq!(
            backend.execute(&analyzer, invocation).await,
            Err(AnalyzerBackendError::InvalidOutput)
        );
    }
}
