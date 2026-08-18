//! Canonical conversion of analyzer observations into processing findings.
//!
//! Raw evidence is accepted only as borrowed input to the normalizer. Outputs
//! contain a job-local HMAC token and never retain evidence bytes or the HMAC
//! key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::domain::{
    AnalyzerId, ArtifactId, ArtifactManifest, Digest, FindingCategory, InspectionPhase,
    LogicalPath, NormalizedObservation, ObservationId, Provenance, RunId, ValidatedLocation,
};

use super::{
    Correlation, CorrelationId, CredentialVerificationState, Finding, FindingId, GitProvenance,
    Occurrence, OccurrenceId, ProcessingDomainError,
};

const HMAC_BLOCK_BYTES: usize = 64;
const ID_HEX_BYTES: usize = 24;

/// A random, per-job correlation key. It is intentionally not serializable and
/// its `Debug` representation never reveals key material.
#[derive(Clone)]
pub struct JobCorrelationKey([u8; 32]);

impl JobCorrelationKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for JobCorrelationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobCorrelationKey([REDACTED])")
    }
}

impl Drop for JobCorrelationKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Canonical logical provenance used for identity binding. Host paths are not
/// accepted by this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactFindingProvenance {
    LogicalPath(LogicalPath),
    Derived {
        parent_artifact_id: ArtifactId,
        member_path: LogicalPath,
    },
    Git {
        repository_identity: Digest,
        provenance: GitProvenance,
    },
}

/// Integrity and provenance identity for one analyzer-visible artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactFindingContext {
    pub artifact_id: ArtifactId,
    pub content_digest: Digest,
    pub provenance: ArtifactFindingProvenance,
}

impl ArtifactFindingContext {
    /// Builds contexts for a captured working-tree manifest. The caller still
    /// supplies the snapshot identity to `FindingNormalizationContext`.
    pub fn from_manifest(manifest: &ArtifactManifest) -> Vec<Self> {
        manifest
            .artifacts()
            .iter()
            .map(|artifact| Self {
                artifact_id: artifact.id.clone(),
                content_digest: artifact.content_digest,
                provenance: match &artifact.provenance {
                    Provenance::Physical { logical_path } => {
                        ArtifactFindingProvenance::LogicalPath(logical_path.clone())
                    }
                    Provenance::Derived {
                        parent_artifact_id,
                        member_path,
                    } => ArtifactFindingProvenance::Derived {
                        parent_artifact_id: parent_artifact_id.clone(),
                        member_path: member_path.clone(),
                    },
                },
            })
            .collect()
    }
}

/// Optional host-validated metadata for one observation. Evidence bytes are
/// borrowed and are never copied into the normalized result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ObservationEvidence<'a> {
    pub observation_id: &'a ObservationId,
    pub canonical_window: &'a [u8],
    pub verification_state: CredentialVerificationState,
}

impl fmt::Debug for ObservationEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationEvidence")
            .field("observation_id", self.observation_id)
            .field("canonical_window", &"[REDACTED]")
            .field("window_byte_len", &self.canonical_window.len())
            .field("verification_state", &self.verification_state)
            .finish()
    }
}

/// Frozen context for normalizing all completed analyzer runs in one phase.
#[derive(Clone, Copy, Debug)]
pub struct FindingNormalizationContext<'a> {
    pub run_id: &'a RunId,
    pub phase: InspectionPhase,
    /// Exact host-configured analyzer set whose observations are present.
    pub analyzer_ids: &'a [AnalyzerId],
    pub snapshot_identity: Digest,
    pub artifacts: &'a [ArtifactFindingContext],
    pub evidence: &'a [ObservationEvidence<'a>],
    pub correlation_key: &'a JobCorrelationKey,
}

/// Canonically ordered processing findings plus the mapping needed to resolve
/// legacy analyzer observations through processing policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPhaseFindings {
    pub occurrences: Vec<Occurrence>,
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
    pub observation_to_finding: BTreeMap<ObservationId, FindingId>,
    pub observation_to_occurrence: BTreeMap<ObservationId, OccurrenceId>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FindingNormalizationError {
    #[error("artifact finding context is duplicated")]
    DuplicateArtifact,
    #[error("Git artifact provenance is not canonical")]
    NonCanonicalGitProvenance,
    #[error("observation identifier is duplicated")]
    DuplicateObservation,
    #[error("observation evidence is duplicated")]
    DuplicateEvidence,
    #[error("analyzer-run context is empty or contains duplicate analyzer identifiers")]
    InvalidAnalyzerContext,
    #[error("observation evidence refers to an unknown observation")]
    UnknownEvidence,
    #[error("observation evidence windows must be non-empty and have a validated location")]
    InvalidEvidence,
    #[error("finding refers to an unknown artifact")]
    UnknownArtifact,
    #[error("finding analyzer is not present in its analyzer-run context")]
    AnalyzerMismatch,
    #[error("classification observations require a separate classification result path")]
    ClassificationUnsupported,
    #[error("processing finding domain construction failed: {0}")]
    Domain(#[from] ProcessingDomainError),
}

/// Converts host-validated analyzer observations into job-local processing
/// occurrences, findings, and correlations.
pub fn normalize_findings(
    context: FindingNormalizationContext<'_>,
    observations: &[NormalizedObservation],
) -> Result<NormalizedPhaseFindings, FindingNormalizationError> {
    let artifacts = unique_artifacts(context.artifacts)?;
    let analyzer_ids: BTreeSet<_> = context.analyzer_ids.iter().collect();
    if analyzer_ids.is_empty() || analyzer_ids.len() != context.analyzer_ids.len() {
        return Err(FindingNormalizationError::InvalidAnalyzerContext);
    }
    let observation_ids = unique_observation_ids(observations)?;
    let evidence = unique_evidence(context.evidence, &observation_ids)?;

    let mut occurrence_records = Vec::with_capacity(observations.len());
    for observation in observations {
        let NormalizedObservation::Finding(source) = observation else {
            return Err(FindingNormalizationError::ClassificationUnsupported);
        };
        if !analyzer_ids.contains(&source.analyzer_id) {
            return Err(FindingNormalizationError::AnalyzerMismatch);
        }
        let artifact = artifacts
            .get(&source.artifact_id)
            .ok_or(FindingNormalizationError::UnknownArtifact)?;
        let evidence = evidence.get(&source.id);
        if evidence.is_some_and(|metadata| {
            metadata.canonical_window.is_empty() || source.location.is_none()
        }) {
            return Err(FindingNormalizationError::InvalidEvidence);
        }
        let token = evidence.map(|metadata| {
            evidence_token(
                context.correlation_key,
                artifact,
                source,
                metadata.canonical_window,
            )
        });
        let verification_state = evidence.map_or_else(
            || default_verification_state(source.category),
            |metadata| metadata.verification_state,
        );
        let occurrence_id = OccurrenceId::from_suffix(id_suffix(hmac(
            context.correlation_key,
            &occurrence_identity(context, artifact, source, token),
        )))?;
        let finding_key = finding_identity(context, artifact, source, token);
        occurrence_records.push(OccurrenceRecord {
            source_id: source.id.clone(),
            finding_key,
            occurrence: Occurrence {
                id: occurrence_id,
                phase: context.phase,
                analyzer_id: source.analyzer_id.clone(),
                rule_id: source.rule_id.clone(),
                artifact_id: source.artifact_id.clone(),
                category: source.category,
                severity: source.severity,
                location: source.location.clone(),
                verification_state,
                evidence_token: token,
            },
        });
    }
    occurrence_records.sort_by(|left, right| left.occurrence.id.cmp(&right.occurrence.id));

    let mut grouped: BTreeMap<Vec<u8>, Vec<OccurrenceRecord>> = BTreeMap::new();
    for record in occurrence_records {
        grouped
            .entry(record.finding_key.clone())
            .or_default()
            .push(record);
    }

    let mut findings = Vec::with_capacity(grouped.len());
    let mut occurrences = Vec::with_capacity(observations.len());
    let mut observation_to_finding = BTreeMap::new();
    let mut observation_to_occurrence = BTreeMap::new();
    for (finding_key, records) in grouped {
        let first = &records[0].occurrence;
        let finding_id =
            FindingId::from_suffix(id_suffix(hmac(context.correlation_key, &finding_key)))?;
        let occurrence_ids = records
            .iter()
            .map(|record| record.occurrence.id.clone())
            .collect();
        findings.push(Finding::new(
            finding_id.clone(),
            first.phase,
            first.analyzer_id.clone(),
            first.rule_id.clone(),
            first.artifact_id.clone(),
            first.category,
            first.severity,
            first.location.clone(),
            first.evidence_token,
            occurrence_ids,
        )?);
        for record in records {
            observation_to_finding.insert(record.source_id.clone(), finding_id.clone());
            observation_to_occurrence.insert(record.source_id, record.occurrence.id.clone());
            occurrences.push(record.occurrence);
        }
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    occurrences.sort_by(|left, right| left.id.cmp(&right.id));

    let correlations = correlate(context, &findings, &occurrences)?;
    Ok(NormalizedPhaseFindings {
        occurrences,
        findings,
        correlations,
        observation_to_finding,
        observation_to_occurrence,
    })
}

#[derive(Clone)]
struct OccurrenceRecord {
    source_id: ObservationId,
    finding_key: Vec<u8>,
    occurrence: Occurrence,
}

fn unique_artifacts(
    values: &[ArtifactFindingContext],
) -> Result<BTreeMap<ArtifactId, &ArtifactFindingContext>, FindingNormalizationError> {
    let mut result = BTreeMap::new();
    for value in values {
        if let ArtifactFindingProvenance::Git { provenance, .. } = &value.provenance {
            let canonical = GitProvenance::new(
                provenance.blob_id.clone(),
                provenance.mode,
                provenance.occurrences.clone(),
            )?;
            if &canonical != provenance {
                return Err(FindingNormalizationError::NonCanonicalGitProvenance);
            }
        }
        if result.insert(value.artifact_id.clone(), value).is_some() {
            return Err(FindingNormalizationError::DuplicateArtifact);
        }
    }
    Ok(result)
}

fn unique_observation_ids(
    values: &[NormalizedObservation],
) -> Result<BTreeSet<ObservationId>, FindingNormalizationError> {
    let mut result = BTreeSet::new();
    for value in values {
        let id = match value {
            NormalizedObservation::Finding(finding) => &finding.id,
            NormalizedObservation::Classification(classification) => &classification.id,
        };
        if !result.insert(id.clone()) {
            return Err(FindingNormalizationError::DuplicateObservation);
        }
    }
    Ok(result)
}

fn unique_evidence<'a>(
    values: &'a [ObservationEvidence<'a>],
    observation_ids: &BTreeSet<ObservationId>,
) -> Result<BTreeMap<ObservationId, &'a ObservationEvidence<'a>>, FindingNormalizationError> {
    let mut result = BTreeMap::new();
    for value in values {
        if !observation_ids.contains(value.observation_id) {
            return Err(FindingNormalizationError::UnknownEvidence);
        }
        if result.insert(value.observation_id.clone(), value).is_some() {
            return Err(FindingNormalizationError::DuplicateEvidence);
        }
    }
    Ok(result)
}

fn default_verification_state(category: FindingCategory) -> CredentialVerificationState {
    match category {
        FindingCategory::Secret | FindingCategory::Credential => {
            CredentialVerificationState::Unverified
        }
        _ => CredentialVerificationState::NotApplicable,
    }
}

fn evidence_token(
    key: &JobCorrelationKey,
    artifact: &ArtifactFindingContext,
    finding: &crate::domain::Finding,
    window: &[u8],
) -> Digest {
    let mut material = Vec::new();
    component(&mut material, b"file-guardian/evidence-token/1");
    artifact_evidence_identity(&mut material, artifact);
    component(&mut material, finding.analyzer_id.as_str().as_bytes());
    component(&mut material, finding.rule_id.as_str().as_bytes());
    component(&mut material, category_name(finding.category));
    component(&mut material, window);
    Digest::from_array(hmac(key, &material))
}

/// Evidence correlation deliberately excludes snapshot and host artifact IDs.
/// It stays stable across processing phases when the exact artifact bytes,
/// publication location/provenance, scanner rule, and evidence window are
/// unchanged. Finding and occurrence IDs remain snapshot- and phase-bound.
fn artifact_evidence_identity(output: &mut Vec<u8>, artifact: &ArtifactFindingContext) {
    component(output, artifact.content_digest.as_bytes());
    match &artifact.provenance {
        ArtifactFindingProvenance::LogicalPath(path) => {
            component(output, b"path");
            logical_path_identity(output, path);
        }
        ArtifactFindingProvenance::Derived {
            parent_artifact_id,
            member_path,
        } => {
            component(output, b"derived");
            component(output, parent_artifact_id.as_str().as_bytes());
            logical_path_identity(output, member_path);
        }
        ArtifactFindingProvenance::Git {
            repository_identity,
            provenance,
        } => {
            component(output, b"git");
            component(output, repository_identity.as_bytes());
            component(output, provenance.blob_id.to_string().as_bytes());
            component(output, git_mode_name(provenance.mode));
            for occurrence in &provenance.occurrences {
                component(output, occurrence.commit_id.to_string().as_bytes());
                logical_path_identity(output, &occurrence.path);
                for reference in &occurrence.refs {
                    logical_path_identity(output, reference);
                }
                component(output, b"end-refs");
            }
            component(output, b"end-occurrences");
        }
    }
}

fn occurrence_identity(
    context: FindingNormalizationContext<'_>,
    artifact: &ArtifactFindingContext,
    finding: &crate::domain::Finding,
    token: Option<Digest>,
) -> Vec<u8> {
    let mut material = Vec::new();
    component(&mut material, b"file-guardian/occurrence-id/1");
    component(&mut material, context.run_id.as_str().as_bytes());
    component(&mut material, phase_name(context.phase));
    component(&mut material, finding.id.as_str().as_bytes());
    component(&mut material, context.snapshot_identity.as_bytes());
    artifact_identity(&mut material, artifact);
    finding_shape(&mut material, finding, token);
    material
}

fn finding_identity(
    context: FindingNormalizationContext<'_>,
    artifact: &ArtifactFindingContext,
    finding: &crate::domain::Finding,
    token: Option<Digest>,
) -> Vec<u8> {
    let mut material = Vec::new();
    component(&mut material, b"file-guardian/finding-id/1");
    component(&mut material, context.run_id.as_str().as_bytes());
    component(&mut material, phase_name(context.phase));
    component(&mut material, context.snapshot_identity.as_bytes());
    artifact_identity(&mut material, artifact);
    finding_shape(&mut material, finding, token);
    material
}

fn finding_shape(output: &mut Vec<u8>, finding: &crate::domain::Finding, token: Option<Digest>) {
    component(output, finding.analyzer_id.as_str().as_bytes());
    component(output, finding.rule_id.as_str().as_bytes());
    component(output, category_name(finding.category));
    component(output, severity_name(finding.severity));
    location_identity(output, finding.location.as_ref());
    optional_digest(output, token);
}

fn artifact_identity(output: &mut Vec<u8>, artifact: &ArtifactFindingContext) {
    component(output, artifact.artifact_id.as_str().as_bytes());
    component(output, artifact.content_digest.as_bytes());
    match &artifact.provenance {
        ArtifactFindingProvenance::LogicalPath(path) => {
            component(output, b"path");
            logical_path_identity(output, path);
        }
        ArtifactFindingProvenance::Derived {
            parent_artifact_id,
            member_path,
        } => {
            component(output, b"derived");
            component(output, parent_artifact_id.as_str().as_bytes());
            logical_path_identity(output, member_path);
        }
        ArtifactFindingProvenance::Git {
            repository_identity,
            provenance,
        } => {
            component(output, b"git");
            component(output, repository_identity.as_bytes());
            component(output, provenance.blob_id.to_string().as_bytes());
            component(output, git_mode_name(provenance.mode));
            for occurrence in &provenance.occurrences {
                component(output, occurrence.commit_id.to_string().as_bytes());
                logical_path_identity(output, &occurrence.path);
                for reference in &occurrence.refs {
                    logical_path_identity(output, reference);
                }
                component(output, b"end-refs");
            }
            component(output, b"end-occurrences");
        }
    }
}

fn logical_path_identity(output: &mut Vec<u8>, path: &LogicalPath) {
    for segment in path.segments() {
        component(output, segment.as_slice());
    }
    component(output, b"end-path");
}

fn correlate(
    context: FindingNormalizationContext<'_>,
    findings: &[Finding],
    occurrences: &[Occurrence],
) -> Result<Vec<Correlation>, FindingNormalizationError> {
    let mut parent: Vec<usize> = (0..findings.len()).collect();
    for left in 0..findings.len() {
        for right in (left + 1)..findings.len() {
            if correlates(&findings[left], &findings[right]) {
                union(&mut parent, left, right);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<&Finding>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        let root = find(&mut parent, index);
        groups.entry(root).or_default().push(finding);
    }
    let occurrence_by_id: BTreeMap<_, _> = occurrences
        .iter()
        .map(|occurrence| (occurrence.id.clone(), occurrence))
        .collect();
    let mut result = Vec::with_capacity(groups.len());
    for mut group in groups.into_values() {
        group.sort_by(|left, right| left.id.cmp(&right.id));
        let finding_ids: Vec<_> = group.iter().map(|finding| finding.id.clone()).collect();
        let mut occurrence_ids: Vec<_> = group
            .iter()
            .flat_map(|finding| finding.occurrence_ids.iter().cloned())
            .collect();
        occurrence_ids.sort();
        occurrence_ids.dedup();
        debug_assert!(occurrence_ids
            .iter()
            .all(|id| occurrence_by_id.contains_key(id)));
        let mut identity = Vec::new();
        component(&mut identity, b"file-guardian/correlation-id/1");
        component(&mut identity, context.run_id.as_str().as_bytes());
        component(&mut identity, phase_name(context.phase));
        for id in &finding_ids {
            component(&mut identity, id.as_str().as_bytes());
        }
        let id = CorrelationId::from_suffix(id_suffix(hmac(context.correlation_key, &identity)))?;
        result.push(Correlation::new(
            id,
            context.phase,
            finding_ids,
            occurrence_ids,
        )?);
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

fn correlates(left: &Finding, right: &Finding) -> bool {
    if left.artifact_id != right.artifact_id || left.category != right.category {
        return false;
    }
    if left.evidence_token.is_some() && left.evidence_token == right.evidence_token {
        return true;
    }
    locations_overlap(left.location.as_ref(), right.location.as_ref())
}

fn locations_overlap(left: Option<&ValidatedLocation>, right: Option<&ValidatedLocation>) -> bool {
    match (left, right) {
        (
            Some(ValidatedLocation::ByteRange {
                start: left_start,
                end_exclusive: left_end,
            }),
            Some(ValidatedLocation::ByteRange {
                start: right_start,
                end_exclusive: right_end,
            }),
        ) => left_start < right_end && right_start < left_end,
        (
            Some(ValidatedLocation::Line { line: left_line }),
            Some(ValidatedLocation::Line { line: right_line }),
        ) => left_line == right_line,
        (
            Some(ValidatedLocation::Line { line: left_line }),
            Some(ValidatedLocation::LineColumn {
                line: right_line, ..
            }),
        )
        | (
            Some(ValidatedLocation::LineColumn {
                line: right_line, ..
            }),
            Some(ValidatedLocation::Line { line: left_line }),
        ) => left_line == right_line,
        (
            Some(ValidatedLocation::LineColumn {
                line: left_line, ..
            }),
            Some(ValidatedLocation::LineColumn {
                line: right_line, ..
            }),
        ) => left_line == right_line,
        _ => false,
    }
}

fn find(parent: &mut [usize], index: usize) -> usize {
    if parent[index] != index {
        parent[index] = find(parent, parent[index]);
    }
    parent[index]
}

fn union(parent: &mut [usize], left: usize, right: usize) {
    let left_root = find(parent, left);
    let right_root = find(parent, right);
    if left_root != right_root {
        parent[right_root] = left_root;
    }
}

fn hmac(key: &JobCorrelationKey, message: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key.0.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn id_suffix(value: [u8; 32]) -> String {
    value[..ID_HEX_BYTES]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn component(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn optional_digest(output: &mut Vec<u8>, value: Option<Digest>) {
    match value {
        Some(value) => {
            component(output, b"some");
            component(output, value.as_bytes());
        }
        None => component(output, b"none"),
    }
}

fn location_identity(output: &mut Vec<u8>, location: Option<&ValidatedLocation>) {
    match location {
        None => component(output, b"none"),
        Some(ValidatedLocation::ByteRange {
            start,
            end_exclusive,
        }) => {
            component(output, b"byte-range");
            component(output, &start.to_be_bytes());
            component(output, &end_exclusive.to_be_bytes());
        }
        Some(ValidatedLocation::Line { line }) => {
            component(output, b"line");
            component(output, &line.to_be_bytes());
        }
        Some(ValidatedLocation::LineColumn { line, column }) => {
            component(output, b"line-column");
            component(output, &line.to_be_bytes());
            component(output, &column.to_be_bytes());
        }
    }
}

const fn phase_name(phase: InspectionPhase) -> &'static [u8] {
    match phase {
        InspectionPhase::Initial => b"initial",
        InspectionPhase::Verification => b"verification",
    }
}

const fn category_name(category: FindingCategory) -> &'static [u8] {
    match category {
        FindingCategory::Secret => b"secret",
        FindingCategory::Credential => b"credential",
        FindingCategory::SensitiveContent => b"sensitive-content",
        FindingCategory::KnownSensitiveFile => b"known-sensitive-file",
        FindingCategory::Filename => b"filename",
        FindingCategory::ContentPattern => b"content-pattern",
        FindingCategory::PolicyViolation => b"policy-violation",
    }
}

const fn severity_name(severity: crate::domain::Severity) -> &'static [u8] {
    match severity {
        crate::domain::Severity::Informational => b"informational",
        crate::domain::Severity::Low => b"low",
        crate::domain::Severity::Medium => b"medium",
        crate::domain::Severity::High => b"high",
        crate::domain::Severity::Critical => b"critical",
    }
}

const fn git_mode_name(mode: super::GitBlobMode) -> &'static [u8] {
    match mode {
        super::GitBlobMode::Regular => b"regular",
        super::GitBlobMode::Executable => b"executable",
        super::GitBlobMode::SymbolicLink => b"symbolic-link",
    }
}
