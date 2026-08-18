use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::domain::{
    ArtifactId, Digest, InspectionPhase, LogicalPath, SourceFileType, SourceIdentity, SubjectId,
};
use crate::policy::{BindingId, PolicyDirective};
use crate::processing::domain::{ActionId, ActionKind, ArtifactQuarantineId, Finding, FindingId};

const ACTION_PLAN_SCHEMA_VERSION: &str = "1";

/// How an analyzer-visible artifact relates to the mutable job stage.
///
/// Only `MutablePhysicalRegularFile` can become an action target.  Symlinks
/// and nonphysical repository/history artifacts remain useful policy subjects,
/// but a mutating directive against either fails closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StagePublication {
    MutablePhysicalRegularFile { identity: SourceIdentity },
    PhysicalSymlink,
    Nonphysical,
}

/// Immutable planner input produced by trusted stage capture.
///
/// `logical_path` comes from descriptor-anchored capture, never from analyzer
/// output.  The duplicated length and digest make malformed hand-built inputs
/// fail before an action can be planned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageSubject {
    pub artifact_id: ArtifactId,
    pub subject_id: SubjectId,
    pub logical_path: LogicalPath,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub publication: StagePublication,
}

impl StageSubject {
    pub fn mutable_regular_file(
        artifact_id: ArtifactId,
        subject_id: SubjectId,
        logical_path: LogicalPath,
        identity: SourceIdentity,
    ) -> Result<Self, ActionPlanError> {
        if identity.file_type != SourceFileType::RegularFile || identity.link_count != 1 {
            return Err(ActionPlanError::InvalidMutableSubject);
        }
        Ok(Self {
            artifact_id,
            subject_id,
            logical_path,
            byte_len: identity.byte_len,
            content_digest: identity.content_digest,
            publication: StagePublication::MutablePhysicalRegularFile { identity },
        })
    }

    pub fn physical_symlink(
        artifact_id: ArtifactId,
        subject_id: SubjectId,
        logical_path: LogicalPath,
        byte_len: u64,
        content_digest: Digest,
    ) -> Self {
        Self {
            artifact_id,
            subject_id,
            logical_path,
            byte_len,
            content_digest,
            publication: StagePublication::PhysicalSymlink,
        }
    }

    pub fn nonphysical(
        artifact_id: ArtifactId,
        subject_id: SubjectId,
        logical_path: LogicalPath,
        byte_len: u64,
        content_digest: Digest,
    ) -> Self {
        Self {
            artifact_id,
            subject_id,
            logical_path,
            byte_len,
            content_digest,
            publication: StagePublication::Nonphysical,
        }
    }

    fn validate(&self) -> Result<(), ActionPlanError> {
        if let StagePublication::MutablePhysicalRegularFile { identity } = &self.publication {
            if identity.file_type != SourceFileType::RegularFile
                || identity.link_count != 1
                || identity.byte_len != self.byte_len
                || identity.content_digest != self.content_digest
            {
                return Err(ActionPlanError::InvalidMutableSubject);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StageSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            artifact_id: ArtifactId,
            subject_id: SubjectId,
            logical_path: LogicalPath,
            byte_len: u64,
            content_digest: Digest,
            publication: StagePublication,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            artifact_id: wire.artifact_id,
            subject_id: wire.subject_id,
            logical_path: wire.logical_path,
            byte_len: wire.byte_len,
            content_digest: wire.content_digest,
            publication: wire.publication,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    Active,
    Cleared,
}

/// Total policy resolution for one normalized processing finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingResolution {
    pub finding_id: FindingId,
    pub binding_id: BindingId,
    pub directive: PolicyDirective,
    pub state: ResolutionState,
}

/// Exact live-file precondition frozen into a whole-file action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionTarget {
    pub artifact_id: ArtifactId,
    pub subject_id: SubjectId,
    pub logical_path: LogicalPath,
    pub expected_identity: SourceIdentity,
}

impl ActionTarget {
    fn from_subject(subject: &StageSubject) -> Result<Self, ActionPlanError> {
        subject.validate()?;
        let StagePublication::MutablePhysicalRegularFile { identity } = &subject.publication else {
            return Err(ActionPlanError::UnactionableSubject {
                artifact_id: subject.artifact_id.clone(),
            });
        };
        Ok(Self {
            artifact_id: subject.artifact_id.clone(),
            subject_id: subject.subject_id.clone(),
            logical_path: subject.logical_path.clone(),
            expected_identity: identity.clone(),
        })
    }

    fn validate(&self) -> Result<(), ActionPlanError> {
        if self.expected_identity.file_type != SourceFileType::RegularFile
            || self.expected_identity.link_count != 1
        {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedAction {
    pub id: ActionId,
    pub kind: ActionKind,
    pub target: ActionTarget,
    pub finding_ids: Vec<FindingId>,
    pub binding_ids: Vec<BindingId>,
    pub artifact_quarantine_id: Option<ArtifactQuarantineId>,
}

impl PlannedAction {
    fn validate(&self) -> Result<(), ActionPlanError> {
        self.target.validate()?;
        if self.finding_ids.is_empty()
            || self.binding_ids.is_empty()
            || !strictly_sorted(&self.finding_ids)
            || !strictly_sorted(&self.binding_ids)
            || (self.kind == ActionKind::Delete && self.artifact_quarantine_id.is_some())
            || (self.kind == ActionKind::Quarantine && self.artifact_quarantine_id.is_none())
        {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        if action_id(
            self.kind,
            &self.target,
            &self.finding_ids,
            &self.binding_ids,
        )? != self.id
        {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        if self.kind == ActionKind::Quarantine
            && Some(quarantine_id(&self.id)?) != self.artifact_quarantine_id
        {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PlannedAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: ActionId,
            kind: ActionKind,
            target: ActionTarget,
            finding_ids: Vec<FindingId>,
            binding_ids: Vec<BindingId>,
            artifact_quarantine_id: Option<ArtifactQuarantineId>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            id: wire.id,
            kind: wire.kind,
            target: wire.target,
            finding_ids: wire.finding_ids,
            binding_ids: wire.binding_ids,
            artifact_quarantine_id: wire.artifact_quarantine_id,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPlan {
    schema_version: String,
    pub identity: Digest,
    pub initial_manifest_identity: Digest,
    pub actions: Vec<PlannedAction>,
}

impl ActionPlan {
    fn new(
        initial_manifest_identity: Digest,
        mut actions: Vec<PlannedAction>,
    ) -> Result<Self, ActionPlanError> {
        actions.sort_by(|left, right| {
            left.target
                .logical_path
                .cmp(&right.target.logical_path)
                .then_with(|| left.target.subject_id.cmp(&right.target.subject_id))
                .then_with(|| left.id.cmp(&right.id))
        });
        if actions.is_empty() {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        for action in &actions {
            action.validate()?;
        }
        let identity = plan_identity(initial_manifest_identity, &actions)?;
        Ok(Self {
            schema_version: ACTION_PLAN_SCHEMA_VERSION.to_owned(),
            identity,
            initial_manifest_identity,
            actions,
        })
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn validate(&self) -> Result<(), ActionPlanError> {
        if self.schema_version != ACTION_PLAN_SCHEMA_VERSION
            || self.actions.is_empty()
            || !self.actions.windows(2).all(|pair| {
                pair[0]
                    .target
                    .logical_path
                    .cmp(&pair[1].target.logical_path)
                    .then_with(|| pair[0].target.subject_id.cmp(&pair[1].target.subject_id))
                    .then_with(|| pair[0].id.cmp(&pair[1].id))
                    .is_lt()
            })
        {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        let mut subjects = BTreeSet::new();
        let mut logical_paths = BTreeSet::new();
        for action in &self.actions {
            if !subjects.insert(&action.target.subject_id)
                || !logical_paths.insert(&action.target.logical_path)
            {
                return Err(ActionPlanError::InvalidSerializedPlan);
            }
            action.validate()?;
        }
        if plan_identity(self.initial_manifest_identity, &self.actions)? != self.identity {
            return Err(ActionPlanError::InvalidSerializedPlan);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ActionPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            identity: Digest,
            initial_manifest_identity: Digest,
            actions: Vec<PlannedAction>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            identity: wire.identity,
            initial_manifest_identity: wire.initial_manifest_identity,
            actions: wire.actions,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionPlanOutcome {
    NoActions,
    SuppressedByDeny { finding_ids: Vec<FindingId> },
    Planned(ActionPlan),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ActionPlanError {
    #[error("stage subject is not a stable single-link regular file")]
    InvalidMutableSubject,
    #[error("stage subjects contain duplicate artifact {0}")]
    DuplicateArtifact(ArtifactId),
    #[error("stage subjects contain duplicate physical subject {0}")]
    DuplicateSubject(SubjectId),
    #[error("stage subjects contain a duplicate logical path")]
    DuplicateLogicalPath,
    #[error("findings contain duplicate finding {0}")]
    DuplicateFinding(FindingId),
    #[error("finding {0} is not from the initial phase")]
    NonInitialFinding(FindingId),
    #[error("finding {0} has no policy resolution")]
    MissingResolution(FindingId),
    #[error("finding {0} has more than one policy resolution")]
    DuplicateResolution(FindingId),
    #[error("resolution references unknown finding {0}")]
    UnknownFinding(FindingId),
    #[error("actionable finding {finding_id} references unknown artifact {artifact_id}")]
    UnknownArtifact {
        finding_id: FindingId,
        artifact_id: ArtifactId,
    },
    #[error("artifact {artifact_id} is not a mutable physical regular file")]
    UnactionableSubject { artifact_id: ArtifactId },
    #[error("serialized action plan violates canonical or identity invariants")]
    InvalidSerializedPlan,
    #[error("action plan canonical serialization failed")]
    Serialization,
}

/// Build a deterministic whole-file action plan from the complete initial
/// finding set and its total policy resolution.
pub fn build_action_plan(
    initial_manifest_identity: Digest,
    subjects: &[StageSubject],
    findings: &[Finding],
    resolutions: &[FindingResolution],
) -> Result<ActionPlanOutcome, ActionPlanError> {
    let mut subject_by_artifact = BTreeMap::new();
    let mut subject_ids = BTreeSet::new();
    let mut logical_paths = BTreeSet::new();
    for subject in subjects {
        subject.validate()?;
        if subject_by_artifact
            .insert(subject.artifact_id.clone(), subject)
            .is_some()
        {
            return Err(ActionPlanError::DuplicateArtifact(
                subject.artifact_id.clone(),
            ));
        }
        if !subject_ids.insert(subject.subject_id.clone()) {
            return Err(ActionPlanError::DuplicateSubject(
                subject.subject_id.clone(),
            ));
        }
        if !logical_paths.insert(subject.logical_path.clone()) {
            return Err(ActionPlanError::DuplicateLogicalPath);
        }
    }

    let mut finding_by_id = BTreeMap::new();
    for finding in findings {
        if finding.phase != InspectionPhase::Initial {
            return Err(ActionPlanError::NonInitialFinding(finding.id.clone()));
        }
        if finding_by_id.insert(finding.id.clone(), finding).is_some() {
            return Err(ActionPlanError::DuplicateFinding(finding.id.clone()));
        }
    }

    let mut resolution_by_finding = BTreeMap::new();
    for resolution in resolutions {
        if !finding_by_id.contains_key(&resolution.finding_id) {
            return Err(ActionPlanError::UnknownFinding(
                resolution.finding_id.clone(),
            ));
        }
        if resolution_by_finding
            .insert(resolution.finding_id.clone(), resolution)
            .is_some()
        {
            return Err(ActionPlanError::DuplicateResolution(
                resolution.finding_id.clone(),
            ));
        }
    }
    for finding_id in finding_by_id.keys() {
        if !resolution_by_finding.contains_key(finding_id) {
            return Err(ActionPlanError::MissingResolution(finding_id.clone()));
        }
    }

    let deny_ids = resolution_by_finding
        .values()
        .filter(|resolution| {
            resolution.state == ResolutionState::Active
                && resolution.directive == PolicyDirective::Deny
        })
        .map(|resolution| resolution.finding_id.clone())
        .collect::<Vec<_>>();
    if !deny_ids.is_empty() {
        return Ok(ActionPlanOutcome::SuppressedByDeny {
            finding_ids: deny_ids,
        });
    }

    #[derive(Clone)]
    struct Group<'a> {
        subject: &'a StageSubject,
        kind: ActionKind,
        finding_ids: BTreeSet<FindingId>,
        binding_ids: BTreeSet<BindingId>,
    }

    let mut groups = BTreeMap::<SubjectId, Group<'_>>::new();
    for (finding_id, resolution) in resolution_by_finding {
        if resolution.state == ResolutionState::Cleared
            || resolution.directive == PolicyDirective::Audit
        {
            continue;
        }
        let finding = finding_by_id
            .get(&finding_id)
            .expect("resolution set was validated");
        let subject = subject_by_artifact
            .get(&finding.artifact_id)
            .ok_or_else(|| ActionPlanError::UnknownArtifact {
                finding_id: finding_id.clone(),
                artifact_id: finding.artifact_id.clone(),
            })?;
        ActionTarget::from_subject(subject)?;
        let kind = match resolution.directive {
            PolicyDirective::Delete => ActionKind::Delete,
            PolicyDirective::Quarantine => ActionKind::Quarantine,
            PolicyDirective::Audit | PolicyDirective::Deny => unreachable!(),
        };
        let group = groups
            .entry(subject.subject_id.clone())
            .or_insert_with(|| Group {
                subject,
                kind,
                finding_ids: BTreeSet::new(),
                binding_ids: BTreeSet::new(),
            });
        if kind == ActionKind::Quarantine {
            group.kind = ActionKind::Quarantine;
        }
        group.finding_ids.insert(finding_id);
        group.binding_ids.insert(resolution.binding_id.clone());
    }

    if groups.is_empty() {
        return Ok(ActionPlanOutcome::NoActions);
    }

    let mut actions = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        let target = ActionTarget::from_subject(group.subject)?;
        let finding_ids = group.finding_ids.into_iter().collect::<Vec<_>>();
        let binding_ids = group.binding_ids.into_iter().collect::<Vec<_>>();
        let id = action_id(group.kind, &target, &finding_ids, &binding_ids)?;
        let artifact_quarantine_id = if group.kind == ActionKind::Quarantine {
            Some(quarantine_id(&id)?)
        } else {
            None
        };
        actions.push(PlannedAction {
            id,
            kind: group.kind,
            target,
            finding_ids,
            binding_ids,
            artifact_quarantine_id,
        });
    }
    Ok(ActionPlanOutcome::Planned(ActionPlan::new(
        initial_manifest_identity,
        actions,
    )?))
}

#[derive(Serialize)]
struct ActionIdentityInput<'a> {
    schema: &'static str,
    kind: ActionKind,
    target: &'a ActionTarget,
    finding_ids: &'a [FindingId],
    binding_ids: &'a [BindingId],
}

fn action_id(
    kind: ActionKind,
    target: &ActionTarget,
    finding_ids: &[FindingId],
    binding_ids: &[BindingId],
) -> Result<ActionId, ActionPlanError> {
    let bytes = serde_json::to_vec(&ActionIdentityInput {
        schema: "file-guardian-action/1",
        kind,
        target,
        finding_ids,
        binding_ids,
    })
    .map_err(|_| ActionPlanError::Serialization)?;
    ActionId::from_suffix(hex_prefix(Digest::sha256(bytes).as_bytes(), 24))
        .map_err(|_| ActionPlanError::Serialization)
}

fn quarantine_id(action_id: &ActionId) -> Result<ArtifactQuarantineId, ActionPlanError> {
    let digest = Digest::sha256(format!(
        "file-guardian-artifact-quarantine/1\0{}",
        action_id.as_str()
    ));
    ArtifactQuarantineId::from_suffix(hex_prefix(digest.as_bytes(), 24))
        .map_err(|_| ActionPlanError::Serialization)
}

#[derive(Serialize)]
struct PlanIdentityInput<'a> {
    schema: &'static str,
    initial_manifest_identity: Digest,
    actions: &'a [PlannedAction],
}

fn plan_identity(
    initial_manifest_identity: Digest,
    actions: &[PlannedAction],
) -> Result<Digest, ActionPlanError> {
    serde_json::to_vec(&PlanIdentityInput {
        schema: "file-guardian-action-plan/1",
        initial_manifest_identity,
        actions,
    })
    .map(Digest::sha256)
    .map_err(|_| ActionPlanError::Serialization)
}

fn hex_prefix(bytes: &[u8], byte_count: usize) -> String {
    let mut value = String::with_capacity(byte_count * 2);
    for byte in bytes.iter().take(byte_count) {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    value
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
