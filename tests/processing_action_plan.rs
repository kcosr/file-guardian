use std::fs;

use file_guardian::domain::{
    AnalyzerId, ArtifactId, Digest, FindingCategory, InspectionPhase, LogicalPath, PathSegment,
    RuleId, Severity, SourceFileType, SourceIdentity, SubjectId,
};
use file_guardian::policy::{BindingId, PolicyDirective};
use file_guardian::processing::actions::{
    build_action_plan, read_journal, ActionJournalWriter, ActionPlanError, ActionPlanOutcome,
    CleanupKind, FindingResolution, JournalError, JournalEvent, ResolutionState, StageSubject,
    VerificationDecision,
};
use file_guardian::processing::{
    ActionKind, Finding, FindingId, OccurrenceId as ProcessingOccurrenceId, Outcome,
};
use tempfile::tempdir;

fn path(value: &str) -> LogicalPath {
    LogicalPath::new(vec![PathSegment::utf8(value).unwrap()]).unwrap()
}

fn identity(inode: u64, bytes: &[u8]) -> SourceIdentity {
    SourceIdentity {
        device: 7,
        inode,
        file_type: SourceFileType::RegularFile,
        byte_len: bytes.len() as u64,
        link_count: 1,
        modified: None,
        changed: None,
        content_digest: Digest::sha256(bytes),
    }
}

fn subject(suffix: &str, name: &str, bytes: &[u8]) -> StageSubject {
    StageSubject::mutable_regular_file(
        ArtifactId::from_suffix(suffix).unwrap(),
        SubjectId::from_suffix(suffix).unwrap(),
        path(name),
        identity(suffix.as_bytes()[0] as u64, bytes),
    )
    .unwrap()
}

fn finding(suffix: &str, artifact: &ArtifactId) -> Finding {
    Finding::new(
        FindingId::from_suffix(suffix).unwrap(),
        InspectionPhase::Initial,
        AnalyzerId::new("detector").unwrap(),
        RuleId::new(format!("secret/{suffix}")).unwrap(),
        artifact.clone(),
        FindingCategory::Secret,
        Severity::High,
        None,
        None,
        vec![ProcessingOccurrenceId::from_suffix(suffix).unwrap()],
    )
    .unwrap()
}

fn resolution(
    suffix: &str,
    directive: PolicyDirective,
    state: ResolutionState,
) -> FindingResolution {
    FindingResolution {
        finding_id: FindingId::from_suffix(suffix).unwrap(),
        binding_id: BindingId::new(format!("binding-{suffix}")).unwrap(),
        directive,
        state,
    }
}

fn plan_fixture() -> file_guardian::processing::actions::ActionPlan {
    let first = subject("a", "z.txt", b"first");
    let second = subject("b", "a.txt", b"second");
    let findings = vec![
        finding("delete", &first.artifact_id),
        finding("quarantine", &first.artifact_id),
        finding("other", &second.artifact_id),
    ];
    let resolutions = vec![
        resolution("delete", PolicyDirective::Delete, ResolutionState::Active),
        resolution(
            "quarantine",
            PolicyDirective::Quarantine,
            ResolutionState::Active,
        ),
        resolution("other", PolicyDirective::Delete, ResolutionState::Active),
    ];
    match build_action_plan(
        Digest::sha256(b"manifest"),
        &[first, second],
        &findings,
        &resolutions,
    )
    .unwrap()
    {
        ActionPlanOutcome::Planned(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    }
}

#[test]
fn plan_is_canonical_coalesced_and_uses_strongest_action() {
    let plan = plan_fixture();
    assert_eq!(plan.actions.len(), 2);
    assert_eq!(plan.actions[0].target.logical_path.to_string(), "a.txt");
    assert_eq!(plan.actions[1].target.logical_path.to_string(), "z.txt");
    assert_eq!(plan.actions[0].kind, ActionKind::Delete);
    assert_eq!(plan.actions[1].kind, ActionKind::Quarantine);
    assert_eq!(plan.actions[1].finding_ids.len(), 2);
    assert!(plan.actions[1].artifact_quarantine_id.is_some());

    let mut subjects = vec![
        subject("a", "z.txt", b"first"),
        subject("b", "a.txt", b"second"),
    ];
    let mut findings = vec![
        finding("delete", &subjects[0].artifact_id),
        finding("quarantine", &subjects[0].artifact_id),
        finding("other", &subjects[1].artifact_id),
    ];
    let mut resolutions = vec![
        resolution("delete", PolicyDirective::Delete, ResolutionState::Active),
        resolution(
            "quarantine",
            PolicyDirective::Quarantine,
            ResolutionState::Active,
        ),
        resolution("other", PolicyDirective::Delete, ResolutionState::Active),
    ];
    subjects.reverse();
    findings.reverse();
    resolutions.reverse();
    let reversed = match build_action_plan(
        Digest::sha256(b"manifest"),
        &subjects,
        &findings,
        &resolutions,
    )
    .unwrap()
    {
        ActionPlanOutcome::Planned(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    assert_eq!(plan, reversed);
}

#[test]
fn active_deny_suppresses_every_mutation() {
    let target = subject("a", "target.txt", b"secret");
    let findings = vec![
        finding("delete", &target.artifact_id),
        finding("deny", &target.artifact_id),
    ];
    let result = build_action_plan(
        Digest::sha256(b"manifest"),
        &[target],
        &findings,
        &[
            resolution("delete", PolicyDirective::Delete, ResolutionState::Active),
            resolution("deny", PolicyDirective::Deny, ResolutionState::Active),
        ],
    )
    .unwrap();
    assert_eq!(
        result,
        ActionPlanOutcome::SuppressedByDeny {
            finding_ids: vec![FindingId::from_suffix("deny").unwrap()]
        }
    );
}

#[test]
fn planner_rejects_nonphysical_symlink_and_malformed_targets() {
    let nonphysical = StageSubject::nonphysical(
        ArtifactId::from_suffix("history").unwrap(),
        SubjectId::from_suffix("history").unwrap(),
        path("history.txt"),
        6,
        Digest::sha256(b"secret"),
    );
    let history_finding = finding("history", &nonphysical.artifact_id);
    assert!(matches!(
        build_action_plan(
            Digest::sha256(b"manifest"),
            &[nonphysical],
            &[history_finding],
            &[resolution(
                "history",
                PolicyDirective::Delete,
                ResolutionState::Active,
            )],
        ),
        Err(ActionPlanError::UnactionableSubject { .. })
    ));

    let symlink = StageSubject::physical_symlink(
        ArtifactId::from_suffix("link").unwrap(),
        SubjectId::from_suffix("link").unwrap(),
        path("link"),
        6,
        Digest::sha256(b"target"),
    );
    let link_finding = finding("link", &symlink.artifact_id);
    assert!(matches!(
        build_action_plan(
            Digest::sha256(b"manifest"),
            &[symlink],
            &[link_finding],
            &[resolution(
                "link",
                PolicyDirective::Quarantine,
                ResolutionState::Active,
            )],
        ),
        Err(ActionPlanError::UnactionableSubject { .. })
    ));

    let mut malformed = subject("bad", "bad.txt", b"secret");
    malformed.byte_len += 1;
    assert!(matches!(
        build_action_plan(Digest::sha256(b"manifest"), &[malformed], &[], &[]),
        Err(ActionPlanError::InvalidMutableSubject)
    ));
}

#[test]
fn cleared_mutation_is_ignored_and_plan_contains_no_analyzer_path_or_content() {
    let target = subject("safe", "safe.txt", b"password-do-not-report");
    let initial = finding("safe", &target.artifact_id);
    assert_eq!(
        build_action_plan(
            Digest::sha256(b"manifest"),
            std::slice::from_ref(&target),
            std::slice::from_ref(&initial),
            &[resolution(
                "safe",
                PolicyDirective::Delete,
                ResolutionState::Cleared,
            )],
        )
        .unwrap(),
        ActionPlanOutcome::NoActions
    );

    let plan = match build_action_plan(
        Digest::sha256(b"manifest"),
        &[target],
        &[initial],
        &[resolution(
            "safe",
            PolicyDirective::Delete,
            ResolutionState::Active,
        )],
    )
    .unwrap()
    {
        ActionPlanOutcome::Planned(plan) => plan,
        other => panic!("expected plan, got {other:?}"),
    };
    let encoded = serde_json::to_string(&plan).unwrap();
    assert!(!encoded.contains("password-do-not-report"));
    assert!(!encoded.contains("detector"));
    assert!(!encoded.contains("secret/safe"));
    assert!(!encoded.contains("/tmp/"));
    assert!(encoded.contains("safe.txt"));
    assert_eq!(
        serde_json::from_str::<file_guardian::processing::actions::ActionPlan>(&encoded).unwrap(),
        plan
    );
}

#[test]
fn planner_requires_one_resolution_for_every_initial_finding() {
    let target = subject("a", "a.txt", b"a");
    let initial = finding("a", &target.artifact_id);
    assert_eq!(
        build_action_plan(
            Digest::sha256(b"manifest"),
            std::slice::from_ref(&target),
            std::slice::from_ref(&initial),
            &[],
        ),
        Err(ActionPlanError::MissingResolution(initial.id.clone()))
    );
    let one = resolution("a", PolicyDirective::Audit, ResolutionState::Active);
    assert_eq!(
        build_action_plan(
            Digest::sha256(b"manifest"),
            &[target],
            &[initial],
            &[one.clone(), one],
        ),
        Err(ActionPlanError::DuplicateResolution(
            FindingId::from_suffix("a").unwrap()
        ))
    );
}

fn append_committed_transaction(
    writer: &mut ActionJournalWriter,
    plan: &file_guardian::processing::actions::ActionPlan,
) {
    writer
        .append_and_sync(&JournalEvent::PlanPrepared { plan: plan.clone() })
        .unwrap();
    for action in &plan.actions {
        writer
            .append_and_sync(&JournalEvent::PreconditionValidated {
                action_id: action.id.clone(),
                observed_identity: action.target.expected_identity.clone(),
            })
            .unwrap();
        writer
            .append_and_sync(&JournalEvent::ActionStarted {
                action_id: action.id.clone(),
            })
            .unwrap();
        writer
            .append_and_sync(&JournalEvent::ActionApplied {
                action_id: action.id.clone(),
                result_identity: action.target.expected_identity.clone(),
                artifact_quarantine_id: action.artifact_quarantine_id.clone(),
            })
            .unwrap();
        writer
            .append_and_sync(&JournalEvent::ActionFsynced {
                action_id: action.id.clone(),
            })
            .unwrap();
    }
    let final_manifest = Digest::sha256(b"final-manifest");
    writer
        .append_and_sync(&JournalEvent::VerificationStarted {
            manifest_identity: final_manifest,
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::VerificationCompleted {
            manifest_identity: final_manifest,
            decision: VerificationDecision::Allow,
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::DecisionPrepared {
            outcome: Outcome::AllowModified,
            current_manifest_identity: Some(final_manifest),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::TransactionCommitted {
            final_manifest_identity: final_manifest,
        })
        .unwrap();
}

fn append_successful_transaction(
    writer: &mut ActionJournalWriter,
    plan: &file_guardian::processing::actions::ActionPlan,
) {
    append_committed_transaction(writer, plan);
    for action in &plan.actions {
        writer
            .append_and_sync(&JournalEvent::CleanupCompleted {
                action_id: action.id.clone(),
                kind: if action.kind == ActionKind::Delete {
                    CleanupKind::DeleteTrashRemoved
                } else {
                    CleanupKind::ArtifactQuarantineDurable
                },
            })
            .unwrap();
    }
}

#[test]
fn journal_allows_only_retryable_cleanup_state_after_commit() {
    let dir = tempdir().unwrap();
    let journal_path = dir.path().join("cleanup.journal");
    let plan = plan_fixture();
    let first = &plan.actions[0];
    let mut writer = ActionJournalWriter::create(&journal_path).unwrap();
    append_committed_transaction(&mut writer, &plan);

    writer
        .append_and_sync(&JournalEvent::FailureRecorded {
            action_id: Some(first.id.clone()),
            code: file_guardian::processing::actions::JournalFailureCode::CleanupFailed,
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::CleanupCompleted {
            action_id: first.id.clone(),
            kind: if first.kind == ActionKind::Delete {
                CleanupKind::DeleteTrashRemoved
            } else {
                CleanupKind::ArtifactQuarantineDurable
            },
        })
        .unwrap();
    assert!(matches!(
        writer.append_and_sync(&JournalEvent::FailureRecorded {
            action_id: Some(first.id.clone()),
            code: file_guardian::processing::actions::JournalFailureCode::CleanupFailed,
        }),
        Err(JournalError::InvalidTransition)
    ));
    assert!(matches!(
        writer.append_and_sync(&JournalEvent::VerificationStarted {
            manifest_identity: Digest::sha256(b"late-verification"),
        }),
        Err(JournalError::InvalidTransition)
    ));

    let parsed = read_journal(&journal_path).unwrap();
    assert!(matches!(
        parsed.records.last().map(|record| &record.event),
        Some(JournalEvent::CleanupCompleted { action_id, .. }) if action_id == &first.id
    ));
}

#[test]
fn journal_round_trips_a_complete_synced_transaction() {
    let dir = tempdir().unwrap();
    let journal_path = dir.path().join("actions.journal");
    let plan = plan_fixture();
    let mut writer = ActionJournalWriter::create(&journal_path).unwrap();
    append_successful_transaction(&mut writer, &plan);
    writer.sync().unwrap();
    drop(writer);

    let journal = read_journal(&journal_path).unwrap();
    assert!(!journal.incomplete_tail);
    assert!(matches!(
        journal.records.last().map(|record| &record.event),
        Some(JournalEvent::CleanupCompleted { .. })
    ));
    assert_eq!(journal.records[0].sequence, 0);
    assert_eq!(
        journal.records.last().unwrap().sequence as usize + 1,
        journal.records.len()
    );
}

#[test]
fn journal_accepts_only_a_valid_incomplete_tail_and_rejects_corruption() {
    let dir = tempdir().unwrap();
    let first_path = dir.path().join("first.journal");
    let full_path = dir.path().join("full.journal");
    let plan = plan_fixture();
    let action = &plan.actions[0];

    let mut first = ActionJournalWriter::create(&first_path).unwrap();
    first
        .append_and_sync(&JournalEvent::PlanPrepared { plan: plan.clone() })
        .unwrap();
    drop(first);
    let first_bytes = fs::read(&first_path).unwrap();

    let mut full = ActionJournalWriter::create(&full_path).unwrap();
    full.append_and_sync(&JournalEvent::PlanPrepared { plan: plan.clone() })
        .unwrap();
    full.append_and_sync(&JournalEvent::PreconditionValidated {
        action_id: action.id.clone(),
        observed_identity: action.target.expected_identity.clone(),
    })
    .unwrap();
    drop(full);
    let full_bytes = fs::read(&full_path).unwrap();

    for cut in first_bytes.len() + 1..full_bytes.len() {
        fs::write(&full_path, &full_bytes[..cut]).unwrap();
        let parsed = read_journal(&full_path).unwrap();
        assert!(
            parsed.incomplete_tail,
            "cut {cut} should be an incomplete tail"
        );
        assert_eq!(parsed.records.len(), 1);
    }

    let mut invalid_partial_header = full_bytes[..first_bytes.len() + 7].to_vec();
    invalid_partial_header[first_bytes.len() + 4] ^= 1;
    fs::write(&full_path, invalid_partial_header).unwrap();
    assert!(matches!(
        read_journal(&full_path),
        Err(JournalError::InvalidFrameHeader)
    ));

    let mut corrupt_payload = first_bytes.clone();
    // File magic (8) + fixed frame header (52) reaches the JSON payload.
    corrupt_payload[8 + 52 + 5] ^= 1;
    fs::write(&full_path, corrupt_payload).unwrap();
    assert!(matches!(
        read_journal(&full_path),
        Err(JournalError::InvalidChecksum)
    ));

    let mut garbage = first_bytes;
    garbage.extend_from_slice(b"NO");
    fs::write(&full_path, garbage).unwrap();
    assert!(matches!(
        read_journal(&full_path),
        Err(JournalError::InvalidFrameHeader)
    ));
}

#[test]
fn journal_rejects_semantically_impossible_complete_frames() {
    let dir = tempdir().unwrap();
    let journal_path = dir.path().join("invalid.journal");
    let plan = plan_fixture();
    let action_id = plan.actions[0].id.clone();
    let mut writer = ActionJournalWriter::create(&journal_path).unwrap();
    writer
        .append_and_sync(&JournalEvent::PlanPrepared { plan })
        .unwrap();
    assert!(matches!(
        writer.append_and_sync(&JournalEvent::ActionStarted { action_id }),
        Err(JournalError::InvalidTransition)
    ));
    drop(writer);
    let journal = read_journal(&journal_path).unwrap();
    assert_eq!(journal.records.len(), 1);
}

#[test]
fn journal_models_verified_reverse_rollback_and_error_decision() {
    let dir = tempdir().unwrap();
    let journal_path = dir.path().join("rollback.journal");
    let plan = plan_fixture();
    let action = &plan.actions[0];
    let mut writer = ActionJournalWriter::create(&journal_path).unwrap();
    writer
        .append_and_sync(&JournalEvent::PlanPrepared { plan: plan.clone() })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::PreconditionValidated {
            action_id: action.id.clone(),
            observed_identity: action.target.expected_identity.clone(),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::ActionStarted {
            action_id: action.id.clone(),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::ActionApplied {
            action_id: action.id.clone(),
            result_identity: action.target.expected_identity.clone(),
            artifact_quarantine_id: action.artifact_quarantine_id.clone(),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::ActionFsynced {
            action_id: action.id.clone(),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::RollbackStarted)
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::ActionRolledBack {
            action_id: action.id.clone(),
            restored_identity: action.target.expected_identity.clone(),
        })
        .unwrap();
    writer
        .append_and_sync(&JournalEvent::DecisionPrepared {
            outcome: Outcome::Error,
            current_manifest_identity: Some(plan.initial_manifest_identity),
        })
        .unwrap();
    drop(writer);

    let read = read_journal(&journal_path).unwrap();
    assert!(!read.incomplete_tail);
    assert!(matches!(
        read.records.last().map(|record| &record.event),
        Some(JournalEvent::DecisionPrepared {
            outcome: Outcome::Error,
            ..
        })
    ));
}
