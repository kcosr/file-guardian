#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use file_guardian::domain::{
    AnalyzerId, ArtifactId, Digest, FileTimestamp, FindingCategory, InspectionPhase, LogicalPath,
    PathSegment, RuleId, Severity, SourceFileType, SourceIdentity, SubjectId,
};
use file_guardian::policy::{BindingId, PolicyDirective};
use file_guardian::processing::actions::{
    build_action_plan, cleanup_committed_actions, execute_actions, read_journal, recover_actions,
    ActionExecutionRequest, ActionFailureKind, ActionFaultInjector, ActionFaultPoint,
    ActionJournalWriter, ActionPlan, ActionPlanOutcome, ActionRecoveryRequest, CleanupFailureKind,
    CommittedCleanupRequest, FindingResolution, JournalEvent, JournalFailureCode, NoActionFaults,
    RecoveredActionTransaction, ResolutionState, RollbackStatus, StageManifestProofError,
    StageManifestProver, StageSubject, VerificationDecision,
};
use file_guardian::processing::{ActionId, ActionKind, Finding, FindingId, OccurrenceId, Outcome};
use sha2::{Digest as _, Sha256};
use tempfile::{tempdir, TempDir};

struct Fixture {
    _root: TempDir,
    source: PathBuf,
    stage: PathBuf,
    trash: PathBuf,
    quarantine: PathBuf,
    journal: PathBuf,
}

impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Self {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let stage = root.path().join("stage");
        let trash = root.path().join("trash");
        let quarantine = root.path().join("quarantine");
        for directory in [&source, &stage, &trash, &quarantine] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, bytes) in files {
            fs::write(source.join(name), bytes).unwrap();
            fs::write(stage.join(name), bytes).unwrap();
        }
        let journal = root.path().join("actions.journal");
        Self {
            _root: root,
            source,
            stage,
            trash,
            quarantine,
            journal,
        }
    }
}

#[derive(Clone, Copy)]
struct ExactManifestProver;

static EXACT_MANIFEST_PROVER: ExactManifestProver = ExactManifestProver;

impl StageManifestProver for ExactManifestProver {
    fn capture_manifest(&self, stage_root: &Path) -> Result<Digest, StageManifestProofError> {
        stage_manifest(stage_root).map_err(|()| StageManifestProofError)
    }
}

fn stage_manifest(root: &Path) -> Result<Digest, ()> {
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<Vec<u8>>) -> Result<(), ()> {
        let mut children = fs::read_dir(directory)
            .map_err(|_| ())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let relative = child_path.strip_prefix(root).map_err(|_| ())?;
            let metadata = fs::symlink_metadata(&child_path).map_err(|_| ())?;
            let mut record = relative.as_os_str().as_encoded_bytes().to_vec();
            record.push(0);
            if metadata.file_type().is_dir() {
                record.push(b'd');
                entries.push(record);
                visit(root, &child_path, entries)?;
            } else if metadata.file_type().is_symlink() {
                record.push(b'l');
                record.extend_from_slice(
                    fs::read_link(&child_path)
                        .map_err(|_| ())?
                        .as_os_str()
                        .as_encoded_bytes(),
                );
                entries.push(record);
            } else if metadata.file_type().is_file() {
                record.push(b'f');
                record.extend_from_slice(&metadata.dev().to_be_bytes());
                record.extend_from_slice(&metadata.ino().to_be_bytes());
                record.extend_from_slice(&metadata.nlink().to_be_bytes());
                record.extend_from_slice(
                    Digest::sha256(fs::read(&child_path).map_err(|_| ())?).as_bytes(),
                );
                entries.push(record);
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    let mut hasher = Sha256::new();
    hasher.update(b"executor-test-manifest/1\0");
    for entry in entries {
        hasher.update((entry.len() as u64).to_be_bytes());
        hasher.update(entry);
    }
    Ok(Digest::from_array(hasher.finalize().into()))
}

fn source_identity(path: &Path) -> SourceIdentity {
    let metadata = fs::metadata(path).unwrap();
    SourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_type: SourceFileType::RegularFile,
        byte_len: metadata.len(),
        link_count: metadata.nlink(),
        modified: FileTimestamp::new(metadata.mtime(), metadata.mtime_nsec() as u32),
        changed: FileTimestamp::new(metadata.ctime(), metadata.ctime_nsec() as u32),
        content_digest: Digest::sha256(fs::read(path).unwrap()),
    }
}

fn logical_path(value: &str) -> LogicalPath {
    LogicalPath::new(vec![PathSegment::utf8(value).unwrap()]).unwrap()
}

fn plan(fixture: &Fixture, actions: &[(&str, &str, ActionKind)]) -> ActionPlan {
    let mut subjects = Vec::new();
    let mut findings = Vec::new();
    let mut resolutions = Vec::new();
    for (suffix, name, kind) in actions {
        let artifact_id = ArtifactId::from_suffix(suffix).unwrap();
        subjects.push(
            StageSubject::mutable_regular_file(
                artifact_id.clone(),
                SubjectId::from_suffix(suffix).unwrap(),
                logical_path(name),
                source_identity(&fixture.stage.join(name)),
            )
            .unwrap(),
        );
        let finding_id = FindingId::from_suffix(suffix).unwrap();
        findings.push(
            Finding::new(
                finding_id.clone(),
                InspectionPhase::Initial,
                AnalyzerId::new("test-analyzer").unwrap(),
                RuleId::new(format!("test/{suffix}")).unwrap(),
                artifact_id,
                FindingCategory::Secret,
                Severity::High,
                None,
                None,
                vec![OccurrenceId::from_suffix(suffix).unwrap()],
            )
            .unwrap(),
        );
        resolutions.push(FindingResolution {
            finding_id,
            binding_id: BindingId::new(format!("binding-{suffix}")).unwrap(),
            directive: match kind {
                ActionKind::Delete => PolicyDirective::Delete,
                ActionKind::Quarantine => PolicyDirective::Quarantine,
            },
            state: ResolutionState::Active,
        });
    }
    match build_action_plan(
        stage_manifest(&fixture.stage).unwrap(),
        &subjects,
        &findings,
        &resolutions,
    )
    .unwrap()
    {
        ActionPlanOutcome::Planned(plan) => plan,
        other => panic!("expected an action plan, got {other:?}"),
    }
}

fn request<'a>(
    fixture: &'a Fixture,
    plan: &'a ActionPlan,
    cancellation: &'a file_guardian::processing::acquisition::local::AcquisitionCancellation,
    faults: &'a dyn ActionFaultInjector,
) -> ActionExecutionRequest<'a> {
    ActionExecutionRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan,
        cancellation,
        manifest_prover: &EXACT_MANIFEST_PROVER,
        faults,
    }
}

fn commit_verified_transaction(journal: &Path, final_manifest: Digest) {
    let mut writer = ActionJournalWriter::open_append(journal).unwrap();
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

struct FaultRule {
    point: ActionFaultPoint,
    action_id: Option<ActionId>,
    inject: bool,
    hook: Option<Box<dyn FnOnce() + Send>>,
}

#[derive(Default)]
struct ScriptedFaults {
    rules: Mutex<Vec<FaultRule>>,
}

impl ScriptedFaults {
    fn new(rules: Vec<FaultRule>) -> Self {
        Self {
            rules: Mutex::new(rules),
        }
    }
}

impl ActionFaultInjector for ScriptedFaults {
    fn fail(&self, point: ActionFaultPoint, action_id: Option<&ActionId>) -> bool {
        let mut rules = self.rules.lock().unwrap();
        let Some(index) = rules.iter().position(|rule| {
            rule.point == point
                && rule.action_id.as_ref().map(ActionId::as_str) == action_id.map(ActionId::as_str)
        }) else {
            return false;
        };
        let rule = rules.remove(index);
        drop(rules);
        if let Some(hook) = rule.hook {
            hook();
        }
        rule.inject
    }
}

fn fault(
    point: ActionFaultPoint,
    action_id: Option<ActionId>,
    inject: bool,
    hook: impl FnOnce() + Send + 'static,
) -> FaultRule {
    FaultRule {
        point,
        action_id,
        inject,
        hook: Some(Box::new(hook)),
    }
}

fn injected(point: ActionFaultPoint, action_id: Option<ActionId>) -> FaultRule {
    FaultRule {
        point,
        action_id,
        inject: true,
        hook: None,
    }
}

#[test]
fn delete_and_quarantine_are_durable_private_moves_then_post_commit_cleanup() {
    let fixture = Fixture::new(&[
        ("delete.txt", b"delete-secret"),
        ("keep.txt", b"keep-secret"),
    ]);
    let plan = plan(
        &fixture,
        &[
            ("delete", "delete.txt", ActionKind::Delete),
            ("keep", "keep.txt", ActionKind::Quarantine),
        ],
    );
    let cancellation = Default::default();

    let applied =
        execute_actions(request(&fixture, &plan, &cancellation, &NoActionFaults)).unwrap();
    assert_eq!(applied.action_ids.len(), 2);
    assert!(!fixture.stage.join("delete.txt").exists());
    assert!(!fixture.stage.join("keep.txt").exists());

    let delete = plan
        .actions
        .iter()
        .find(|action| action.kind == ActionKind::Delete)
        .unwrap();
    let quarantine = plan
        .actions
        .iter()
        .find(|action| action.kind == ActionKind::Quarantine)
        .unwrap();
    assert_eq!(
        fs::read(fixture.trash.join(delete.id.as_str())).unwrap(),
        b"delete-secret"
    );
    let quarantine_id = quarantine.artifact_quarantine_id.as_ref().unwrap();
    assert_eq!(
        fs::read(fixture.quarantine.join(quarantine_id.as_str())).unwrap(),
        b"keep-secret"
    );
    assert!(fixture
        .quarantine
        .join(format!("{}.json", quarantine_id.as_str()))
        .is_file());

    let final_manifest = stage_manifest(&fixture.stage).unwrap();
    commit_verified_transaction(&fixture.journal, final_manifest);
    let cleanup = cleanup_committed_actions(CommittedCleanupRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        faults: &NoActionFaults,
    })
    .unwrap();
    assert_eq!(cleanup.cleaned_action_ids.len(), 2);
    assert!(!fixture.trash.join(delete.id.as_str()).exists());
    assert!(fixture.quarantine.join(quarantine_id.as_str()).is_file());
    assert_eq!(
        fs::read(fixture.source.join("delete.txt")).unwrap(),
        b"delete-secret"
    );
    assert_eq!(
        fs::read(fixture.source.join("keep.txt")).unwrap(),
        b"keep-secret"
    );

    let raw_journal = fs::read(&fixture.journal).unwrap();
    assert!(!raw_journal
        .windows(b"delete-secret".len())
        .any(|value| value == b"delete-secret"));
    assert!(!raw_journal
        .windows(b"keep-secret".len())
        .any(|value| value == b"keep-secret"));
    assert!(!String::from_utf8_lossy(&raw_journal).contains(fixture.source.to_str().unwrap()));
    let parsed = read_journal(&fixture.journal).unwrap();
    assert!(matches!(
        parsed.records.last().map(|record| &record.event),
        Some(JournalEvent::CleanupCompleted { .. })
    ));
}

#[test]
fn every_target_is_preflighted_before_the_first_mutation() {
    let fixture = Fixture::new(&[("a.txt", b"first"), ("b.txt", b"second")]);
    let plan = plan(
        &fixture,
        &[
            ("a", "a.txt", ActionKind::Delete),
            ("b", "b.txt", ActionKind::Delete),
        ],
    );
    fs::remove_file(fixture.stage.join("b.txt")).unwrap();
    std::os::unix::fs::symlink(fixture.source.join("b.txt"), fixture.stage.join("b.txt")).unwrap();

    let failure = execute_actions(request(
        &fixture,
        &plan,
        &Default::default(),
        &NoActionFaults,
    ))
    .unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::PreconditionMismatch);
    assert!(failure.applied_action_ids.is_empty());
    assert!(fixture.stage.join("a.txt").is_file());
    assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
    assert_eq!(fs::read(fixture.source.join("a.txt")).unwrap(), b"first");
    assert_eq!(fs::read(fixture.source.join("b.txt")).unwrap(), b"second");
}

#[test]
fn per_action_revalidation_rejects_symlink_hardlink_and_content_swaps() {
    for attack in ["symlink", "hardlink", "content"] {
        let fixture = Fixture::new(&[("target.txt", b"original"), ("outside.txt", b"outside")]);
        let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
        let stage_target = fixture.stage.join("target.txt");
        let outside = fixture.source.join("outside.txt");
        let hook_target = stage_target.clone();
        let hook_outside = outside.clone();
        let faults = ScriptedFaults::new(vec![fault(
            ActionFaultPoint::AfterPreflight,
            None,
            false,
            move || match attack {
                "symlink" => {
                    fs::remove_file(&hook_target).unwrap();
                    std::os::unix::fs::symlink(&hook_outside, &hook_target).unwrap();
                }
                "hardlink" => {
                    fs::remove_file(&hook_target).unwrap();
                    fs::hard_link(&hook_outside, &hook_target).unwrap();
                }
                "content" => fs::write(&hook_target, b"changed").unwrap(),
                _ => unreachable!(),
            },
        )]);

        let failure =
            execute_actions(request(&fixture, &plan, &Default::default(), &faults)).unwrap_err();
        assert_eq!(
            failure.kind,
            ActionFailureKind::PreconditionMismatch,
            "{attack}"
        );
        assert!(failure.applied_action_ids.is_empty(), "{attack}");
        assert_eq!(failure.rollback, RollbackStatus::Failed, "{attack}");
        assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
        assert_eq!(fs::read(&outside).unwrap(), b"outside", "{attack}");
        assert_eq!(
            fs::read(fixture.source.join("target.txt")).unwrap(),
            b"original",
            "{attack}"
        );
    }
}

#[test]
fn rename_boundary_revalidation_rejects_a_last_moment_exchange() {
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    let target = fixture.stage.join("target.txt");
    let faults = ScriptedFaults::new(vec![fault(
        ActionFaultPoint::BeforeRename,
        Some(plan.actions[0].id.clone()),
        false,
        move || fs::write(target, b"exchanged").unwrap(),
    )]);

    let failure =
        execute_actions(request(&fixture, &plan, &Default::default(), &faults)).unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::PreconditionMismatch);
    assert!(failure.applied_action_ids.is_empty());
    assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
    assert_eq!(
        fs::read(fixture.stage.join("target.txt")).unwrap(),
        b"exchanged"
    );
    assert_eq!(
        fs::read(fixture.source.join("target.txt")).unwrap(),
        b"original"
    );
}

#[test]
fn a_partial_failure_rolls_back_in_reverse_and_proves_the_exact_manifest() {
    let fixture = Fixture::new(&[("a.txt", b"first"), ("b.txt", b"second")]);
    let plan = plan(
        &fixture,
        &[
            ("a", "a.txt", ActionKind::Delete),
            ("b", "b.txt", ActionKind::Delete),
        ],
    );
    let second = plan.actions[1].id.clone();
    let faults = ScriptedFaults::new(vec![injected(ActionFaultPoint::BeforeAction, Some(second))]);

    let failure =
        execute_actions(request(&fixture, &plan, &Default::default(), &faults)).unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::FaultInjected);
    assert_eq!(failure.applied_action_ids, vec![plan.actions[0].id.clone()]);
    assert_eq!(
        failure.rollback,
        RollbackStatus::RestoredProven {
            manifest_identity: plan.initial_manifest_identity
        }
    );
    assert_eq!(fs::read(fixture.stage.join("a.txt")).unwrap(), b"first");
    assert_eq!(fs::read(fixture.stage.join("b.txt")).unwrap(), b"second");
    assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
    assert_eq!(fs::read(fixture.source.join("a.txt")).unwrap(), b"first");
    assert_eq!(fs::read(fixture.source.join("b.txt")).unwrap(), b"second");
}

#[test]
fn rollback_never_overwrites_a_conflicting_stage_entry() {
    let fixture = Fixture::new(&[("a.txt", b"first"), ("b.txt", b"second")]);
    let plan = plan(
        &fixture,
        &[
            ("a", "a.txt", ActionKind::Delete),
            ("b", "b.txt", ActionKind::Delete),
        ],
    );
    let first = plan.actions[0].id.clone();
    let second = plan.actions[1].id.clone();
    let conflict = fixture.stage.join("a.txt");
    let faults = ScriptedFaults::new(vec![
        injected(ActionFaultPoint::BeforeAction, Some(second)),
        fault(
            ActionFaultPoint::BeforeRollbackAction,
            Some(first.clone()),
            false,
            move || fs::write(conflict, b"do-not-overwrite").unwrap(),
        ),
    ]);

    let failure =
        execute_actions(request(&fixture, &plan, &Default::default(), &faults)).unwrap_err();
    assert_eq!(failure.rollback, RollbackStatus::Failed);
    assert_eq!(
        fs::read(fixture.stage.join("a.txt")).unwrap(),
        b"do-not-overwrite"
    );
    assert_eq!(
        fs::read(fixture.trash.join(first.as_str())).unwrap(),
        b"first"
    );
    assert_eq!(fs::read(fixture.source.join("a.txt")).unwrap(), b"first");
}

#[test]
fn cancellation_is_a_proven_non_mutating_failure() {
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    let cancellation =
        file_guardian::processing::acquisition::local::AcquisitionCancellation::default();
    cancellation.cancel();

    let failure =
        execute_actions(request(&fixture, &plan, &cancellation, &NoActionFaults)).unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::Cancelled);
    assert_eq!(
        failure.rollback,
        RollbackStatus::UnchangedProven {
            manifest_identity: plan.initial_manifest_identity
        }
    );
    assert_eq!(
        fs::read(fixture.stage.join("target.txt")).unwrap(),
        b"original"
    );
    assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
}

#[test]
fn cancellation_at_the_rename_boundary_prevents_mutation() {
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    let cancellation =
        file_guardian::processing::acquisition::local::AcquisitionCancellation::default();
    let cancel_from_hook = cancellation.clone();
    let faults = ScriptedFaults::new(vec![fault(
        ActionFaultPoint::BeforeRename,
        Some(plan.actions[0].id.clone()),
        false,
        move || cancel_from_hook.cancel(),
    )]);

    let failure = execute_actions(request(&fixture, &plan, &cancellation, &faults)).unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::Cancelled);
    assert_eq!(
        failure.rollback,
        RollbackStatus::UnchangedProven {
            manifest_identity: plan.initial_manifest_identity
        }
    );
    assert_eq!(
        fs::read(fixture.stage.join("target.txt")).unwrap(),
        b"original"
    );
    assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
}

#[test]
fn recovery_rolls_back_each_durable_move_prefix_and_repairs_an_incomplete_tail() {
    for prefix in ["started", "applied", "fsynced", "incomplete"] {
        let fixture = Fixture::new(&[("target.txt", b"original")]);
        let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
        let action = &plan.actions[0];
        let mut writer = ActionJournalWriter::create(&fixture.journal).unwrap();
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
        fs::rename(
            fixture.stage.join("target.txt"),
            fixture.trash.join(action.id.as_str()),
        )
        .unwrap();
        let moved_identity = source_identity(&fixture.trash.join(action.id.as_str()));
        if matches!(prefix, "applied" | "fsynced") {
            writer
                .append_and_sync(&JournalEvent::ActionApplied {
                    action_id: action.id.clone(),
                    result_identity: moved_identity,
                    artifact_quarantine_id: None,
                })
                .unwrap();
        }
        if prefix == "fsynced" {
            writer
                .append_and_sync(&JournalEvent::ActionFsynced {
                    action_id: action.id.clone(),
                })
                .unwrap();
        }
        if prefix == "incomplete" {
            let complete_len = fs::metadata(&fixture.journal).unwrap().len();
            writer
                .append_and_sync(&JournalEvent::FailureRecorded {
                    action_id: Some(action.id.clone()),
                    code: JournalFailureCode::InternalFailure,
                })
                .unwrap();
            drop(writer);
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&fixture.journal)
                .unwrap();
            file.set_len(complete_len + 6).unwrap();
        } else {
            drop(writer);
        }

        let recovered = recover_actions(ActionRecoveryRequest {
            stage_root: &fixture.stage,
            trash_root: &fixture.trash,
            artifact_quarantine_root: &fixture.quarantine,
            journal_path: &fixture.journal,
            plan: &plan,
            manifest_prover: &EXACT_MANIFEST_PROVER,
            faults: &NoActionFaults,
        })
        .unwrap();
        assert_eq!(
            recovered,
            RecoveredActionTransaction::RolledBackProven {
                action_ids: vec![action.id.clone()],
                manifest_identity: plan.initial_manifest_identity,
            },
            "{prefix}"
        );
        assert_eq!(
            fs::read(fixture.stage.join("target.txt")).unwrap(),
            b"original"
        );
        assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
        assert_eq!(
            fs::read(fixture.source.join("target.txt")).unwrap(),
            b"original"
        );
        assert!(!read_journal(&fixture.journal).unwrap().incomplete_tail);
    }
}

#[test]
fn recovery_never_rolls_back_a_committed_transaction() {
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    execute_actions(request(
        &fixture,
        &plan,
        &Default::default(),
        &NoActionFaults,
    ))
    .unwrap();
    let final_manifest = stage_manifest(&fixture.stage).unwrap();
    commit_verified_transaction(&fixture.journal, final_manifest);

    let recovered = recover_actions(ActionRecoveryRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        manifest_prover: &EXACT_MANIFEST_PROVER,
        faults: &NoActionFaults,
    })
    .unwrap();
    assert_eq!(
        recovered,
        RecoveredActionTransaction::AlreadyCommitted {
            final_manifest_identity: final_manifest
        }
    );
    assert!(!fixture.stage.join("target.txt").exists());
    assert!(fixture.trash.join(plan.actions[0].id.as_str()).is_file());
}

#[test]
fn cleanup_requires_the_matching_committed_plan_and_is_retryable_after_unlink() {
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    execute_actions(request(
        &fixture,
        &plan,
        &Default::default(),
        &NoActionFaults,
    ))
    .unwrap();

    let before_commit = cleanup_committed_actions(CommittedCleanupRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        faults: &NoActionFaults,
    })
    .unwrap_err();
    assert_eq!(
        before_commit.kind,
        CleanupFailureKind::TransactionNotCommitted
    );

    commit_verified_transaction(&fixture.journal, stage_manifest(&fixture.stage).unwrap());
    let other_fixture = Fixture::new(&[("other.txt", b"other")]);
    let other_plan = crate::plan(
        &other_fixture,
        &[("other", "other.txt", ActionKind::Delete)],
    );
    let mismatched = cleanup_committed_actions(CommittedCleanupRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &other_plan,
        faults: &NoActionFaults,
    })
    .unwrap_err();
    assert_eq!(mismatched.kind, CleanupFailureKind::JournalFailed);

    let action = plan.actions[0].id.clone();
    let faults = ScriptedFaults::new(vec![injected(
        ActionFaultPoint::AfterCleanupMutation,
        Some(action.clone()),
    )]);
    let interrupted = cleanup_committed_actions(CommittedCleanupRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        faults: &faults,
    })
    .unwrap_err();
    assert_eq!(interrupted.kind, CleanupFailureKind::FaultInjected);
    assert!(!fixture.trash.join(action.as_str()).exists());

    let retried = cleanup_committed_actions(CommittedCleanupRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &fixture.quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        faults: &NoActionFaults,
    })
    .unwrap();
    assert_eq!(retried.cleaned_action_ids, vec![action]);
}

#[cfg(target_os = "linux")]
#[test]
fn cross_filesystem_roots_are_rejected_before_mutation() {
    let Ok(other_parent) = tempfile::tempdir_in("/dev/shm") else {
        return;
    };
    let fixture = Fixture::new(&[("target.txt", b"original")]);
    if fs::metadata(other_parent.path()).unwrap().dev()
        == fs::metadata(&fixture.stage).unwrap().dev()
    {
        return;
    }
    let other_quarantine = other_parent.path().join("quarantine");
    fs::create_dir(&other_quarantine).unwrap();
    fs::set_permissions(&other_quarantine, fs::Permissions::from_mode(0o700)).unwrap();
    let plan = plan(&fixture, &[("target", "target.txt", ActionKind::Delete)]);
    let cancellation = Default::default();
    let failure = execute_actions(ActionExecutionRequest {
        stage_root: &fixture.stage,
        trash_root: &fixture.trash,
        artifact_quarantine_root: &other_quarantine,
        journal_path: &fixture.journal,
        plan: &plan,
        cancellation: &cancellation,
        manifest_prover: &EXACT_MANIFEST_PROVER,
        faults: &NoActionFaults,
    })
    .unwrap_err();
    assert_eq!(failure.kind, ActionFailureKind::CrossFilesystem);
    assert_eq!(
        failure.rollback,
        RollbackStatus::UnchangedProven {
            manifest_identity: plan.initial_manifest_identity
        }
    );
    assert_eq!(
        fs::read(fixture.stage.join("target.txt")).unwrap(),
        b"original"
    );
    assert_eq!(
        fs::read(fixture.source.join("target.txt")).unwrap(),
        b"original"
    );
    assert!(!fixture.journal.exists());
}
