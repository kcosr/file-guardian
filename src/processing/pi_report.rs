//! Privacy-safe conversion of validated Pi triage runs into report summaries.

use serde::Serialize;
use thiserror::Error;

use crate::analyzers::pi::protocol::PROTOCOL_VERSION;
use crate::analyzers::pi::triage::{
    PiStageAttestation, PiTriageCoverage, TRIAGE_REQUEST_SCHEMA, TRIAGE_TERMINAL_SCHEMA,
};
use crate::domain::{Digest, InspectionPhase as DomainInspectionPhase};
use crate::processing::executor::PiAnalyzerResult;
use crate::processing::report::{
    Attestation, ExecutionStatus, InspectionPhase, PiInvocationSummary, ReportError,
    Rfc3339Timestamp, SafeId, Sha256Digest,
};
use crate::processing::runtime::{
    CompiledProcessingRuntime, FrozenAnalyzer, FrozenAnalyzerImplementation, FrozenPiRuntime,
};

const MODEL_IDENTITY_SCHEMA: &str = "file-guardian-pi-model-identity/1";
const PROTOCOL_IDENTITY_SCHEMA: &str = "file-guardian-pi-protocol-identity/1";
const NORMALIZED_OUTPUT_SCHEMA: &str = "file-guardian-pi-normalized-output/1";

#[derive(Debug, Error)]
pub enum PiReportError {
    #[error("the Pi result does not identify exactly one frozen analyzer")]
    AnalyzerBinding,
    #[error("the Pi result is stale for the compiled processing runtime")]
    RuntimeBinding,
    #[error("the normalized Pi result could not be serialized")]
    Serialization(#[from] serde_json::Error),
    #[error("the converted Pi report value is invalid")]
    Report(#[from] ReportError),
}

/// Converts one complete, validated Pi result into the public report schema.
///
/// The runtime lookup and identity checks prevent a result from being reported
/// against a different analyzer or compiled job. Model names, provider names,
/// credentials, prompts, terminal output, and provider request IDs are not
/// represented in the returned value.
pub fn pi_invocation_summary(
    runtime: &CompiledProcessingRuntime,
    result: &PiAnalyzerResult,
    started_at: Rfc3339Timestamp,
    finished_at: Rfc3339Timestamp,
) -> Result<PiInvocationSummary, PiReportError> {
    let mut matching = runtime
        .pipeline
        .stages
        .iter()
        .flat_map(|stage| &stage.analyzers)
        .filter(|analyzer| analyzer.id == result.analyzer_id);
    let analyzer = matching.next().ok_or(PiReportError::AnalyzerBinding)?;
    if matching.next().is_some() {
        return Err(PiReportError::AnalyzerBinding);
    }
    let FrozenAnalyzerImplementation::Pi(pi_runtime) = &analyzer.implementation else {
        return Err(PiReportError::AnalyzerBinding);
    };
    let request = result.analysis.request();
    if request.run_id != runtime.run_id
        || request.pipeline_identity != runtime.pipeline_identity
        || request.policy_identity != runtime.policy_identity
        || request.prompt_template_identity != pi_runtime.instruction_identity
    {
        return Err(PiReportError::RuntimeBinding);
    }

    summary_from_frozen(analyzer, pi_runtime, result, started_at, finished_at)
}

fn summary_from_frozen(
    analyzer: &FrozenAnalyzer,
    pi_runtime: &FrozenPiRuntime,
    result: &PiAnalyzerResult,
    started_at: Rfc3339Timestamp,
    finished_at: Rfc3339Timestamp,
) -> Result<PiInvocationSummary, PiReportError> {
    if analyzer.id != result.analyzer_id {
        return Err(PiReportError::AnalyzerBinding);
    }
    let request = result.analysis.request();
    let assessments = result
        .analysis
        .result()
        .assessments
        .iter()
        .map(|assessment| NormalizedAssessment {
            finding_id: &assessment.finding_id,
            assessment: &assessment.assessment,
        })
        .collect::<Vec<_>>();
    let normalized = NormalizedOutput {
        schema_version: NORMALIZED_OUTPUT_SCHEMA,
        request_identity: request.request_identity,
        assessments: &assessments,
        stage_attestation: result.analysis.result().stage_attestation,
        coverage: result.analysis.result().coverage,
    };
    let normalized_bytes = serde_json::to_vec(&normalized)?;

    Ok(PiInvocationSummary {
        invocation_id: SafeId::new(request.invocation_id.as_str())?,
        phase: report_phase(request.phase),
        analyzer_id: SafeId::new(analyzer.id.as_str())?,
        model_identity: report_digest(model_identity(pi_runtime)?),
        runtime_identity: report_digest(analyzer.identity),
        prompt_identity: report_digest(pi_runtime.instruction_identity),
        protocol_identity: report_digest(protocol_identity()?),
        status: ExecutionStatus::Complete,
        attestation: Some(report_attestation(
            result.analysis.result().stage_attestation,
        )),
        normalized_output_digest: Some(report_digest(Digest::sha256(normalized_bytes))),
        started_at,
        finished_at,
    })
}

#[derive(Serialize)]
struct NormalizedOutput<'a> {
    schema_version: &'static str,
    request_identity: Digest,
    assessments: &'a [NormalizedAssessment<'a>],
    stage_attestation: PiStageAttestation,
    coverage: PiTriageCoverage,
}

#[derive(Serialize)]
struct NormalizedAssessment<'a> {
    finding_id: &'a crate::processing::FindingId,
    assessment: &'a crate::processing::PiFindingAssessment,
}

fn model_identity(runtime: &FrozenPiRuntime) -> Result<Digest, serde_json::Error> {
    model_identity_from_parts(&runtime.config.pi.provider, &runtime.config.pi.model)
}

fn model_identity_from_parts(provider: &str, model: &str) -> Result<Digest, serde_json::Error> {
    Ok(Digest::sha256(serde_json::to_vec(&(
        MODEL_IDENTITY_SCHEMA,
        provider,
        model,
    ))?))
}

fn protocol_identity() -> Result<Digest, serde_json::Error> {
    Ok(Digest::sha256(serde_json::to_vec(&(
        PROTOCOL_IDENTITY_SCHEMA,
        PROTOCOL_VERSION,
        TRIAGE_REQUEST_SCHEMA,
        TRIAGE_TERMINAL_SCHEMA,
    ))?))
}

fn report_digest(value: Digest) -> Sha256Digest {
    Sha256Digest::new(value.to_string()).expect("Digest has the report's canonical SHA-256 form")
}

const fn report_phase(phase: DomainInspectionPhase) -> InspectionPhase {
    match phase {
        DomainInspectionPhase::Initial => InspectionPhase::Initial,
        DomainInspectionPhase::Verification => InspectionPhase::Verification,
    }
}

const fn report_attestation(attestation: PiStageAttestation) -> Attestation {
    match attestation {
        PiStageAttestation::NoBlockingConcernsObserved => Attestation::NoBlockingConcernsObserved,
        PiStageAttestation::BlockingConcernsObserved => Attestation::BlockingConcernsObserved,
        PiStageAttestation::UnableToAssert => Attestation::UnableToAssert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_identity_is_deterministic_and_domain_separated() {
        assert_eq!(protocol_identity().unwrap(), protocol_identity().unwrap());
        assert_ne!(
            protocol_identity().unwrap(),
            Digest::sha256(PROTOCOL_VERSION.as_bytes())
        );
    }

    #[test]
    fn normalized_output_has_only_closed_safe_fields() {
        let output = NormalizedOutput {
            schema_version: NORMALIZED_OUTPUT_SCHEMA,
            request_identity: Digest::sha256(b"request"),
            assessments: &[],
            stage_attestation: PiStageAttestation::UnableToAssert,
            coverage: PiTriageCoverage {
                assigned_artifact_count: 0,
                completed_artifact_count: 0,
                not_applicable_artifact_count: 0,
                assigned_finding_count: 0,
                assessed_finding_count: 0,
            },
        };
        let bytes = serde_json::to_vec(&output).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            text,
            r#"{"schema_version":"file-guardian-pi-normalized-output/1","request_identity":"sha256:1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047","assessments":[],"stage_attestation":"unable_to_assert","coverage":{"assigned_artifact_count":0,"completed_artifact_count":0,"not_applicable_artifact_count":0,"assigned_finding_count":0,"assessed_finding_count":0}}"#
        );
        for forbidden in [
            "prompt",
            "content",
            "provider_request_id",
            "rationale",
            "snippet",
            "stdout",
            "stderr",
        ] {
            assert!(!text.contains(forbidden), "leaked field name: {forbidden}");
        }
    }

    #[test]
    fn model_identity_is_opaque_and_changes_with_frozen_selection() {
        let provider = "private-provider-name";
        let model = "private-model-name";
        let identity = model_identity_from_parts(provider, model).unwrap();
        let rendered = identity.to_string();
        assert!(!rendered.contains(provider));
        assert!(!rendered.contains(model));
        assert_ne!(
            identity,
            model_identity_from_parts(provider, "different-model").unwrap()
        );
    }

    #[test]
    fn every_attestation_maps_to_the_closed_report_vocabulary() {
        assert_eq!(
            report_attestation(PiStageAttestation::NoBlockingConcernsObserved),
            Attestation::NoBlockingConcernsObserved
        );
        assert_eq!(
            report_attestation(PiStageAttestation::BlockingConcernsObserved),
            Attestation::BlockingConcernsObserved
        );
        assert_eq!(
            report_attestation(PiStageAttestation::UnableToAssert),
            Attestation::UnableToAssert
        );
    }
}
