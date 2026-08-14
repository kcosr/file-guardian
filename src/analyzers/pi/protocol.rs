use crate::domain::{
    AnalyzerId, ArtifactId, Classification, ClassificationCode, ClassificationScope,
    ConfiguredConfidence, Digest, InspectionPhase, NormalizedObservation, ObservationId,
    ReasonCode, RunId,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "file-guardian-pi-proxy/1";
pub const OUTPUT_SCHEMA_VERSION: &str = "file-guardian-pi-classifier/1";

pub const REQUIRED_TOOLS: &[&str] = &[
    "artifact_metadata",
    "artifact_read",
    "artifact_read_range",
    "artifact_search",
    "manifest_list",
    "prior_observations",
    "submit_classification",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyRequest {
    pub protocol: String,
    pub run_token: String,
    pub request_id: u64,
    pub run_id: RunId,
    pub analyzer_id: AnalyzerId,
    pub manifest_identity: Digest,
    #[serde(flatten)]
    pub operation: ProxyOperation,
}

impl<'de> Deserialize<'de> for ProxyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("proxy request must be an object"))?;
        let operation_name = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("proxy request requires a string type"))?;
        let operation_fields: &[&str] = match operation_name {
            "runtime_ready" => &[
                "pi_version",
                "provider",
                "model",
                "thinking",
                "mode",
                "model_in_catalog",
                "active_tools",
            ],
            "instruction" | "manifest_list" | "prior_observations" => &[],
            "artifact_metadata" | "artifact_read" => &["artifact_id"],
            "artifact_read_range" => &["artifact_id", "offset", "length"],
            "artifact_search" => &["artifact_id", "literal", "max_matches"],
            "submit_classification" => &["payload"],
            _ => return Err(serde::de::Error::custom("unknown proxy request type")),
        };
        const COMMON_FIELDS: &[&str] = &[
            "protocol",
            "run_token",
            "request_id",
            "run_id",
            "analyzer_id",
            "manifest_identity",
            "type",
        ];
        if object.keys().any(|field| {
            !COMMON_FIELDS.contains(&field.as_str()) && !operation_fields.contains(&field.as_str())
        }) {
            return Err(serde::de::Error::custom(
                "proxy request contains an unknown field",
            ));
        }

        #[derive(Deserialize)]
        struct Common {
            protocol: String,
            run_token: String,
            request_id: u64,
            run_id: RunId,
            analyzer_id: AnalyzerId,
            manifest_identity: Digest,
        }
        let common: Common = serde_json::from_value(value.clone()).map_err(|error| {
            serde::de::Error::custom(format!("invalid proxy request envelope: {error}"))
        })?;
        let mut operation_object = serde_json::Map::new();
        operation_object.insert(
            "type".into(),
            object.get("type").expect("validated type field").clone(),
        );
        for field in operation_fields {
            if let Some(value) = object.get(*field) {
                operation_object.insert((*field).into(), value.clone());
            }
        }
        let operation = serde_json::from_value(serde_json::Value::Object(operation_object))
            .map_err(|error| {
                serde::de::Error::custom(format!("invalid proxy request operation: {error}"))
            })?;
        Ok(Self {
            protocol: common.protocol,
            run_token: common.run_token,
            request_id: common.request_id,
            run_id: common.run_id,
            analyzer_id: common.analyzer_id,
            manifest_identity: common.manifest_identity,
            operation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyOperation {
    RuntimeReady {
        pi_version: String,
        provider: String,
        model: String,
        thinking: String,
        mode: String,
        model_in_catalog: bool,
        active_tools: Vec<String>,
    },
    Instruction {},
    ManifestList {},
    ArtifactMetadata {
        artifact_id: ArtifactId,
    },
    ArtifactRead {
        artifact_id: ArtifactId,
    },
    ArtifactReadRange {
        artifact_id: ArtifactId,
        offset: u64,
        length: u64,
    },
    ArtifactSearch {
        artifact_id: ArtifactId,
        literal: Base64UrlBytes,
        max_matches: u64,
    },
    PriorObservations {},
    SubmitClassification {
        payload: TerminalSubmission,
    },
}

/// Binary-safe bytes with one canonical, unpadded base64url representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base64UrlBytes(Vec<u8>);

impl Base64UrlBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(serde::de::Error::custom(
                "bytes must use canonical unpadded base64url",
            ));
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyResponse {
    Ok {
        protocol: String,
        request_id: u64,
        result: serde_json::Value,
    },
    Error {
        protocol: String,
        request_id: u64,
        error: ProxyError,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyError {
    pub code: ProxyErrorCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyErrorCode {
    ProtocolViolation,
    Unauthorized,
    InvalidRequest,
    BudgetExceeded,
    TerminalAlreadySubmitted,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSubmission {
    pub schema_version: String,
    pub status: SubmissionStatus,
    pub manifest_identity: Digest,
    pub classification: TreeClassification,
    pub artifact_classifications: Vec<ArtifactClassification>,
    pub coverage: SubmissionCoverage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TreeClassification {
    pub code: ClassificationCode,
    pub confidence: ConfiguredConfidence,
    pub reason_codes: Vec<ReasonCode>,
    pub subject_artifact_ids: Vec<ArtifactId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactClassification {
    pub artifact_id: ArtifactId,
    pub code: ClassificationCode,
    pub confidence: ConfiguredConfidence,
    pub reason_codes: Vec<ReasonCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionCoverage {
    pub assigned_artifact_count: u64,
    pub status: SubmissionStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationVocabulary {
    classifications: BTreeSet<ClassificationCode>,
    confidences: BTreeSet<ConfiguredConfidence>,
    reason_codes: BTreeSet<ReasonCode>,
}

impl ClassificationVocabulary {
    pub fn new(
        classifications: impl IntoIterator<Item = ClassificationCode>,
        confidences: impl IntoIterator<Item = ConfiguredConfidence>,
        reason_codes: impl IntoIterator<Item = ReasonCode>,
    ) -> Result<Self, VocabularyError> {
        let vocabulary = Self {
            classifications: classifications.into_iter().collect(),
            confidences: confidences.into_iter().collect(),
            reason_codes: reason_codes.into_iter().collect(),
        };
        if vocabulary.classifications.is_empty()
            || vocabulary.confidences.is_empty()
            || vocabulary.reason_codes.is_empty()
        {
            return Err(VocabularyError::Empty);
        }
        Ok(vocabulary)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VocabularyError {
    #[error("classification vocabularies must not be empty")]
    Empty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalValidationLimits {
    pub max_subject_artifact_ids: usize,
    pub max_artifact_classifications: usize,
    pub max_reason_codes_per_classification: usize,
}

impl TerminalValidationLimits {
    pub fn new(
        max_subject_artifact_ids: usize,
        max_artifact_classifications: usize,
        max_reason_codes_per_classification: usize,
    ) -> Result<Self, TerminalValidationError> {
        if max_subject_artifact_ids == 0
            || max_artifact_classifications == 0
            || max_reason_codes_per_classification == 0
        {
            return Err(TerminalValidationError::InvalidLimits);
        }
        Ok(Self {
            max_subject_artifact_ids,
            max_artifact_classifications,
            max_reason_codes_per_classification,
        })
    }
}

pub struct TerminalValidationContext<'a> {
    pub manifest_identity: Digest,
    pub assigned_artifact_ids: &'a [ArtifactId],
    pub scope: ClassificationScope,
    pub vocabulary: &'a ClassificationVocabulary,
    pub limits: TerminalValidationLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSubmission {
    observations: Vec<NormalizedObservation>,
}

impl ValidatedSubmission {
    pub fn observations(&self) -> &[NormalizedObservation] {
        &self.observations
    }

    pub fn into_observations(self) -> Vec<NormalizedObservation> {
        self.observations
    }
}

impl TerminalSubmission {
    pub fn validate(
        &self,
        context: &TerminalValidationContext<'_>,
        analyzer_id: &AnalyzerId,
        phase: InspectionPhase,
    ) -> Result<ValidatedSubmission, TerminalValidationError> {
        if self.schema_version != OUTPUT_SCHEMA_VERSION {
            return Err(TerminalValidationError::SchemaVersion);
        }
        if self.manifest_identity != context.manifest_identity {
            return Err(TerminalValidationError::ManifestIdentity);
        }
        if context.scope != ClassificationScope::Tree {
            return Err(TerminalValidationError::UnsupportedScope);
        }

        let assigned: BTreeSet<_> = context.assigned_artifact_ids.iter().cloned().collect();
        if assigned.len() != context.assigned_artifact_ids.len() {
            return Err(TerminalValidationError::HostAssignment);
        }
        let assigned_count =
            u64::try_from(assigned.len()).map_err(|_| TerminalValidationError::AssignedCount)?;
        if self.coverage.assigned_artifact_count != assigned_count {
            return Err(TerminalValidationError::AssignedCount);
        }
        if self.classification.subject_artifact_ids.len() > context.limits.max_subject_artifact_ids
            || self.artifact_classifications.len() > context.limits.max_artifact_classifications
        {
            return Err(TerminalValidationError::ListLimit);
        }

        validate_classification(
            &self.classification.code,
            self.classification.confidence,
            &self.classification.reason_codes,
            context,
        )?;
        validate_canonical_ids(
            &self.classification.subject_artifact_ids,
            &assigned,
            TerminalValidationError::SubjectArtifacts,
        )?;

        if !self
            .artifact_classifications
            .windows(2)
            .all(|pair| pair[0].artifact_id < pair[1].artifact_id)
        {
            return Err(TerminalValidationError::ArtifactClassifications);
        }
        for classification in &self.artifact_classifications {
            if !assigned.contains(&classification.artifact_id) {
                return Err(TerminalValidationError::UnassignedArtifact);
            }
            validate_classification(
                &classification.code,
                classification.confidence,
                &classification.reason_codes,
                context,
            )?;
        }

        let phase_key = match phase {
            InspectionPhase::Initial => "initial",
            InspectionPhase::Verification => "verification",
        };
        let digest = Digest::sha256(analyzer_id.as_str()).to_string();
        let analyzer_key = &digest["sha256:".len().."sha256:".len() + 16];
        let mut observations = Vec::with_capacity(self.artifact_classifications.len() + 1);
        observations.push(NormalizedObservation::Classification(Classification {
            id: generated_observation_id(analyzer_key, phase_key, 1),
            analyzer_id: analyzer_id.clone(),
            code: self.classification.code.clone(),
            scope: ClassificationScope::Tree,
            subject_artifacts: self.classification.subject_artifact_ids.clone(),
            confidence: Some(self.classification.confidence),
            reason_codes: self.classification.reason_codes.clone(),
        }));
        observations.extend(self.artifact_classifications.iter().enumerate().map(
            |(index, classification)| {
                NormalizedObservation::Classification(Classification {
                    id: generated_observation_id(analyzer_key, phase_key, index + 2),
                    analyzer_id: analyzer_id.clone(),
                    code: classification.code.clone(),
                    scope: ClassificationScope::Artifact,
                    subject_artifacts: vec![classification.artifact_id.clone()],
                    confidence: Some(classification.confidence),
                    reason_codes: classification.reason_codes.clone(),
                })
            },
        ));
        Ok(ValidatedSubmission { observations })
    }
}

fn generated_observation_id(analyzer_key: &str, phase_key: &str, index: usize) -> ObservationId {
    ObservationId::from_suffix(format!("pi-{analyzer_key}-{phase_key}-{index:08}"))
        .expect("bounded canonical Pi observation identifier")
}

fn validate_classification(
    code: &ClassificationCode,
    confidence: ConfiguredConfidence,
    reason_codes: &[ReasonCode],
    context: &TerminalValidationContext<'_>,
) -> Result<(), TerminalValidationError> {
    if !context.vocabulary.classifications.contains(code) {
        return Err(TerminalValidationError::ClassificationCode);
    }
    if !context.vocabulary.confidences.contains(&confidence) {
        return Err(TerminalValidationError::Confidence);
    }
    if reason_codes.len() > context.limits.max_reason_codes_per_classification {
        return Err(TerminalValidationError::ListLimit);
    }
    if !reason_codes.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(TerminalValidationError::ReasonCodes);
    }
    if reason_codes
        .iter()
        .any(|reason| !context.vocabulary.reason_codes.contains(reason))
    {
        return Err(TerminalValidationError::ReasonCode);
    }
    Ok(())
}

fn validate_canonical_ids(
    ids: &[ArtifactId],
    assigned: &BTreeSet<ArtifactId>,
    canonical_error: TerminalValidationError,
) -> Result<(), TerminalValidationError> {
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(canonical_error);
    }
    if ids.iter().any(|id| !assigned.contains(id)) {
        return Err(TerminalValidationError::UnassignedArtifact);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TerminalValidationError {
    #[error("terminal validation limits must be greater than zero")]
    InvalidLimits,
    #[error("terminal schema version does not match the configured protocol")]
    SchemaVersion,
    #[error("terminal manifest identity does not match the immutable manifest")]
    ManifestIdentity,
    #[error("only tree-scope Pi classification is supported")]
    UnsupportedScope,
    #[error("host assignment contains duplicate artifact identifiers")]
    HostAssignment,
    #[error("terminal assigned artifact count does not match the host assignment")]
    AssignedCount,
    #[error("terminal output exceeds a configured list limit")]
    ListLimit,
    #[error("classification code is outside the configured vocabulary")]
    ClassificationCode,
    #[error("confidence is outside the configured vocabulary")]
    Confidence,
    #[error("reason code is outside the configured vocabulary")]
    ReasonCode,
    #[error("reason codes must be unique and in canonical order")]
    ReasonCodes,
    #[error("subject artifact identifiers must be unique and in canonical order")]
    SubjectArtifacts,
    #[error("artifact classifications must be unique and in canonical order")]
    ArtifactClassifications,
    #[error("terminal output refers to an unassigned artifact")]
    UnassignedArtifact,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn artifact(suffix: &str) -> ArtifactId {
        ArtifactId::from_suffix(suffix).unwrap()
    }

    fn code(value: &str) -> ClassificationCode {
        ClassificationCode::new(value).unwrap()
    }

    fn reason(value: &str) -> ReasonCode {
        ReasonCode::new(value).unwrap()
    }

    fn vocabulary() -> ClassificationVocabulary {
        ClassificationVocabulary::new(
            [code("public"), code("sensitive"), code("uncertain")],
            [
                ConfiguredConfidence::Low,
                ConfiguredConfidence::Medium,
                ConfiguredConfidence::High,
            ],
            [
                reason("internal_material"),
                reason("no_sensitive_material"),
                reason("review_required"),
            ],
        )
        .unwrap()
    }

    fn limits() -> TerminalValidationLimits {
        TerminalValidationLimits::new(8, 8, 8).unwrap()
    }

    fn manifest_identity() -> Digest {
        Digest::sha256(b"manifest")
    }

    fn valid_json(classification: &str, confidence: &str, reason_code: &str) -> Value {
        json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "status": "complete",
            "manifest_identity": manifest_identity(),
            "classification": {
                "code": classification,
                "confidence": confidence,
                "reason_codes": [reason_code],
                "subject_artifact_ids": ["a_01", "a_07"]
            },
            "artifact_classifications": [{
                "artifact_id": "a_07",
                "code": classification,
                "confidence": confidence,
                "reason_codes": [reason_code]
            }],
            "coverage": {
                "assigned_artifact_count": 2,
                "status": "complete"
            }
        })
    }

    fn parse(value: Value) -> TerminalSubmission {
        serde_json::from_value(value).unwrap()
    }

    fn validate(
        submission: &TerminalSubmission,
    ) -> Result<ValidatedSubmission, TerminalValidationError> {
        let assigned = [artifact("01"), artifact("07")];
        let vocabulary = vocabulary();
        submission.validate(
            &TerminalValidationContext {
                manifest_identity: manifest_identity(),
                assigned_artifact_ids: &assigned,
                scope: ClassificationScope::Tree,
                vocabulary: &vocabulary,
                limits: limits(),
            },
            &AnalyzerId::new("pi-review").unwrap(),
            InspectionPhase::Initial,
        )
    }

    #[test]
    fn valid_public_sensitive_and_uncertain_outputs_normalize_deterministically() {
        for (value, confidence, reason_code) in [
            ("public", "high", "no_sensitive_material"),
            ("sensitive", "high", "internal_material"),
            ("uncertain", "low", "review_required"),
        ] {
            let accepted = validate(&parse(valid_json(value, confidence, reason_code))).unwrap();
            assert_eq!(accepted.observations().len(), 2);
            let NormalizedObservation::Classification(tree) = &accepted.observations()[0] else {
                panic!("expected tree classification")
            };
            assert_eq!(tree.code, code(value));
            assert_eq!(tree.scope, ClassificationScope::Tree);
            assert_eq!(tree.subject_artifacts, [artifact("01"), artifact("07")]);
            assert!(tree.id.as_str().contains("-initial-00000001"));
            let NormalizedObservation::Classification(per_artifact) = &accepted.observations()[1]
            else {
                panic!("expected artifact classification")
            };
            assert_eq!(per_artifact.scope, ClassificationScope::Artifact);
            assert_eq!(per_artifact.subject_artifacts, [artifact("07")]);
            assert!(per_artifact.id.as_str().contains("-initial-00000002"));
        }
    }

    #[test]
    fn strict_deserialization_rejects_unknown_fields_at_every_object_level() {
        for pointer in [
            "",
            "/classification",
            "/artifact_classifications/0",
            "/coverage",
        ] {
            let mut value = valid_json("sensitive", "high", "internal_material");
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("snippet".into(), json!("secret bytes"));
            assert!(serde_json::from_value::<TerminalSubmission>(value).is_err());
        }
    }

    #[test]
    fn schema_manifest_and_coverage_are_host_bound() {
        let mut wrong_schema = valid_json("public", "high", "no_sensitive_material");
        wrong_schema["schema_version"] = json!("file-guardian-pi-classifier/2");
        assert_eq!(
            validate(&parse(wrong_schema)),
            Err(TerminalValidationError::SchemaVersion)
        );

        let mut wrong_manifest = valid_json("public", "high", "no_sensitive_material");
        wrong_manifest["manifest_identity"] = json!(Digest::sha256(b"other"));
        assert_eq!(
            validate(&parse(wrong_manifest)),
            Err(TerminalValidationError::ManifestIdentity)
        );

        let mut wrong_count = valid_json("public", "high", "no_sensitive_material");
        wrong_count["coverage"]["assigned_artifact_count"] = json!(1);
        assert_eq!(
            validate(&parse(wrong_count)),
            Err(TerminalValidationError::AssignedCount)
        );

        let mut incomplete = valid_json("public", "high", "no_sensitive_material");
        incomplete["status"] = json!("incomplete");
        assert!(serde_json::from_value::<TerminalSubmission>(incomplete).is_err());
        let mut incomplete_coverage = valid_json("public", "high", "no_sensitive_material");
        incomplete_coverage["coverage"]["status"] = json!("incomplete");
        assert!(serde_json::from_value::<TerminalSubmission>(incomplete_coverage).is_err());
    }

    #[test]
    fn subject_ids_must_be_assigned_unique_and_canonical() {
        for ids in [json!(["a_07", "a_01"]), json!(["a_01", "a_01"])] {
            let mut value = valid_json("sensitive", "high", "internal_material");
            value["classification"]["subject_artifact_ids"] = ids;
            assert_eq!(
                validate(&parse(value)),
                Err(TerminalValidationError::SubjectArtifacts)
            );
        }
        let mut unassigned = valid_json("sensitive", "high", "internal_material");
        unassigned["classification"]["subject_artifact_ids"] = json!(["a_99"]);
        assert_eq!(
            validate(&parse(unassigned)),
            Err(TerminalValidationError::UnassignedArtifact)
        );
    }

    #[test]
    fn artifact_classifications_must_be_assigned_unique_and_canonical() {
        let mut duplicate = valid_json("sensitive", "high", "internal_material");
        let row = duplicate["artifact_classifications"][0].clone();
        duplicate["artifact_classifications"] = json!([row.clone(), row]);
        assert_eq!(
            validate(&parse(duplicate)),
            Err(TerminalValidationError::ArtifactClassifications)
        );

        let mut unassigned = valid_json("sensitive", "high", "internal_material");
        unassigned["artifact_classifications"][0]["artifact_id"] = json!("a_99");
        assert_eq!(
            validate(&parse(unassigned)),
            Err(TerminalValidationError::UnassignedArtifact)
        );
    }

    #[test]
    fn every_semantic_value_must_be_in_the_closed_vocabulary() {
        let mut unknown_code = valid_json("outside", "high", "internal_material");
        assert_eq!(
            validate(&parse(unknown_code.take())),
            Err(TerminalValidationError::ClassificationCode)
        );
        let mut unknown_confidence = valid_json("sensitive", "high", "internal_material");
        unknown_confidence["classification"]["confidence"] = json!("medium");
        let restricted = ClassificationVocabulary::new(
            [code("sensitive")],
            [ConfiguredConfidence::High],
            [reason("internal_material")],
        )
        .unwrap();
        let assigned = [artifact("01"), artifact("07")];
        assert_eq!(
            parse(unknown_confidence).validate(
                &TerminalValidationContext {
                    manifest_identity: manifest_identity(),
                    assigned_artifact_ids: &assigned,
                    scope: ClassificationScope::Tree,
                    vocabulary: &restricted,
                    limits: limits(),
                },
                &AnalyzerId::new("pi-review").unwrap(),
                InspectionPhase::Initial,
            ),
            Err(TerminalValidationError::Confidence)
        );
        let unknown_reason = valid_json("sensitive", "high", "outside_reason");
        assert_eq!(
            validate(&parse(unknown_reason)),
            Err(TerminalValidationError::ReasonCode)
        );
    }

    #[test]
    fn duplicate_noncanonical_and_oversized_values_are_rejected() {
        for reasons in [
            json!(["review_required", "internal_material"]),
            json!(["internal_material", "internal_material"]),
        ] {
            let mut value = valid_json("sensitive", "high", "internal_material");
            value["classification"]["reason_codes"] = reasons;
            assert_eq!(
                validate(&parse(value)),
                Err(TerminalValidationError::ReasonCodes)
            );
        }

        let mut oversized_list = valid_json("sensitive", "high", "internal_material");
        oversized_list["classification"]["subject_artifact_ids"] = json!(["a_01", "a_07"]);
        let submission = parse(oversized_list);
        let assigned = [artifact("01"), artifact("07")];
        let vocabulary = vocabulary();
        assert_eq!(
            submission.validate(
                &TerminalValidationContext {
                    manifest_identity: manifest_identity(),
                    assigned_artifact_ids: &assigned,
                    scope: ClassificationScope::Tree,
                    vocabulary: &vocabulary,
                    limits: TerminalValidationLimits::new(1, 8, 8).unwrap(),
                },
                &AnalyzerId::new("pi-review").unwrap(),
                InspectionPhase::Initial,
            ),
            Err(TerminalValidationError::ListLimit)
        );

        let mut oversized_string = valid_json("sensitive", "high", "internal_material");
        oversized_string["classification"]["code"] = json!("x".repeat(129));
        assert!(serde_json::from_value::<TerminalSubmission>(oversized_string).is_err());
    }

    #[test]
    fn proxy_envelope_and_binary_literal_are_strict_and_canonical() {
        let bytes = Base64UrlBytes::new(vec![0, 255, 1]);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"AP8B\"");
        assert_eq!(
            serde_json::from_str::<Base64UrlBytes>("\"AP8B\"").unwrap(),
            bytes
        );
        assert!(serde_json::from_str::<Base64UrlBytes>("\"AP8B=\"").is_err());

        let request = json!({
            "protocol": PROTOCOL_VERSION,
            "run_token": "opaque",
            "request_id": 1,
            "run_id": "run_01",
            "analyzer_id": "pi-review",
            "manifest_identity": manifest_identity(),
            "type": "instruction"
        });
        assert!(serde_json::from_value::<ProxyRequest>(request.clone()).is_ok());
        let mut with_unknown = request;
        with_unknown["path"] = json!("/secret");
        assert!(serde_json::from_value::<ProxyRequest>(with_unknown).is_err());
        assert_eq!(REQUIRED_TOOLS.len(), 7);
        assert!(!REQUIRED_TOOLS.contains(&"instruction"));
    }
}
