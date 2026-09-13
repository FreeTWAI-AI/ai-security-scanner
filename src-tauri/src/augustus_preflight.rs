//! Pure, reject-only Augustus research preflight evaluation.
//!
//! This module validates the frozen pre-contact evidence exchange and selects
//! its first rejection. It has no process, credential, scope-grant, gateway,
//! provider, or network capability. A successful Rust return means only that a
//! well-formed `reject_before_contact` document was produced; it never grants
//! authority to dispatch Augustus or contact a model endpoint.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const AUGUSTUS_PREFLIGHT_SCHEMA_VERSION: &str = "1";
pub const AUGUSTUS_PROFILE_SCHEMA_VERSION: &str = "1";
pub const AUGUSTUS_PROFILE_ID: &str = "augustus-openai-promptinject-v1";
pub const AUGUSTUS_PROFILE_SHA256: &str =
    "9dedd3695cd38575ba4137754803e50114c5a0f868a0f71ce5fd6305377e55b4";
pub const AUGUSTUS_SOURCE_REVISION: &str = "f032fc6373aaa9983868282b31dc9c59503c78a2";
pub const AUGUSTUS_MACHINE_PATCH_SHA256: &str =
    "4f6c1e0d16014ac2a638ec50ebbab053b7a3c6a7320911fbff14b8541f45b59a";
pub const AUGUSTUS_ENFORCEMENT_MATRIX_SHA256: &str =
    "cd212569b48ad8186df0924cf0c86b2cbcac9bb7cb9a1bd71e1faed8a85240df";
pub const AUGUSTUS_REJECTION_VECTORS_SHA256: &str =
    "3376e1757f658acbb13863584e105acc043192997ce3c02e71a73c174bedbab7";
pub const MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES: usize = 64 * 1024;

const RULE_COUNT: usize = 14;
const PROFILE_ADMISSION_RULE_COUNT: usize = 2;
const FROZEN_AUGUSTUS_PROFILE: &[u8] =
    include_bytes!("../../docs/research/augustus-single-destination-profile.json");
const RETAINED_AUGUSTUS_MACHINE_PATCH: &[u8] =
    include_bytes!("../../docs/research/patches/augustus-0.14.29-machine-json.patch");

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AugustusPreflightError {
    #[error("Augustus preflight input exceeds the bounded document size")]
    InputTooLarge,
    #[error("Augustus preflight input is not a valid reject-only document")]
    InvalidDocument,
    #[error("Augustus preflight evaluation identity is invalid")]
    InvalidEvaluationId,
    #[error("Augustus preflight artifact references do not match the frozen contract")]
    ArtifactReferenceMismatch,
    #[error("Augustus preflight rule evidence does not match the frozen order")]
    RuleContractMismatch,
    #[error("Augustus preflight rule evidence state is invalid")]
    InvalidEvidence,
    #[error("Augustus preflight cannot produce an accepted decision")]
    NoRejection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputDocumentKind {
    PreflightInput,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusPreflightNormativeStatus {
    ResearchOnlyNonExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AugustusPreflightInput {
    document_kind: InputDocumentKind,
    schema_version: String,
    normative_status: AugustusPreflightNormativeStatus,
    evaluation_id: String,
    artifact_references: AugustusArtifactReferences,
    rule_evidence: Vec<AugustusRuleEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AugustusArtifactReferences {
    pub profile_id: String,
    pub profile_sha256: String,
    pub enforcement_matrix_sha256: String,
    pub rejection_vectors_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AugustusRuleEvidence {
    pre_contact_order: u8,
    rule_id: AugustusPreflightRuleId,
    state: AugustusEvidenceState,
    rejection_condition_indices: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusEvidenceState {
    Verified,
    Rejected,
    Unverified,
}

impl AugustusRuleEvidence {
    pub fn pre_contact_order(&self) -> u8 {
        self.pre_contact_order
    }

    pub fn rule_id(&self) -> AugustusPreflightRuleId {
        self.rule_id
    }

    pub fn state(&self) -> AugustusEvidenceState {
        self.state
    }

    pub fn rejection_condition_indices(&self) -> &[u8] {
        &self.rejection_condition_indices
    }
}

/// Pure-data evidence derived from the retained Augustus research artifacts.
///
/// This value covers only the first two checks. It does not grant scope, create
/// an egress lease, or authorize execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusProfileAdmissionEvidence {
    calculated_profile_sha256: String,
    calculated_machine_patch_sha256: String,
    source_revision: Option<String>,
    dispatch_blocker_count: Option<usize>,
    rule_evidence: [AugustusRuleEvidence; PROFILE_ADMISSION_RULE_COUNT],
}

impl AugustusProfileAdmissionEvidence {
    pub fn calculated_profile_sha256(&self) -> &str {
        &self.calculated_profile_sha256
    }

    pub fn calculated_machine_patch_sha256(&self) -> &str {
        &self.calculated_machine_patch_sha256
    }

    pub fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }

    pub fn dispatch_blocker_count(&self) -> Option<usize> {
        self.dispatch_blocker_count
    }

    pub fn rule_evidence(&self) -> &[AugustusRuleEvidence; PROFILE_ADMISSION_RULE_COUNT] {
        &self.rule_evidence
    }
}

#[derive(Debug, Deserialize)]
struct AugustusProfileAdmissionFields {
    schema_version: String,
    profile_id: String,
    normative_status: String,
    source_revision: String,
    machine_patch_sha256: String,
    dispatch_blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusPreflightRuleId {
    ProfileIdentityAndProvenance,
    UnresolvedDispatchBlockers,
    ExactDestinationAndModelBinding,
    BaseUrlAndRedirectDenial,
    DeniedCapabilities,
    ProbeDetectorAllowlist,
    AttemptShape,
    PromptCorpusAttestation,
    TokenRequestAndCostBudget,
    SingleConnectionExecution,
    RequestRateRetryAndTimeout,
    ProbeScannerAndProcessDeadlines,
    ProcessResourceSandbox,
    ResponseAndProcessOutputBounds,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusPreflightErrorCode {
    AugustusProfileNotAdmitted,
    AugustusDispatchBlocked,
    AugustusScopeBindingRejected,
    AugustusDestinationPolicyRejected,
    AugustusCapabilityRejected,
    AugustusPlanAllowlistRejected,
    AugustusAttemptShapeRejected,
    AugustusPromptCorpusRejected,
    AugustusCostBudgetRejected,
    AugustusConcurrencyPolicyRejected,
    AugustusRequestPolicyRejected,
    AugustusDeadlinePolicyRejected,
    AugustusSandboxPolicyRejected,
    AugustusOutputBoundRejected,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusPreflightDocumentKind {
    PreflightOutput,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusPreflightDecision {
    RejectBeforeContact,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AugustusFirstRejection {
    pub pre_contact_order: u8,
    pub rule_id: AugustusPreflightRuleId,
    pub error_code: AugustusPreflightErrorCode,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AugustusPreflightOutput {
    document_kind: AugustusPreflightDocumentKind,
    schema_version: String,
    normative_status: AugustusPreflightNormativeStatus,
    evaluation_id: String,
    artifact_references: AugustusArtifactReferences,
    input_sha256: String,
    decision: AugustusPreflightDecision,
    first_rejection: AugustusFirstRejection,
    egress_lease_created: bool,
    target_contact_attempted: bool,
    provider_request_count: u64,
    finding_count: u64,
}

impl AugustusPreflightOutput {
    pub fn evaluation_id(&self) -> &str {
        &self.evaluation_id
    }

    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    pub fn first_rejection(&self) -> &AugustusFirstRejection {
        &self.first_rejection
    }
}

#[derive(Debug, Clone, Copy)]
struct RuleContract {
    order: u8,
    rule_id: AugustusPreflightRuleId,
    error_code: AugustusPreflightErrorCode,
    rejection_condition_count: u8,
}

const RULE_CONTRACTS: [RuleContract; RULE_COUNT] = [
    RuleContract {
        order: 1,
        rule_id: AugustusPreflightRuleId::ProfileIdentityAndProvenance,
        error_code: AugustusPreflightErrorCode::AugustusProfileNotAdmitted,
        rejection_condition_count: 3,
    },
    RuleContract {
        order: 2,
        rule_id: AugustusPreflightRuleId::UnresolvedDispatchBlockers,
        error_code: AugustusPreflightErrorCode::AugustusDispatchBlocked,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 3,
        rule_id: AugustusPreflightRuleId::ExactDestinationAndModelBinding,
        error_code: AugustusPreflightErrorCode::AugustusScopeBindingRejected,
        rejection_condition_count: 4,
    },
    RuleContract {
        order: 4,
        rule_id: AugustusPreflightRuleId::BaseUrlAndRedirectDenial,
        error_code: AugustusPreflightErrorCode::AugustusDestinationPolicyRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 5,
        rule_id: AugustusPreflightRuleId::DeniedCapabilities,
        error_code: AugustusPreflightErrorCode::AugustusCapabilityRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 6,
        rule_id: AugustusPreflightRuleId::ProbeDetectorAllowlist,
        error_code: AugustusPreflightErrorCode::AugustusPlanAllowlistRejected,
        rejection_condition_count: 3,
    },
    RuleContract {
        order: 7,
        rule_id: AugustusPreflightRuleId::AttemptShape,
        error_code: AugustusPreflightErrorCode::AugustusAttemptShapeRejected,
        rejection_condition_count: 3,
    },
    RuleContract {
        order: 8,
        rule_id: AugustusPreflightRuleId::PromptCorpusAttestation,
        error_code: AugustusPreflightErrorCode::AugustusPromptCorpusRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 9,
        rule_id: AugustusPreflightRuleId::TokenRequestAndCostBudget,
        error_code: AugustusPreflightErrorCode::AugustusCostBudgetRejected,
        rejection_condition_count: 4,
    },
    RuleContract {
        order: 10,
        rule_id: AugustusPreflightRuleId::SingleConnectionExecution,
        error_code: AugustusPreflightErrorCode::AugustusConcurrencyPolicyRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 11,
        rule_id: AugustusPreflightRuleId::RequestRateRetryAndTimeout,
        error_code: AugustusPreflightErrorCode::AugustusRequestPolicyRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 12,
        rule_id: AugustusPreflightRuleId::ProbeScannerAndProcessDeadlines,
        error_code: AugustusPreflightErrorCode::AugustusDeadlinePolicyRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 13,
        rule_id: AugustusPreflightRuleId::ProcessResourceSandbox,
        error_code: AugustusPreflightErrorCode::AugustusSandboxPolicyRejected,
        rejection_condition_count: 2,
    },
    RuleContract {
        order: 14,
        rule_id: AugustusPreflightRuleId::ResponseAndProcessOutputBounds,
        error_code: AugustusPreflightErrorCode::AugustusOutputBoundRejected,
        rejection_condition_count: 2,
    },
];

/// Produces the first two preflight evidence rows from retained, frozen data.
///
/// The caller supplies no identity, provenance, status, or blocker claims. The
/// complete profile and retained machine patch are compiled into this module,
/// hashed again here, and compared with their reviewed constants.
pub fn produce_augustus_profile_admission_evidence() -> AugustusProfileAdmissionEvidence {
    produce_profile_admission_evidence(FROZEN_AUGUSTUS_PROFILE, RETAINED_AUGUSTUS_MACHINE_PATCH)
}

fn produce_profile_admission_evidence(
    profile_json: &[u8],
    machine_patch: &[u8],
) -> AugustusProfileAdmissionEvidence {
    let calculated_profile_sha256 = hex::encode(Sha256::digest(profile_json));
    let calculated_machine_patch_sha256 = hex::encode(Sha256::digest(machine_patch));
    let profile = if profile_json.len() <= MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        serde_json::from_slice::<AugustusProfileAdmissionFields>(profile_json).ok()
    } else {
        None
    };

    let profile_identity_matches = calculated_profile_sha256 == AUGUSTUS_PROFILE_SHA256
        && profile.as_ref().is_some_and(|profile| {
            profile.schema_version == AUGUSTUS_PROFILE_SCHEMA_VERSION
                && profile.profile_id == AUGUSTUS_PROFILE_ID
        });
    let provenance_matches = calculated_machine_patch_sha256 == AUGUSTUS_MACHINE_PATCH_SHA256
        && profile.as_ref().is_some_and(|profile| {
            profile.source_revision == AUGUSTUS_SOURCE_REVISION
                && profile.machine_patch_sha256 == AUGUSTUS_MACHINE_PATCH_SHA256
                && profile.machine_patch_sha256 == calculated_machine_patch_sha256
        });

    let mut profile_rejections = Vec::with_capacity(3);
    if !profile_identity_matches {
        profile_rejections.push(0);
    }
    if !provenance_matches {
        profile_rejections.push(1);
    }
    if profile
        .as_ref()
        .is_some_and(|profile| profile.normative_status == "research_only_blocked")
    {
        profile_rejections.push(2);
    }

    let profile_state = if profile_rejections.is_empty() {
        AugustusEvidenceState::Verified
    } else {
        AugustusEvidenceState::Rejected
    };
    let source_revision = if profile_identity_matches {
        profile
            .as_ref()
            .map(|profile| profile.source_revision.clone())
    } else {
        None
    };
    let (blocker_state, blocker_rejections, dispatch_blocker_count) = if profile_identity_matches {
        let blocker_count = profile
            .as_ref()
            .map_or(0, |profile| profile.dispatch_blockers.len());
        if blocker_count == 0 {
            (AugustusEvidenceState::Verified, Vec::new(), Some(0))
        } else {
            (
                AugustusEvidenceState::Rejected,
                vec![0],
                Some(blocker_count),
            )
        }
    } else {
        (AugustusEvidenceState::Unverified, vec![0], None)
    };

    AugustusProfileAdmissionEvidence {
        calculated_profile_sha256,
        calculated_machine_patch_sha256,
        source_revision,
        dispatch_blocker_count,
        rule_evidence: [
            AugustusRuleEvidence {
                pre_contact_order: 1,
                rule_id: AugustusPreflightRuleId::ProfileIdentityAndProvenance,
                state: profile_state,
                rejection_condition_indices: profile_rejections,
            },
            AugustusRuleEvidence {
                pre_contact_order: 2,
                rule_id: AugustusPreflightRuleId::UnresolvedDispatchBlockers,
                state: blocker_state,
                rejection_condition_indices: blocker_rejections,
            },
        ],
    }
}

/// Evaluates a bounded, research-only Augustus preflight input.
///
/// The only successful output is `reject_before_contact`. Invalid input is an
/// error and must never be interpreted as permission to continue.
pub fn evaluate_augustus_research_preflight(
    input_json: &[u8],
) -> Result<AugustusPreflightOutput, AugustusPreflightError> {
    if input_json.len() > MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        return Err(AugustusPreflightError::InputTooLarge);
    }

    let mut input: AugustusPreflightInput =
        serde_json::from_slice(input_json).map_err(|_| AugustusPreflightError::InvalidDocument)?;
    validate_input(&input)?;

    let profile_admission = produce_augustus_profile_admission_evidence();
    input.rule_evidence[..PROFILE_ADMISSION_RULE_COUNT]
        .clone_from_slice(profile_admission.rule_evidence());

    let (evidence, contract) = input
        .rule_evidence
        .iter()
        .zip(RULE_CONTRACTS.iter())
        .find(|(evidence, _)| evidence.state != AugustusEvidenceState::Verified)
        .ok_or(AugustusPreflightError::NoRejection)?;

    debug_assert_eq!(evidence.pre_contact_order, contract.order);
    debug_assert_eq!(evidence.rule_id, contract.rule_id);

    Ok(AugustusPreflightOutput {
        document_kind: AugustusPreflightDocumentKind::PreflightOutput,
        schema_version: AUGUSTUS_PREFLIGHT_SCHEMA_VERSION.to_owned(),
        normative_status: AugustusPreflightNormativeStatus::ResearchOnlyNonExecutable,
        evaluation_id: input.evaluation_id,
        artifact_references: input.artifact_references,
        input_sha256: hex::encode(Sha256::digest(input_json)),
        decision: AugustusPreflightDecision::RejectBeforeContact,
        first_rejection: AugustusFirstRejection {
            pre_contact_order: contract.order,
            rule_id: contract.rule_id,
            error_code: contract.error_code,
        },
        egress_lease_created: false,
        target_contact_attempted: false,
        provider_request_count: 0,
        finding_count: 0,
    })
}

fn validate_input(input: &AugustusPreflightInput) -> Result<(), AugustusPreflightError> {
    if input.schema_version != AUGUSTUS_PREFLIGHT_SCHEMA_VERSION {
        return Err(AugustusPreflightError::InvalidDocument);
    }
    if !valid_evaluation_id(&input.evaluation_id) {
        return Err(AugustusPreflightError::InvalidEvaluationId);
    }
    if !artifact_references_match(&input.artifact_references) {
        return Err(AugustusPreflightError::ArtifactReferenceMismatch);
    }
    if input.rule_evidence.len() != RULE_COUNT {
        return Err(AugustusPreflightError::RuleContractMismatch);
    }

    for (evidence, contract) in input.rule_evidence.iter().zip(RULE_CONTRACTS.iter()) {
        if evidence.pre_contact_order != contract.order || evidence.rule_id != contract.rule_id {
            return Err(AugustusPreflightError::RuleContractMismatch);
        }
        validate_evidence(evidence, contract)?;
    }

    if input
        .rule_evidence
        .iter()
        .all(|evidence| evidence.state == AugustusEvidenceState::Verified)
    {
        return Err(AugustusPreflightError::NoRejection);
    }
    Ok(())
}

fn validate_evidence(
    evidence: &AugustusRuleEvidence,
    contract: &RuleContract,
) -> Result<(), AugustusPreflightError> {
    match evidence.state {
        AugustusEvidenceState::Verified if !evidence.rejection_condition_indices.is_empty() => {
            return Err(AugustusPreflightError::InvalidEvidence);
        }
        AugustusEvidenceState::Rejected | AugustusEvidenceState::Unverified
            if evidence.rejection_condition_indices.is_empty() =>
        {
            return Err(AugustusPreflightError::InvalidEvidence);
        }
        _ => {}
    }

    if evidence.rejection_condition_indices.len() > usize::from(contract.rejection_condition_count)
        || evidence
            .rejection_condition_indices
            .iter()
            .any(|index| *index >= contract.rejection_condition_count)
        || evidence
            .rejection_condition_indices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != evidence.rejection_condition_indices.len()
    {
        return Err(AugustusPreflightError::InvalidEvidence);
    }

    Ok(())
}

fn valid_evaluation_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 128
        && first.is_ascii_alphanumeric()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn artifact_references_match(references: &AugustusArtifactReferences) -> bool {
    references.profile_id == AUGUSTUS_PROFILE_ID
        && references.profile_sha256 == AUGUSTUS_PROFILE_SHA256
        && references.enforcement_matrix_sha256 == AUGUSTUS_ENFORCEMENT_MATRIX_SHA256
        && references.rejection_vectors_sha256 == AUGUSTUS_REJECTION_VECTORS_SHA256
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const VALID_FIXTURE_PAIRS: [(&[u8], &[u8]); RULE_COUNT] = [
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/01-profile-identity.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/01-profile-identity.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/02-dispatch-blockers.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/02-dispatch-blockers.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/03-scope-binding.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/03-scope-binding.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/04-destination-policy.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/04-destination-policy.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/05-denied-capabilities.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/05-denied-capabilities.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/06-plan-allowlist.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/06-plan-allowlist.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/07-attempt-shape.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/07-attempt-shape.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/08-prompt-corpus.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/08-prompt-corpus.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/09-cost-budget.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/09-cost-budget.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/10-concurrency.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/10-concurrency.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/11-request-policy.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/11-request-policy.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/12-deadlines.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/12-deadlines.output.json"
            ),
        ),
        (
            include_bytes!("../../docs/research/fixtures/augustus/preflight/13-sandbox.input.json"),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/13-sandbox.output.json"
            ),
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/14-output-bounds.input.json"
            ),
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight/14-output-bounds.output.json"
            ),
        ),
    ];

    const NEGATIVE_FIXTURES: [(&[u8], AugustusPreflightError); 4] = [
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight-negative/accepted-output.json"
            ),
            AugustusPreflightError::InvalidDocument,
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight-negative/all-verified-input.json"
            ),
            AugustusPreflightError::NoRejection,
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight-negative/mismatched-error-code.json"
            ),
            AugustusPreflightError::InvalidDocument,
        ),
        (
            include_bytes!(
                "../../docs/research/fixtures/augustus/preflight-negative/extra-argv-input.json"
            ),
            AugustusPreflightError::InvalidDocument,
        ),
    ];

    #[test]
    fn frozen_profile_admission_overrides_caller_evidence_in_every_valid_pair() {
        for (index, (input, expected_output)) in VALID_FIXTURE_PAIRS.into_iter().enumerate() {
            let output = evaluate_augustus_research_preflight(input).expect("valid fixture input");
            let expected: Value =
                serde_json::from_slice(expected_output).expect("valid expected output");
            assert_eq!(
                expected["first_rejection"]["pre_contact_order"],
                json!(index + 1),
                "fixture remains a valid isolated rule example"
            );
            assert_eq!(output.first_rejection.pre_contact_order, 1);
            assert_eq!(
                output.first_rejection.rule_id,
                AugustusPreflightRuleId::ProfileIdentityAndProvenance
            );
            assert_eq!(
                output.first_rejection.error_code,
                AugustusPreflightErrorCode::AugustusProfileNotAdmitted
            );
            assert_eq!(output.input_sha256(), hex::encode(Sha256::digest(input)));

            if index == 0 {
                assert_eq!(
                    serde_json::to_value(output).expect("serializable output"),
                    expected
                );
            }
        }
    }

    #[test]
    fn current_profile_admission_evidence_is_derived_from_retained_bytes() {
        let evidence = produce_augustus_profile_admission_evidence();

        assert_eq!(
            evidence.calculated_profile_sha256(),
            AUGUSTUS_PROFILE_SHA256
        );
        assert_eq!(
            evidence.calculated_machine_patch_sha256(),
            AUGUSTUS_MACHINE_PATCH_SHA256
        );
        assert_eq!(evidence.source_revision(), Some(AUGUSTUS_SOURCE_REVISION));
        assert_eq!(evidence.dispatch_blocker_count(), Some(5));
        assert_eq!(
            evidence.rule_evidence(),
            &[
                AugustusRuleEvidence {
                    pre_contact_order: 1,
                    rule_id: AugustusPreflightRuleId::ProfileIdentityAndProvenance,
                    state: AugustusEvidenceState::Rejected,
                    rejection_condition_indices: vec![2],
                },
                AugustusRuleEvidence {
                    pre_contact_order: 2,
                    rule_id: AugustusPreflightRuleId::UnresolvedDispatchBlockers,
                    state: AugustusEvidenceState::Rejected,
                    rejection_condition_indices: vec![0],
                },
            ]
        );
    }

    #[test]
    fn profile_identity_drift_makes_the_blocker_ledger_unverified() {
        let mut profile: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        profile["unreviewed_field"] = json!(true);
        let drifted_profile = serde_json::to_vec(&profile).expect("serializable drifted profile");

        let evidence =
            produce_profile_admission_evidence(&drifted_profile, RETAINED_AUGUSTUS_MACHINE_PATCH);

        assert_eq!(
            evidence.rule_evidence()[0].rejection_condition_indices(),
            &[0, 2]
        );
        assert_eq!(
            evidence.rule_evidence()[1].state(),
            AugustusEvidenceState::Unverified
        );
        assert_eq!(
            evidence.rule_evidence()[1].rejection_condition_indices(),
            &[0]
        );
        assert_eq!(evidence.source_revision(), None);
        assert_eq!(evidence.dispatch_blocker_count(), None);
    }

    #[test]
    fn retained_patch_drift_is_a_provenance_rejection() {
        let mut drifted_patch = RETAINED_AUGUSTUS_MACHINE_PATCH.to_vec();
        drifted_patch.push(b'\n');

        let evidence = produce_profile_admission_evidence(FROZEN_AUGUSTUS_PROFILE, &drifted_patch);

        assert_eq!(
            evidence.rule_evidence()[0].rejection_condition_indices(),
            &[1, 2]
        );
        assert_eq!(
            evidence.rule_evidence()[1].state(),
            AugustusEvidenceState::Rejected
        );
        assert_eq!(evidence.dispatch_blocker_count(), Some(5));
    }

    #[test]
    fn schema_negative_fixtures_never_produce_an_output() {
        for (fixture, expected_error) in NEGATIVE_FIXTURES {
            assert_eq!(
                evaluate_augustus_research_preflight(fixture),
                Err(expected_error)
            );
        }
    }

    #[test]
    fn lowest_non_verified_rule_wins_even_when_later_rules_also_fail() {
        let mut input: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[13].0).expect("valid input fixture");
        input["rule_evidence"][0]["state"] = json!("unverified");
        input["rule_evidence"][0]["rejection_condition_indices"] = json!([0]);
        let encoded = serde_json::to_vec(&input).expect("serializable test input");

        let output =
            evaluate_augustus_research_preflight(&encoded).expect("valid multi-rejection input");
        assert_eq!(output.first_rejection.pre_contact_order, 1);
        assert_eq!(
            output.first_rejection.rule_id,
            AugustusPreflightRuleId::ProfileIdentityAndProvenance
        );
        assert_eq!(
            output.first_rejection.error_code,
            AugustusPreflightErrorCode::AugustusProfileNotAdmitted
        );
    }

    #[test]
    fn evidence_indices_are_bounded_and_unique() {
        let mut out_of_range: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[0].0).expect("valid input fixture");
        out_of_range["rule_evidence"][0]["rejection_condition_indices"] = json!([3]);
        assert_eq!(
            evaluate_augustus_research_preflight(
                &serde_json::to_vec(&out_of_range).expect("serializable test input")
            ),
            Err(AugustusPreflightError::InvalidEvidence)
        );

        let mut duplicate: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[0].0).expect("valid input fixture");
        duplicate["rule_evidence"][0]["rejection_condition_indices"] = json!([0, 0]);
        assert_eq!(
            evaluate_augustus_research_preflight(
                &serde_json::to_vec(&duplicate).expect("serializable test input")
            ),
            Err(AugustusPreflightError::InvalidEvidence)
        );
    }

    #[test]
    fn identity_artifact_and_rule_order_drift_fail_closed() {
        let mut invalid_identity: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[0].0).expect("valid input fixture");
        invalid_identity["evaluation_id"] = json!("invalid/id");
        assert_eq!(
            evaluate_augustus_research_preflight(
                &serde_json::to_vec(&invalid_identity).expect("serializable test input")
            ),
            Err(AugustusPreflightError::InvalidEvaluationId)
        );

        let mut drifted_artifact: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[0].0).expect("valid input fixture");
        drifted_artifact["artifact_references"]["profile_sha256"] = json!("0".repeat(64));
        assert_eq!(
            evaluate_augustus_research_preflight(
                &serde_json::to_vec(&drifted_artifact).expect("serializable test input")
            ),
            Err(AugustusPreflightError::ArtifactReferenceMismatch)
        );

        let mut reordered: Value =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[0].0).expect("valid input fixture");
        reordered["rule_evidence"]
            .as_array_mut()
            .expect("rule evidence array")
            .swap(0, 1);
        assert_eq!(
            evaluate_augustus_research_preflight(
                &serde_json::to_vec(&reordered).expect("serializable test input")
            ),
            Err(AugustusPreflightError::RuleContractMismatch)
        );
    }

    #[test]
    fn unbounded_or_malformed_documents_fail_closed() {
        assert_eq!(
            evaluate_augustus_research_preflight(&vec![
                b' ';
                MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES + 1
            ]),
            Err(AugustusPreflightError::InputTooLarge)
        );
        assert_eq!(
            evaluate_augustus_research_preflight(br#"{"document_kind":"preflight_input"}"#),
            Err(AugustusPreflightError::InvalidDocument)
        );
    }
}
