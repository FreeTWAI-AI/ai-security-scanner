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

use crate::augustus_terminal::{
    AUGUSTUS_FROZEN_DETECTOR, AUGUSTUS_FROZEN_EXPECTED_ATTEMPTS, AUGUSTUS_FROZEN_PROBE,
};

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
const AUGUSTUS_FROZEN_GENERATOR: &str = "openai.OpenAI";
const AUGUSTUS_FROZEN_SCHEME: &str = "https";
const AUGUSTUS_FROZEN_HOST: &str = "api.openai.com";
const AUGUSTUS_FROZEN_PORT: u16 = 443;
const AUGUSTUS_FROZEN_API_BASE_PATH: &str = "/v1";

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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusModelBindingRequirement {
    ExactScopeGrant,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileDestinationFields {
    generator: String,
    scheme: String,
    host: String,
    port: u16,
    api_base_path: String,
    model_binding: AugustusModelBindingRequirement,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileScopeFields {
    schema_version: String,
    profile_id: String,
    destination: AugustusProfileDestinationFields,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileDestinationPolicyFields {
    custom_base_url_allowed: bool,
    redirects_allowed: bool,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileDestinationPolicyDocument {
    schema_version: String,
    profile_id: String,
    destination: AugustusProfileDestinationPolicyFields,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileDeniedCapabilitiesDocument {
    schema_version: String,
    profile_id: String,
    denied_capabilities: Vec<AugustusDeniedCapability>,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileDetectorConfigFields {
    case_sensitive: bool,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileAllowlistEntryFields {
    probe: String,
    detectors: Vec<String>,
    detector_config: AugustusProfileDetectorConfigFields,
    expected_attempts: u32,
}

#[derive(Debug, Deserialize)]
struct AugustusProfileAllowlistDocument {
    schema_version: String,
    profile_id: String,
    allowlist: Vec<AugustusProfileAllowlistEntryFields>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusFrozenDestination {
    generator: String,
    scheme: String,
    host: String,
    port: u16,
    api_base_path: String,
    model_binding: AugustusModelBindingRequirement,
}

impl AugustusFrozenDestination {
    pub fn generator(&self) -> &str {
        &self.generator
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn api_base_path(&self) -> &str {
        &self.api_base_path
    }

    pub fn model_binding(&self) -> AugustusModelBindingRequirement {
        self.model_binding
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugustusScopeGrantState {
    Absent,
}

/// Pure-data Rule 3 evidence for the frozen endpoint and model binding.
///
/// There is deliberately no caller-supplied grant or model input. Until a
/// separately reviewed product scope-grant path exists, both remain absent and
/// this evidence rejects before contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusScopeBindingEvidence {
    frozen_destination: Option<AugustusFrozenDestination>,
    scope_grant_state: AugustusScopeGrantState,
    bound_model: Option<String>,
    rule_evidence: AugustusRuleEvidence,
}

impl AugustusScopeBindingEvidence {
    pub fn frozen_destination(&self) -> Option<&AugustusFrozenDestination> {
        self.frozen_destination.as_ref()
    }

    pub fn scope_grant_state(&self) -> AugustusScopeGrantState {
        self.scope_grant_state
    }

    pub fn bound_model(&self) -> Option<&str> {
        self.bound_model.as_deref()
    }

    pub fn rule_evidence(&self) -> &AugustusRuleEvidence {
        &self.rule_evidence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AugustusFrozenDestinationPolicy {
    custom_base_url_allowed: bool,
    redirects_allowed: bool,
}

impl AugustusFrozenDestinationPolicy {
    pub fn custom_base_url_allowed(&self) -> bool {
        self.custom_base_url_allowed
    }

    pub fn redirects_allowed(&self) -> bool {
        self.redirects_allowed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugustusDestinationPolicyEnforcementState {
    Absent,
}

/// Pure-data Rule 4 evidence for base-URL and redirect denial.
///
/// Frozen policy intent is not treated as enforcement. Until separately
/// reviewed launcher and HTTP-gate controls exist, both enforcement points
/// remain absent and this rule stays unverified before contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusDestinationPolicyEvidence {
    frozen_policy: Option<AugustusFrozenDestinationPolicy>,
    base_url_enforcement_state: AugustusDestinationPolicyEnforcementState,
    redirect_enforcement_state: AugustusDestinationPolicyEnforcementState,
    rule_evidence: AugustusRuleEvidence,
}

impl AugustusDestinationPolicyEvidence {
    pub fn frozen_policy(&self) -> Option<AugustusFrozenDestinationPolicy> {
        self.frozen_policy
    }

    pub fn base_url_enforcement_state(&self) -> AugustusDestinationPolicyEnforcementState {
        self.base_url_enforcement_state
    }

    pub fn redirect_enforcement_state(&self) -> AugustusDestinationPolicyEnforcementState {
        self.redirect_enforcement_state
    }

    pub fn rule_evidence(&self) -> &AugustusRuleEvidence {
        &self.rule_evidence
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AugustusDeniedCapability {
    AllOtherGenerators,
    AllOtherProbes,
    AllOtherDetectors,
    CustomBaseUrl,
    Redirects,
    Reconnaissance,
    Buffs,
    RuntimeHooks,
    Tools,
    MultiTurn,
    AttackerOrJudgeModels,
    DetectorNetworkAccess,
    ConfigurationFiles,
    InlineConfiguration,
    Wildcards,
    Retries,
}

const AUGUSTUS_FROZEN_DENIED_CAPABILITIES: [AugustusDeniedCapability; 16] = [
    AugustusDeniedCapability::AllOtherGenerators,
    AugustusDeniedCapability::AllOtherProbes,
    AugustusDeniedCapability::AllOtherDetectors,
    AugustusDeniedCapability::CustomBaseUrl,
    AugustusDeniedCapability::Redirects,
    AugustusDeniedCapability::Reconnaissance,
    AugustusDeniedCapability::Buffs,
    AugustusDeniedCapability::RuntimeHooks,
    AugustusDeniedCapability::Tools,
    AugustusDeniedCapability::MultiTurn,
    AugustusDeniedCapability::AttackerOrJudgeModels,
    AugustusDeniedCapability::DetectorNetworkAccess,
    AugustusDeniedCapability::ConfigurationFiles,
    AugustusDeniedCapability::InlineConfiguration,
    AugustusDeniedCapability::Wildcards,
    AugustusDeniedCapability::Retries,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugustusCapabilityEnforcementState {
    Absent,
}

/// Pure-data Rule 5 evidence for the frozen denied-capability ledger.
///
/// The list is retained only when the complete profile and exact ordered enum
/// set remain frozen. With no admitted launcher controls or destination gate,
/// the deny list is policy intent rather than enforced execution behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusDeniedCapabilitiesEvidence {
    frozen_denied_capabilities: Option<Vec<AugustusDeniedCapability>>,
    launcher_enforcement_state: AugustusCapabilityEnforcementState,
    destination_gate_enforcement_state: AugustusCapabilityEnforcementState,
    rule_evidence: AugustusRuleEvidence,
}

impl AugustusDeniedCapabilitiesEvidence {
    pub fn frozen_denied_capabilities(&self) -> Option<&[AugustusDeniedCapability]> {
        self.frozen_denied_capabilities.as_deref()
    }

    pub fn launcher_enforcement_state(&self) -> AugustusCapabilityEnforcementState {
        self.launcher_enforcement_state
    }

    pub fn destination_gate_enforcement_state(&self) -> AugustusCapabilityEnforcementState {
        self.destination_gate_enforcement_state
    }

    pub fn rule_evidence(&self) -> &AugustusRuleEvidence {
        &self.rule_evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusFrozenPlanAllowlistEntry {
    probe: String,
    detectors: Vec<String>,
    detector_case_sensitive: bool,
    expected_attempts: u32,
}

impl AugustusFrozenPlanAllowlistEntry {
    pub fn probe(&self) -> &str {
        &self.probe
    }

    pub fn detectors(&self) -> &[String] {
        &self.detectors
    }

    pub fn detector_case_sensitive(&self) -> bool {
        self.detector_case_sensitive
    }

    pub fn expected_attempts(&self) -> u32 {
        self.expected_attempts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AugustusPlanEnforcementState {
    Absent,
}

/// Pure-data Rule 6 evidence for the frozen probe and detector allowlist.
///
/// The expected-attempt count is retained as metadata for the separately owned
/// Rule 7 check. With no launcher-built machine plan, Rule 6 rejects before
/// contact rather than treating profile intent as an observed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugustusPlanAllowlistEvidence {
    frozen_allowlist: Option<Vec<AugustusFrozenPlanAllowlistEntry>>,
    argument_builder_state: AugustusPlanEnforcementState,
    plan_verifier_state: AugustusPlanEnforcementState,
    machine_plan_state: AugustusPlanEnforcementState,
    rule_evidence: AugustusRuleEvidence,
}

impl AugustusPlanAllowlistEvidence {
    pub fn frozen_allowlist(&self) -> Option<&[AugustusFrozenPlanAllowlistEntry]> {
        self.frozen_allowlist.as_deref()
    }

    pub fn argument_builder_state(&self) -> AugustusPlanEnforcementState {
        self.argument_builder_state
    }

    pub fn plan_verifier_state(&self) -> AugustusPlanEnforcementState {
        self.plan_verifier_state
    }

    pub fn machine_plan_state(&self) -> AugustusPlanEnforcementState {
        self.machine_plan_state
    }

    pub fn rule_evidence(&self) -> &AugustusRuleEvidence {
        &self.rule_evidence
    }
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

/// Produces Rule 3 evidence without accepting a caller-provided grant claim.
///
/// The frozen destination is returned only when the complete embedded profile
/// still matches its reviewed hash and exact endpoint fields. The current
/// product has no admitted Augustus model-endpoint scope grant, so the bound
/// model is absent and the rule always rejects before contact.
pub fn produce_augustus_scope_binding_evidence() -> AugustusScopeBindingEvidence {
    produce_scope_binding_evidence(FROZEN_AUGUSTUS_PROFILE)
}

fn produce_scope_binding_evidence(profile_json: &[u8]) -> AugustusScopeBindingEvidence {
    let calculated_profile_sha256 = hex::encode(Sha256::digest(profile_json));
    let profile = if profile_json.len() <= MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        serde_json::from_slice::<AugustusProfileScopeFields>(profile_json).ok()
    } else {
        None
    };
    let destination_matches = profile
        .as_ref()
        .is_some_and(|profile| destination_matches_frozen_profile(&profile.destination));
    let profile_is_trusted = calculated_profile_sha256 == AUGUSTUS_PROFILE_SHA256
        && profile.as_ref().is_some_and(|profile| {
            profile.schema_version == AUGUSTUS_PROFILE_SCHEMA_VERSION
                && profile.profile_id == AUGUSTUS_PROFILE_ID
        });
    let frozen_destination = if profile_is_trusted && destination_matches {
        profile
            .as_ref()
            .map(|profile| frozen_destination(&profile.destination))
    } else {
        None
    };

    let mut rejection_condition_indices = vec![0];
    if !destination_matches {
        rejection_condition_indices.push(1);
    }

    AugustusScopeBindingEvidence {
        frozen_destination,
        scope_grant_state: AugustusScopeGrantState::Absent,
        bound_model: None,
        rule_evidence: AugustusRuleEvidence {
            pre_contact_order: 3,
            rule_id: AugustusPreflightRuleId::ExactDestinationAndModelBinding,
            state: AugustusEvidenceState::Rejected,
            rejection_condition_indices,
        },
    }
}

fn destination_matches_frozen_profile(destination: &AugustusProfileDestinationFields) -> bool {
    destination.generator == AUGUSTUS_FROZEN_GENERATOR
        && destination.scheme == AUGUSTUS_FROZEN_SCHEME
        && destination.host == AUGUSTUS_FROZEN_HOST
        && destination.port == AUGUSTUS_FROZEN_PORT
        && destination.api_base_path == AUGUSTUS_FROZEN_API_BASE_PATH
        && destination.model_binding == AugustusModelBindingRequirement::ExactScopeGrant
}

fn frozen_destination(destination: &AugustusProfileDestinationFields) -> AugustusFrozenDestination {
    AugustusFrozenDestination {
        generator: destination.generator.clone(),
        scheme: destination.scheme.clone(),
        host: destination.host.clone(),
        port: destination.port,
        api_base_path: destination.api_base_path.clone(),
        model_binding: destination.model_binding,
    }
}

/// Produces Rule 4 evidence without accepting caller policy or configuration.
///
/// The embedded profile permits neither a custom base URL nor redirects, but
/// those declarations are not execution controls. With no admitted launcher or
/// HTTP gate, both enforcement points remain absent and fail closed.
pub fn produce_augustus_destination_policy_evidence() -> AugustusDestinationPolicyEvidence {
    produce_destination_policy_evidence(FROZEN_AUGUSTUS_PROFILE)
}

fn produce_destination_policy_evidence(profile_json: &[u8]) -> AugustusDestinationPolicyEvidence {
    let calculated_profile_sha256 = hex::encode(Sha256::digest(profile_json));
    let profile = if profile_json.len() <= MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        serde_json::from_slice::<AugustusProfileDestinationPolicyDocument>(profile_json).ok()
    } else {
        None
    };
    let frozen_policy = profile.and_then(|profile| {
        if calculated_profile_sha256 == AUGUSTUS_PROFILE_SHA256
            && profile.schema_version == AUGUSTUS_PROFILE_SCHEMA_VERSION
            && profile.profile_id == AUGUSTUS_PROFILE_ID
            && !profile.destination.custom_base_url_allowed
            && !profile.destination.redirects_allowed
        {
            Some(AugustusFrozenDestinationPolicy {
                custom_base_url_allowed: profile.destination.custom_base_url_allowed,
                redirects_allowed: profile.destination.redirects_allowed,
            })
        } else {
            None
        }
    });

    AugustusDestinationPolicyEvidence {
        frozen_policy,
        base_url_enforcement_state: AugustusDestinationPolicyEnforcementState::Absent,
        redirect_enforcement_state: AugustusDestinationPolicyEnforcementState::Absent,
        rule_evidence: AugustusRuleEvidence {
            pre_contact_order: 4,
            rule_id: AugustusPreflightRuleId::BaseUrlAndRedirectDenial,
            state: AugustusEvidenceState::Unverified,
            rejection_condition_indices: vec![0, 1],
        },
    }
}

/// Produces Rule 5 evidence without accepting caller capability claims.
///
/// The exact ordered deny list is read from the embedded profile. Because no
/// admitted launcher or destination-gate enforcement exists, the list cannot
/// be treated as proof that those capabilities are inert.
pub fn produce_augustus_denied_capabilities_evidence() -> AugustusDeniedCapabilitiesEvidence {
    produce_denied_capabilities_evidence(FROZEN_AUGUSTUS_PROFILE)
}

fn produce_denied_capabilities_evidence(profile_json: &[u8]) -> AugustusDeniedCapabilitiesEvidence {
    let calculated_profile_sha256 = hex::encode(Sha256::digest(profile_json));
    let profile = if profile_json.len() <= MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        serde_json::from_slice::<AugustusProfileDeniedCapabilitiesDocument>(profile_json).ok()
    } else {
        None
    };
    let frozen_denied_capabilities = profile.and_then(|profile| {
        if calculated_profile_sha256 == AUGUSTUS_PROFILE_SHA256
            && profile.schema_version == AUGUSTUS_PROFILE_SCHEMA_VERSION
            && profile.profile_id == AUGUSTUS_PROFILE_ID
            && profile.denied_capabilities == AUGUSTUS_FROZEN_DENIED_CAPABILITIES
        {
            Some(profile.denied_capabilities)
        } else {
            None
        }
    });

    AugustusDeniedCapabilitiesEvidence {
        frozen_denied_capabilities,
        launcher_enforcement_state: AugustusCapabilityEnforcementState::Absent,
        destination_gate_enforcement_state: AugustusCapabilityEnforcementState::Absent,
        rule_evidence: AugustusRuleEvidence {
            pre_contact_order: 5,
            rule_id: AugustusPreflightRuleId::DeniedCapabilities,
            state: AugustusEvidenceState::Unverified,
            rejection_condition_indices: vec![0, 1],
        },
    }
}

/// Produces Rule 6 evidence without accepting a caller-built machine plan.
///
/// The exact one-entry allowlist is read from the embedded profile and bound to
/// the same probe, detector, and expected-attempt constants as the terminal
/// verifier. A machine plan remains absent until a separately reviewed typed
/// launcher exists, so this evidence always rejects before contact.
pub fn produce_augustus_plan_allowlist_evidence() -> AugustusPlanAllowlistEvidence {
    produce_plan_allowlist_evidence(FROZEN_AUGUSTUS_PROFILE)
}

fn produce_plan_allowlist_evidence(profile_json: &[u8]) -> AugustusPlanAllowlistEvidence {
    let calculated_profile_sha256 = hex::encode(Sha256::digest(profile_json));
    let profile = if profile_json.len() <= MAX_AUGUSTUS_PREFLIGHT_INPUT_BYTES {
        serde_json::from_slice::<AugustusProfileAllowlistDocument>(profile_json).ok()
    } else {
        None
    };
    let entry = profile
        .as_ref()
        .and_then(|profile| match profile.allowlist.as_slice() {
            [entry] => Some(entry),
            _ => None,
        });
    let probe_and_detectors_match = entry.is_some_and(|entry| {
        entry.probe == AUGUSTUS_FROZEN_PROBE
            && entry.detectors.as_slice() == [AUGUSTUS_FROZEN_DETECTOR]
    });
    let detector_config_matches = entry.is_some_and(|entry| !entry.detector_config.case_sensitive);
    let expected_attempts_match =
        entry.is_some_and(|entry| entry.expected_attempts == AUGUSTUS_FROZEN_EXPECTED_ATTEMPTS);
    let profile_is_trusted = calculated_profile_sha256 == AUGUSTUS_PROFILE_SHA256
        && profile.as_ref().is_some_and(|profile| {
            profile.schema_version == AUGUSTUS_PROFILE_SCHEMA_VERSION
                && profile.profile_id == AUGUSTUS_PROFILE_ID
        });
    let frozen_allowlist = if profile_is_trusted
        && probe_and_detectors_match
        && detector_config_matches
        && expected_attempts_match
    {
        entry.map(|entry| {
            vec![AugustusFrozenPlanAllowlistEntry {
                probe: entry.probe.clone(),
                detectors: entry.detectors.clone(),
                detector_case_sensitive: entry.detector_config.case_sensitive,
                expected_attempts: entry.expected_attempts,
            }]
        })
    } else {
        None
    };

    let mut rejection_condition_indices = Vec::with_capacity(3);
    if !probe_and_detectors_match {
        rejection_condition_indices.push(0);
    }
    if !detector_config_matches {
        rejection_condition_indices.push(1);
    }
    rejection_condition_indices.push(2);

    AugustusPlanAllowlistEvidence {
        frozen_allowlist,
        argument_builder_state: AugustusPlanEnforcementState::Absent,
        plan_verifier_state: AugustusPlanEnforcementState::Absent,
        machine_plan_state: AugustusPlanEnforcementState::Absent,
        rule_evidence: AugustusRuleEvidence {
            pre_contact_order: 6,
            rule_id: AugustusPreflightRuleId::ProbeDetectorAllowlist,
            state: AugustusEvidenceState::Rejected,
            rejection_condition_indices,
        },
    }
}

fn replace_caller_mechanical_evidence(input: &mut AugustusPreflightInput) {
    let profile_admission = produce_augustus_profile_admission_evidence();
    input.rule_evidence[..PROFILE_ADMISSION_RULE_COUNT]
        .clone_from_slice(profile_admission.rule_evidence());

    let scope_binding = produce_augustus_scope_binding_evidence();
    input.rule_evidence[2].clone_from(scope_binding.rule_evidence());

    let destination_policy = produce_augustus_destination_policy_evidence();
    input.rule_evidence[3].clone_from(destination_policy.rule_evidence());

    let denied_capabilities = produce_augustus_denied_capabilities_evidence();
    input.rule_evidence[4].clone_from(denied_capabilities.rule_evidence());

    let plan_allowlist = produce_augustus_plan_allowlist_evidence();
    input.rule_evidence[5].clone_from(plan_allowlist.rule_evidence());
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

    replace_caller_mechanical_evidence(&mut input);

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
    fn mechanical_admission_overrides_caller_evidence_in_every_valid_pair() {
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
    fn current_scope_binding_evidence_has_no_grant_or_bound_model() {
        let evidence = produce_augustus_scope_binding_evidence();
        let destination = evidence
            .frozen_destination()
            .expect("trusted frozen destination");

        assert_eq!(destination.generator(), AUGUSTUS_FROZEN_GENERATOR);
        assert_eq!(destination.scheme(), AUGUSTUS_FROZEN_SCHEME);
        assert_eq!(destination.host(), AUGUSTUS_FROZEN_HOST);
        assert_eq!(destination.port(), AUGUSTUS_FROZEN_PORT);
        assert_eq!(destination.api_base_path(), AUGUSTUS_FROZEN_API_BASE_PATH);
        assert_eq!(
            destination.model_binding(),
            AugustusModelBindingRequirement::ExactScopeGrant
        );
        assert_eq!(
            evidence.scope_grant_state(),
            AugustusScopeGrantState::Absent
        );
        assert_eq!(evidence.bound_model(), None);
        assert_eq!(
            evidence.rule_evidence(),
            &AugustusRuleEvidence {
                pre_contact_order: 3,
                rule_id: AugustusPreflightRuleId::ExactDestinationAndModelBinding,
                state: AugustusEvidenceState::Rejected,
                rejection_condition_indices: vec![0],
            }
        );
    }

    #[test]
    fn destination_profile_drift_adds_the_exact_mismatch_condition() {
        let mut profile: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        profile["destination"]["host"] = json!("api.example.invalid");
        let drifted_profile = serde_json::to_vec(&profile).expect("serializable drifted profile");

        let evidence = produce_scope_binding_evidence(&drifted_profile);

        assert_eq!(evidence.frozen_destination(), None);
        assert_eq!(evidence.bound_model(), None);
        assert_eq!(
            evidence.rule_evidence().state(),
            AugustusEvidenceState::Rejected
        );
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[0, 1]
        );
    }

    #[test]
    fn caller_cannot_mark_scope_binding_verified() {
        let mut input: AugustusPreflightInput =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[3].0).expect("valid later-rule fixture");
        assert_eq!(
            input.rule_evidence[2].state(),
            AugustusEvidenceState::Verified
        );

        replace_caller_mechanical_evidence(&mut input);

        assert_eq!(
            &input.rule_evidence[2],
            produce_augustus_scope_binding_evidence().rule_evidence()
        );
        assert_eq!(input.rule_evidence[2].rejection_condition_indices(), &[0]);
    }

    #[test]
    fn current_destination_policy_is_intent_with_absent_enforcement() {
        let evidence = produce_augustus_destination_policy_evidence();
        let policy = evidence.frozen_policy().expect("trusted frozen policy");

        assert!(!policy.custom_base_url_allowed());
        assert!(!policy.redirects_allowed());
        assert_eq!(
            evidence.base_url_enforcement_state(),
            AugustusDestinationPolicyEnforcementState::Absent
        );
        assert_eq!(
            evidence.redirect_enforcement_state(),
            AugustusDestinationPolicyEnforcementState::Absent
        );
        assert_eq!(
            evidence.rule_evidence(),
            &AugustusRuleEvidence {
                pre_contact_order: 4,
                rule_id: AugustusPreflightRuleId::BaseUrlAndRedirectDenial,
                state: AugustusEvidenceState::Unverified,
                rejection_condition_indices: vec![0, 1],
            }
        );
    }

    #[test]
    fn destination_policy_drift_is_not_returned_as_trusted_policy() {
        let mut profile: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        profile["destination"]["custom_base_url_allowed"] = json!(true);
        let drifted_profile = serde_json::to_vec(&profile).expect("serializable drifted profile");

        let evidence = produce_destination_policy_evidence(&drifted_profile);

        assert_eq!(evidence.frozen_policy(), None);
        assert_eq!(
            evidence.rule_evidence().state(),
            AugustusEvidenceState::Unverified
        );
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[0, 1]
        );
    }

    #[test]
    fn caller_cannot_mark_destination_policy_verified() {
        let mut input: AugustusPreflightInput =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[4].0).expect("valid later-rule fixture");
        assert_eq!(
            input.rule_evidence[3].state(),
            AugustusEvidenceState::Verified
        );

        replace_caller_mechanical_evidence(&mut input);

        assert_eq!(
            &input.rule_evidence[3],
            produce_augustus_destination_policy_evidence().rule_evidence()
        );
        assert_eq!(
            input.rule_evidence[3].rejection_condition_indices(),
            &[0, 1]
        );
    }

    #[test]
    fn current_denied_capability_ledger_is_frozen_but_not_enforced() {
        let evidence = produce_augustus_denied_capabilities_evidence();
        let denied = evidence
            .frozen_denied_capabilities()
            .expect("trusted frozen deny list");

        assert_eq!(denied, AUGUSTUS_FROZEN_DENIED_CAPABILITIES.as_slice());
        assert_eq!(denied.len(), 16);
        assert_eq!(
            evidence.launcher_enforcement_state(),
            AugustusCapabilityEnforcementState::Absent
        );
        assert_eq!(
            evidence.destination_gate_enforcement_state(),
            AugustusCapabilityEnforcementState::Absent
        );
        assert_eq!(
            evidence.rule_evidence(),
            &AugustusRuleEvidence {
                pre_contact_order: 5,
                rule_id: AugustusPreflightRuleId::DeniedCapabilities,
                state: AugustusEvidenceState::Unverified,
                rejection_condition_indices: vec![0, 1],
            }
        );
    }

    #[test]
    fn denied_capability_order_drift_is_not_returned_as_trusted_policy() {
        let mut profile: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        profile["denied_capabilities"]
            .as_array_mut()
            .expect("denied capability array")
            .reverse();
        let drifted_profile = serde_json::to_vec(&profile).expect("serializable drifted profile");

        let evidence = produce_denied_capabilities_evidence(&drifted_profile);

        assert_eq!(evidence.frozen_denied_capabilities(), None);
        assert_eq!(
            evidence.rule_evidence().state(),
            AugustusEvidenceState::Unverified
        );
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[0, 1]
        );
    }

    #[test]
    fn caller_cannot_mark_denied_capabilities_verified() {
        let mut input: AugustusPreflightInput =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[5].0).expect("valid later-rule fixture");
        assert_eq!(
            input.rule_evidence[4].state(),
            AugustusEvidenceState::Verified
        );

        replace_caller_mechanical_evidence(&mut input);

        assert_eq!(
            &input.rule_evidence[4],
            produce_augustus_denied_capabilities_evidence().rule_evidence()
        );
        assert_eq!(
            input.rule_evidence[4].rejection_condition_indices(),
            &[0, 1]
        );
    }

    #[test]
    fn current_plan_allowlist_is_frozen_but_machine_plan_is_absent() {
        let evidence = produce_augustus_plan_allowlist_evidence();
        let allowlist = evidence
            .frozen_allowlist()
            .expect("trusted frozen allowlist");

        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist[0].probe(), AUGUSTUS_FROZEN_PROBE);
        assert_eq!(allowlist[0].detectors(), &[AUGUSTUS_FROZEN_DETECTOR]);
        assert!(!allowlist[0].detector_case_sensitive());
        assert_eq!(allowlist[0].expected_attempts(), 15);
        assert_eq!(
            allowlist[0].expected_attempts(),
            AUGUSTUS_FROZEN_EXPECTED_ATTEMPTS
        );
        assert_eq!(
            evidence.argument_builder_state(),
            AugustusPlanEnforcementState::Absent
        );
        assert_eq!(
            evidence.plan_verifier_state(),
            AugustusPlanEnforcementState::Absent
        );
        assert_eq!(
            evidence.machine_plan_state(),
            AugustusPlanEnforcementState::Absent
        );
        assert_eq!(
            evidence.rule_evidence(),
            &AugustusRuleEvidence {
                pre_contact_order: 6,
                rule_id: AugustusPreflightRuleId::ProbeDetectorAllowlist,
                state: AugustusEvidenceState::Rejected,
                rejection_condition_indices: vec![2],
            }
        );
    }

    #[test]
    fn allowlist_drift_uses_only_the_owning_rule_six_conditions() {
        let mut extra_detector: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        extra_detector["allowlist"][0]["detectors"] =
            json!([AUGUSTUS_FROZEN_DETECTOR, "synthetic.AdditionalDetector"]);
        let evidence = produce_plan_allowlist_evidence(
            &serde_json::to_vec(&extra_detector).expect("serializable detector drift"),
        );
        assert_eq!(evidence.frozen_allowlist(), None);
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[0, 2]
        );

        let mut detector_tuning: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        detector_tuning["allowlist"][0]["detector_config"]["case_sensitive"] = json!(true);
        let evidence = produce_plan_allowlist_evidence(
            &serde_json::to_vec(&detector_tuning).expect("serializable detector tuning"),
        );
        assert_eq!(evidence.frozen_allowlist(), None);
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[1, 2]
        );

        let mut attempt_metadata: Value =
            serde_json::from_slice(FROZEN_AUGUSTUS_PROFILE).expect("valid frozen profile");
        attempt_metadata["allowlist"][0]["expected_attempts"] = json!(14);
        let evidence = produce_plan_allowlist_evidence(
            &serde_json::to_vec(&attempt_metadata).expect("serializable attempt drift"),
        );
        assert_eq!(evidence.frozen_allowlist(), None);
        assert_eq!(
            evidence.rule_evidence().rejection_condition_indices(),
            &[2],
            "attempt-count drift belongs to Rule 7, not Rule 6"
        );
    }

    #[test]
    fn caller_cannot_mark_plan_allowlist_verified() {
        let mut input: AugustusPreflightInput =
            serde_json::from_slice(VALID_FIXTURE_PAIRS[6].0).expect("valid later-rule fixture");
        assert_eq!(
            input.rule_evidence[5].state(),
            AugustusEvidenceState::Verified
        );

        replace_caller_mechanical_evidence(&mut input);

        assert_eq!(
            &input.rule_evidence[5],
            produce_augustus_plan_allowlist_evidence().rule_evidence()
        );
        assert_eq!(input.rule_evidence[5].rejection_condition_indices(), &[2]);
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

        let scope_evidence = produce_scope_binding_evidence(&drifted_profile);
        assert_eq!(scope_evidence.frozen_destination(), None);
        assert_eq!(
            scope_evidence.rule_evidence().rejection_condition_indices(),
            &[0],
            "unrelated profile drift must not invent a destination mismatch"
        );
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
