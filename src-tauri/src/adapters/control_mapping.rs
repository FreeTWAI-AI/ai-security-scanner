//! Versioned, allowlisted evidence-to-control relationships.
//!
//! The embedded catalog is project-authored metadata. A match never means a
//! control is implemented, effective, certified, or compliant.

use crate::domain::{ControlMappingProvenance, ControlReference};
use crate::error::{AppError, AppResult};
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const CATALOG_JSON: &str = include_str!("../../../mappings/control-mappings.json");
const MAX_CONTROLS: usize = 1_024;
const MAX_ENTRIES: usize = 4_096;
const MAX_REFERENCES_PER_ENTRY: usize = 8;
const MAX_LOOKUP_RESULTS: usize = 32;
const MAX_CWE_DERIVED_CONTROLS: usize = 1_024;
/// An OWASP Top 10 category is defined by a few dozen CWEs at most; the widest
/// published 2021 category names 40.
const MAX_CWE_IDS_PER_DERIVED_CONTROL: usize = 64;
const REVIEW_PROCESS_V1: &str = "source_coordinate_and_rationale_review_v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingCatalog {
    schema_version: String,
    mapping_version: String,
    provenance: MappingCatalogProvenance,
    relationship: String,
    disclaimer: String,
    sources: Vec<FrameworkSource>,
    controls: Vec<ControlDefinition>,
    entries: Vec<MappingEntry>,
    /// Controls reached through a scanner's own CWE classification rather than
    /// through its rule id. Optional so a catalog may carry none.
    #[serde(default)]
    cwe_derived_controls: Vec<CweDerivedEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingCatalogProvenance {
    reviewed_at: String,
    review_process: String,
    /// SHA-256 of canonical JSON for the complete catalog after removing only
    /// this field. This avoids a self-referential digest while binding every
    /// mapping, source, rationale, and remaining provenance field.
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameworkSource {
    framework: String,
    framework_version: String,
    url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlDefinition {
    key: String,
    framework: String,
    framework_version: String,
    control_id: String,
    title: String,
    /// Withholds this control unless the case declares the named kind of AI
    /// involvement. Required on an AI-gated framework and rejected elsewhere.
    #[serde(default)]
    applicability: Option<AiApplicability>,
}

/// One OWASP Top 10 category and the CWEs whose membership defines it.
///
/// The Top 10 categories are published as CWE sets, so this is a restatement
/// of that published membership rather than a judgement this product makes.
/// The derivation runs on the scanner's own CWE assignment: a result the
/// scanner never classified reaches no category.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CweDerivedEntry {
    control: String,
    cwe_ids: Vec<String>,
    rationale: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingEntry {
    engine_id: String,
    match_kind: MatchKind,
    source_rule: String,
    controls: Vec<String>,
    rationale: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum MatchKind {
    Exact,
    Prefix,
}

/// Frameworks whose coordinates are withheld until the case says the AI
/// involvement they describe is actually present.
///
/// A defensive coordinate for a system that holds no model is not a weaker
/// claim, it is a claim about something that is not there. Both frameworks
/// here describe AI systems specifically, so both are gated the same way.
const AI_GATED_FRAMEWORKS: [&str; 2] = ["AIDEFEND", "OWASP Top 10 for LLM Applications"];

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AiApplicability {
    AiSystem,
    AiGeneratedArtifact,
}

#[derive(Debug)]
struct ValidatedCatalog {
    mapping_version: String,
    provenance: ControlMappingProvenance,
    relationship: String,
    controls: BTreeMap<String, ControlDefinition>,
    entries: Vec<MappingEntry>,
    cwe_derived_controls: Vec<CweDerivedEntry>,
}

static CATALOG: OnceLock<Result<ValidatedCatalog, String>> = OnceLock::new();

pub(super) fn validate_catalog(known_engines: &[&str]) -> AppResult<()> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    let known = known_engines.iter().copied().collect::<BTreeSet<_>>();
    for entry in &catalog.entries {
        if !known.contains(entry.engine_id.as_str()) {
            return Err(AppError::EngineRegistry(format!(
                "control mapping references unknown engine {}",
                entry.engine_id
            )));
        }
    }
    Ok(())
}

pub(super) fn catalog_version() -> AppResult<&'static str> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    Ok(catalog.mapping_version.as_str())
}

pub(super) fn catalog_provenance() -> AppResult<ControlMappingProvenance> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    Ok(catalog.provenance.clone())
}

/// Prove that a frozen current-catalog relationship is one exact reviewed
/// catalog entry for every bound evidence-producing engine/rule pair. The
/// catalog digest alone only identifies the catalog; engine identity without
/// the structured source rule does not prove which matcher produced a
/// relationship.
pub(super) fn validate_current_reference(
    reference: &ControlReference,
    evidence_sources: &[(String, String)],
    evidence_cwe_ids: &[String],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> AppResult<()> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    if reference.mapping_version != catalog.mapping_version
        || reference.relationship != catalog.relationship
    {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} does not use the exact current catalog version and relationship",
            reference.framework, reference.control_id
        )));
    }

    let matching_controls = catalog
        .controls
        .iter()
        .filter(|(_, control)| {
            control.framework == reference.framework
                && control.framework_version == reference.framework_version
                && control.control_id == reference.control_id
        })
        .collect::<Vec<_>>();
    if matching_controls.len() != 1 {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} is not one exact current-catalog coordinate",
            reference.framework, reference.control_id
        )));
    }
    let &(control_key, control) = matching_controls
        .first()
        .expect("one exact current-catalog coordinate was established");
    if control.title != reference.title {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} title does not match the exact current-catalog control",
            reference.framework, reference.control_id
        )));
    }
    if !control_is_applicable(
        control,
        ai_system_applicable,
        ai_generated_artifact_applicable,
    ) {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} does not match its exact current-catalog AI applicability condition",
            reference.framework, reference.control_id
        )));
    }
    // A relationship reached through the scanner's CWE classification is proved
    // against the derived section instead: it was never claimed to come from a
    // rule entry, and requiring one would reject the coordinate it does have a
    // reviewed basis for.
    if let Some(derived) = catalog
        .cwe_derived_controls
        .iter()
        .find(|derived| derived.control == *control_key)
        && derived.rationale == reference.rationale
    {
        if !evidence_cwe_ids
            .iter()
            .any(|cwe| derived.cwe_ids.contains(cwe))
        {
            return Err(AppError::InvalidRequest(format!(
                "framework reference {} {} was derived from a CWE its evidence does not carry",
                reference.framework, reference.control_id
            )));
        }
        return Ok(());
    }
    if evidence_sources.is_empty()
        || evidence_sources.iter().any(|(engine_id, source_rule)| {
            !catalog.entries.iter().any(|entry| {
                entry.engine_id == *engine_id
                    && source_rule_matches(entry, source_rule)
                    && entry.rationale == reference.rationale
                    && entry.controls.iter().any(|key| key == control_key)
            })
        })
    {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} rationale and structured evidence source rule do not match one exact current-catalog entry",
            reference.framework, reference.control_id
        )));
    }
    Ok(())
}

fn source_rule_matches(entry: &MappingEntry, source_rule: &str) -> bool {
    match entry.match_kind {
        MatchKind::Exact => source_rule == entry.source_rule,
        MatchKind::Prefix => source_rule.starts_with(&entry.source_rule),
    }
}

pub(super) fn lookup(
    engine_id: &str,
    source_rule: &str,
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> Vec<ControlReference> {
    let Ok(catalog) = catalog() else {
        // Registry construction validates this immutable embedded catalog. If a
        // future build ships invalid metadata, findings remain evidence-backed
        // and conservatively unmapped instead of crashing normalization.
        return Vec::new();
    };

    let mut references = BTreeMap::new();
    for entry in catalog
        .entries
        .iter()
        .filter(|entry| entry.engine_id == engine_id && source_rule_matches(entry, source_rule))
    {
        for key in &entry.controls {
            let Some(control) = catalog.controls.get(key) else {
                continue;
            };
            if !control_is_applicable(
                control,
                ai_system_applicable,
                ai_generated_artifact_applicable,
            ) {
                continue;
            }
            let identity = (
                control.framework.clone(),
                control.framework_version.clone(),
                control.control_id.clone(),
                control.title.clone(),
                entry.rationale.clone(),
            );
            references
                .entry(identity)
                .or_insert_with(|| ControlReference {
                    framework: control.framework.clone(),
                    framework_version: control.framework_version.clone(),
                    control_id: control.control_id.clone(),
                    title: control.title.clone(),
                    relationship: catalog.relationship.clone(),
                    rationale: entry.rationale.clone(),
                    mapping_version: catalog.mapping_version.clone(),
                    mapping_provenance: Some(catalog.provenance.clone()),
                });
            if references.len() >= MAX_LOOKUP_RESULTS {
                break;
            }
        }
        if references.len() >= MAX_LOOKUP_RESULTS {
            break;
        }
    }
    references.into_values().collect()
}

/// Whether a control's AI gate is satisfied by what this case declared.
///
/// A control outside an AI-gated framework declares no applicability and is
/// always in scope; validation guarantees the two agree.
fn control_is_applicable(
    control: &ControlDefinition,
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> bool {
    match control.applicability {
        Some(AiApplicability::AiSystem) => ai_system_applicable,
        Some(AiApplicability::AiGeneratedArtifact) => ai_generated_artifact_applicable,
        None => !AI_GATED_FRAMEWORKS.contains(&control.framework.as_str()),
    }
}

/// Controls reached through the CWE identifiers a scanner assigned to a result.
///
/// This is the OWASP Top 10 path. A Top 10 category is published as a set of
/// CWEs, so membership is looked up rather than judged: the reader can check
/// any coordinate here against the published set. A result whose scanner
/// assigned no CWE reaches no category, which is why the trailing categories
/// whose CWEs no scanner emits stay empty rather than being back-filled from
/// something else.
pub(super) fn lookup_by_cwe(
    cwe_ids: &[String],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> Vec<ControlReference> {
    if cwe_ids.is_empty() {
        return Vec::new();
    }
    let Ok(catalog) = catalog() else {
        return Vec::new();
    };
    let mut references = BTreeMap::new();
    for derived in &catalog.cwe_derived_controls {
        if !derived.cwe_ids.iter().any(|cwe| cwe_ids.contains(cwe)) {
            continue;
        }
        let Some(control) = catalog.controls.get(&derived.control) else {
            continue;
        };
        if !control_is_applicable(
            control,
            ai_system_applicable,
            ai_generated_artifact_applicable,
        ) {
            continue;
        }
        references.insert(
            control.control_id.clone(),
            ControlReference {
                framework: control.framework.clone(),
                framework_version: control.framework_version.clone(),
                control_id: control.control_id.clone(),
                title: control.title.clone(),
                relationship: catalog.relationship.clone(),
                rationale: derived.rationale.clone(),
                mapping_version: catalog.mapping_version.clone(),
                mapping_provenance: Some(catalog.provenance.clone()),
            },
        );
        if references.len() >= MAX_LOOKUP_RESULTS {
            break;
        }
    }
    references.into_values().collect()
}

fn catalog() -> Result<&'static ValidatedCatalog, String> {
    match CATALOG.get_or_init(parse_and_validate) {
        Ok(catalog) => Ok(catalog),
        Err(error) => Err(error.clone()),
    }
}

fn parse_and_validate() -> Result<ValidatedCatalog, String> {
    parse_and_validate_json(CATALOG_JSON)
}

fn parse_and_validate_json(input: &str) -> Result<ValidatedCatalog, String> {
    let raw: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid embedded control mapping JSON: {error}"))?;
    let actual_catalog_sha256 = canonical_catalog_sha256(&raw)?;
    let parsed: MappingCatalog = serde_json::from_value(raw)
        .map_err(|error| format!("invalid embedded control mapping JSON: {error}"))?;

    if parsed.schema_version != "1.1" {
        return Err(format!(
            "unsupported control mapping schema version {}",
            parsed.schema_version
        ));
    }
    let mapping_date = validate_mapping_version(&parsed.mapping_version)?;
    let reviewed_at = validate_calendar_date(
        "mapping provenance reviewed_at",
        &parsed.provenance.reviewed_at,
    )?;
    if reviewed_at < mapping_date {
        return Err(
            "mapping provenance reviewed_at cannot predate the mapping version date".into(),
        );
    }
    if parsed.provenance.review_process != REVIEW_PROCESS_V1 {
        return Err(format!(
            "mapping provenance review_process must be {REVIEW_PROCESS_V1}"
        ));
    }
    validate_sha256(
        "mapping provenance canonical_sha256",
        &parsed.provenance.canonical_sha256,
    )?;
    if parsed.provenance.canonical_sha256 != actual_catalog_sha256 {
        return Err(format!(
            "control mapping canonical SHA-256 mismatch: expected {}, calculated {actual_catalog_sha256}",
            parsed.provenance.canonical_sha256
        ));
    }
    if parsed.relationship != "related" {
        return Err("control mapping relationship must be related".into());
    }
    validate_text("mapping disclaimer", &parsed.disclaimer, 40, 512)?;
    let disclaimer = parsed.disclaimer.to_ascii_lowercase();
    if !disclaimer.contains("do not establish") || !disclaimer.contains("compliance") {
        return Err("control mapping disclaimer must reject compliance claims".into());
    }

    if parsed.sources.is_empty() || parsed.sources.len() > 16 {
        return Err("control mapping sources must contain between 1 and 16 items".into());
    }
    let mut sources = BTreeSet::new();
    for source in parsed.sources {
        validate_text("source framework", &source.framework, 1, 80)?;
        validate_text("source framework version", &source.framework_version, 1, 40)?;
        validate_https_url(&source.url)?;
        if !sources.insert((source.framework, source.framework_version)) {
            return Err("duplicate framework source in control mapping catalog".into());
        }
    }

    if parsed.controls.is_empty() || parsed.controls.len() > MAX_CONTROLS {
        return Err(format!(
            "control mapping definitions must contain between 1 and {MAX_CONTROLS} items"
        ));
    }
    let mut controls = BTreeMap::new();
    let mut coordinates = BTreeSet::new();
    for control in parsed.controls {
        validate_slug("control key", &control.key, 80, true)?;
        validate_text("control framework", &control.framework, 1, 80)?;
        validate_text(
            "control framework version",
            &control.framework_version,
            1,
            40,
        )?;
        validate_text("control id", &control.control_id, 1, 80)?;
        validate_text("control title", &control.title, 1, 160)?;
        let ai_gated = AI_GATED_FRAMEWORKS.contains(&control.framework.as_str());
        if ai_gated && control.applicability.is_none() {
            return Err(format!(
                "{} control {} has no explicit applicability",
                control.framework, control.key
            ));
        }
        if !ai_gated && control.applicability.is_some() {
            return Err(format!(
                "control {} declares AI applicability outside an AI-gated framework",
                control.key
            ));
        }
        if !sources.contains(&(control.framework.clone(), control.framework_version.clone())) {
            return Err(format!(
                "control {} has no matching official framework source",
                control.key
            ));
        }
        let coordinate = (
            control.framework.clone(),
            control.framework_version.clone(),
            control.control_id.clone(),
        );
        if !coordinates.insert(coordinate) {
            return Err(format!(
                "duplicate framework coordinate for control {}",
                control.key
            ));
        }
        let key = control.key.clone();
        if controls.insert(key.clone(), control).is_some() {
            return Err(format!("duplicate control mapping key {key}"));
        }
    }

    if parsed.entries.len() > MAX_ENTRIES {
        return Err(format!(
            "control mapping entries exceed the {MAX_ENTRIES}-entry limit"
        ));
    }
    let mut matchers = BTreeSet::new();
    for entry in &parsed.entries {
        validate_slug("mapping engine id", &entry.engine_id, 64, false)?;
        validate_text("mapping source rule", &entry.source_rule, 1, 512)?;
        if entry
            .source_rule
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']'))
        {
            return Err(format!(
                "mapping for {} uses a wildcard source rule",
                entry.engine_id
            ));
        }
        if entry.match_kind == MatchKind::Prefix && entry.source_rule.chars().count() < 4 {
            return Err(format!(
                "prefix mapping for {} is too broad",
                entry.engine_id
            ));
        }
        if entry.controls.is_empty() || entry.controls.len() > MAX_REFERENCES_PER_ENTRY {
            return Err(format!(
                "mapping for {} must reference between 1 and {MAX_REFERENCES_PER_ENTRY} controls",
                entry.engine_id
            ));
        }
        let mut unique_controls = BTreeSet::new();
        for key in &entry.controls {
            if !controls.contains_key(key) {
                return Err(format!(
                    "mapping for {} references unknown control {key}",
                    entry.engine_id
                ));
            }
            if !unique_controls.insert(key) {
                return Err(format!(
                    "mapping for {} repeats control {key}",
                    entry.engine_id
                ));
            }
        }
        validate_text("mapping rationale", &entry.rationale, 20, 512)?;
        let rationale = entry.rationale.to_ascii_lowercase();
        if rationale.contains("is compliant")
            || rationale.contains("is certified")
            || rationale.contains("passes the control")
        {
            return Err(format!(
                "mapping rationale for {} makes a prohibited assurance claim",
                entry.engine_id
            ));
        }
        let matcher = (
            entry.engine_id.clone(),
            entry.match_kind,
            entry.source_rule.clone(),
        );
        if !matchers.insert(matcher) {
            return Err(format!(
                "duplicate source-rule mapping for {}:{}",
                entry.engine_id, entry.source_rule
            ));
        }
    }

    let mapping_version = parsed.mapping_version;
    if parsed.cwe_derived_controls.len() > MAX_CWE_DERIVED_CONTROLS {
        return Err(format!(
            "CWE-derived mappings exceed the {MAX_CWE_DERIVED_CONTROLS}-control limit"
        ));
    }
    let mut derived_controls = BTreeSet::new();
    for derived in &parsed.cwe_derived_controls {
        validate_slug("cwe-derived control key", &derived.control, 80, true)?;
        if !controls.contains_key(&derived.control) {
            return Err(format!(
                "cwe-derived mapping references unknown control {}",
                derived.control
            ));
        }
        if !derived_controls.insert(derived.control.clone()) {
            return Err(format!(
                "duplicate cwe-derived mapping for control {}",
                derived.control
            ));
        }
        if derived.cwe_ids.is_empty() || derived.cwe_ids.len() > MAX_CWE_IDS_PER_DERIVED_CONTROL {
            return Err(format!(
                "cwe-derived mapping for {} must name between 1 and {MAX_CWE_IDS_PER_DERIVED_CONTROL} CWE identifiers",
                derived.control
            ));
        }
        // Deliberately not a disjointness check across controls. OWASP's own
        // published sets overlap -- CWE-259 is in both A02 and A07:2021 -- and
        // a finding that genuinely sits in two categories should say so rather
        // than have one silently dropped to make the sets tidy.
        let mut seen_in_control = BTreeSet::new();
        for cwe in &derived.cwe_ids {
            if !is_cwe_identifier(cwe) {
                return Err(format!(
                    "cwe-derived mapping for {} names {cwe}, which is not a CWE-<digits> identifier",
                    derived.control
                ));
            }
            if !seen_in_control.insert(cwe.clone()) {
                return Err(format!(
                    "cwe-derived mapping for {} repeats {cwe}",
                    derived.control
                ));
            }
        }
        validate_text("cwe-derived rationale", &derived.rationale, 20, 512)?;
    }

    Ok(ValidatedCatalog {
        mapping_version: mapping_version.clone(),
        provenance: ControlMappingProvenance {
            mapping_version,
            reviewed_at: parsed.provenance.reviewed_at,
            review_process: parsed.provenance.review_process,
            catalog_sha256: parsed.provenance.canonical_sha256,
        },
        relationship: parsed.relationship,
        controls,
        entries: parsed.entries,
        cwe_derived_controls: parsed.cwe_derived_controls,
    })
}

fn validate_mapping_version(value: &str) -> Result<NaiveDate, String> {
    let Some((date, revision)) = value.split_once('.') else {
        return Err("control mapping version must be YYYY-MM-DD.N".into());
    };
    let date_is_valid = date.len() == 10
        && date.as_bytes().get(4) == Some(&b'-')
        && date.as_bytes().get(7) == Some(&b'-')
        && date
            .chars()
            .enumerate()
            .all(|(index, character)| matches!(index, 4 | 7) || character.is_ascii_digit());
    let revision_is_valid =
        !revision.starts_with('0') && revision.parse::<u32>().is_ok_and(|revision| revision > 0);
    if !date_is_valid || !revision_is_valid {
        return Err("control mapping version must be YYYY-MM-DD.N".into());
    }
    validate_calendar_date("control mapping version date", date)
}

fn validate_calendar_date(label: &str, value: &str) -> Result<NaiveDate, String> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return Err(format!("{label} must be a real YYYY-MM-DD calendar date"));
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| format!("{label} must be a real YYYY-MM-DD calendar date"))
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must contain exactly 64 hexadecimal characters"
        ));
    }
    if value != value.to_ascii_lowercase() {
        return Err(format!("{label} must use lowercase hexadecimal"));
    }
    Ok(())
}

fn canonical_catalog_sha256(raw: &Value) -> Result<String, String> {
    let mut canonical = raw.clone();
    let root = canonical
        .as_object_mut()
        .ok_or_else(|| "control mapping catalog must be a JSON object".to_owned())?;
    let provenance = root
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "control mapping catalog provenance must be a JSON object".to_owned())?;
    if provenance.remove("canonical_sha256").is_none() {
        return Err("control mapping catalog provenance has no canonical_sha256".into());
    }
    let mut bytes = Vec::new();
    write_canonical_json(&canonical, &mut bytes)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| format!("cannot canonicalize mapping string: {error}"))?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| format!("cannot canonicalize mapping key: {error}"))?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

/// Exactly `CWE-` followed by digits. The catalog is hand-written, so a typo
/// like `CWE 78` or `cwe-78` is caught at load rather than silently matching
/// nothing at scan time.
fn is_cwe_identifier(value: &str) -> bool {
    value
        .strip_prefix("CWE-")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
}

fn validate_https_url(value: &str) -> Result<(), String> {
    validate_text("framework source URL", value, 9, 2_048)?;
    if !value.starts_with("https://")
        || value.contains('@')
        || value.chars().any(char::is_whitespace)
    {
        return Err("framework source URL must be a credential-free HTTPS URL".into());
    }
    Ok(())
}

fn validate_slug(label: &str, value: &str, max: usize, allow_dot: bool) -> Result<(), String> {
    validate_text(label, value, 1, max)?;
    if !value.chars().enumerate().all(|(index, character)| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || (character == '-' && index > 0)
            || (allow_dot && character == '.' && index > 0)
    }) {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, min: usize, max: usize) -> Result<(), String> {
    let length = value.chars().count();
    if length < min || length > max || value.trim() != value || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain {min} to {max} safe characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real execution of the one upstream benchmark the kube-bench image
    /// ships, and the only source of check identifiers this product can
    /// observe from that engine.
    const KUBE_BENCH_CIS_1_11_FIXTURE: &str =
        include_str!("../../tests/fixtures/adapters/kube-bench.json");

    fn catalog_fixture() -> Value {
        serde_json::from_str(CATALOG_JSON).expect("embedded catalog JSON")
    }

    fn kube_bench_cis_1_11_check_ids() -> Vec<String> {
        let fixture: Value = serde_json::from_str(KUBE_BENCH_CIS_1_11_FIXTURE)
            .expect("valid kube-bench execution fixture");
        assert_eq!(fixture["Controls"][0]["version"], "cis-1.11");
        fixture["Controls"][0]["tests"]
            .as_array()
            .expect("kube-bench groups")
            .iter()
            .flat_map(|group| {
                group["results"]
                    .as_array()
                    .expect("kube-bench results")
                    .iter()
            })
            .map(|result| {
                result["test_number"]
                    .as_str()
                    .expect("kube-bench check id")
                    .to_owned()
            })
            .collect()
    }

    fn catalog_json_with_recalculated_digest(mut value: Value) -> String {
        value["provenance"]["canonical_sha256"] = Value::String("0".repeat(64));
        let digest = canonical_catalog_sha256(&value).expect("canonical fixture digest");
        value["provenance"]["canonical_sha256"] = Value::String(digest);
        serde_json::to_string(&value).expect("catalog fixture JSON")
    }

    const ENGINES: &[&str] = &[
        "cloudquery",
        "steampipe",
        "prowler",
        "scoutsuite",
        "cloudsplaining",
        "scubagear",
        "maester",
        "naabu",
        "httpx",
        "nuclei",
        "greenbone",
        "semgrep",
        "gitleaks",
        "trufflehog",
        "checkov",
        "kics",
        "trivy",
        "grype",
        "syft",
        "kubescape",
        "kube-bench",
        "garak",
        "agentic-radar",
        "mcp-armor",
    ];

    #[test]
    fn embedded_catalog_is_bounded_and_only_uses_known_engines() {
        validate_catalog(ENGINES).expect("valid embedded mappings");
        let provenance = catalog_provenance().expect("embedded provenance");
        assert_eq!(provenance.mapping_version, "2026-09-13.2");
        assert_eq!(provenance.reviewed_at, "2026-09-13");
        assert_eq!(provenance.review_process, REVIEW_PROCESS_V1);
        assert_eq!(provenance.catalog_sha256.len(), 64);
    }

    /// Guards the failure that broke five entries at once: a `source_rule`
    /// invented to match a hand-written fixture instead of taken from real
    /// engine output. Mapping and fixture agreed, the coverage assertion in
    /// `adapter_fixtures` passed, and the engine resolved no control reference
    /// in production.
    ///
    /// A coverage test cannot catch this, because it reads the same fixture the
    /// mapping was written against. What can be checked without running the
    /// engine is the *shape* upstream guarantees for an identifier, and the
    /// prefix the launcher itself puts there. Each assertion below names the
    /// upstream fact it encodes.
    ///
    /// kube-bench, Cloudsplaining, and Semgrep are checked exactly rather than
    /// by shape. The kube-bench IDs come from a real execution of the
    /// checksum-bound upstream CIS 1.11 node profile, Cloudsplaining writes a
    /// closed set of six risk category keys, and Semgrep's rule pack is tracked
    /// directly.
    ///
    /// This does not cover every engine, and the gaps are real rather than
    /// oversights. Nuclei was the fifth broken entry, and no shape check would
    /// have found it: `exposed-panel` is indistinguishable from the 13,613 real
    /// template ids, which are ordinary lowercase-hyphenated words. Checkov,
    /// KICS by name, Gitleaks, Kubescape, and ScoutSuite are likewise
    /// unconstrained. Catching those needs the pinned rule pack, which is not
    /// available here — the upstream checkouts are 9.7 GB and untracked.
    /// Reviewing a new entry against real engine output remains the only
    /// defence for them.
    #[test]
    fn engine_rule_identifiers_have_the_shape_their_engine_actually_emits() {
        let catalog = catalog_fixture();
        let entries = catalog["entries"]
            .as_array()
            .expect("catalog entries")
            .iter()
            .map(|entry| {
                (
                    entry["engine_id"].as_str().expect("engine id").to_owned(),
                    entry["match_kind"].as_str().expect("match kind").to_owned(),
                    entry["source_rule"]
                        .as_str()
                        .expect("source rule")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();

        let mut checked = 0;
        for (engine_id, match_kind, source_rule) in &entries {
            match engine_id.as_str() {
                // Every KICS query id is a UUID: at the pinned revision all
                // 1885 assets/queries/**/metadata.json `id` values are 36
                // characters. The previous value here, `e24efb0e`, has the
                // shape of KICS's `description_id`, which nothing reads.
                "kics" => {
                    let groups = source_rule.split('-').map(str::len).collect::<Vec<_>>();
                    assert_eq!(
                        groups,
                        [8, 4, 4, 4, 12],
                        "KICS query ids are UUIDs; {source_rule:?} cannot match real output"
                    );
                    assert!(
                        source_rule
                            .bytes()
                            .all(|byte| byte == b'-' || byte.is_ascii_hexdigit()),
                        "KICS query ids are hexadecimal; {source_rule:?} cannot match real output"
                    );
                    checked += 1;
                }
                // The adapter builds `trufflehog:{DetectorName}`, and
                // DetectorName is `DetectorType.String()` — a name from the
                // generated enum, never free text.
                "trufflehog" => {
                    assert!(
                        source_rule.starts_with("trufflehog:"),
                        "the TruffleHog adapter emits trufflehog:{{DetectorName}}; \
                         {source_rule:?} cannot match"
                    );
                    checked += 1;
                }
                // Cloudsplaining writes one closed set of risk category
                // keys into every policy object, and the adapter carries that
                // key through as the source rule. Any other value is invented.
                "cloudsplaining" => {
                    assert!(
                        crate::adapters::CLOUDSPLAINING_RISKS.contains(&source_rule.as_str()),
                        "Cloudsplaining writes only {:?}; {source_rule:?} cannot match real output",
                        crate::adapters::CLOUDSPLAINING_RISKS
                    );
                    checked += 1;
                }
                // The managed AWS profile runs `--service iam`, and Prowler
                // names every check after the service directory it lives in.
                // The previous value was an `s3` check, unreachable here.
                "prowler" => {
                    assert!(
                        source_rule.starts_with("iam_"),
                        "the managed Prowler profile scans only the iam service; \
                         {source_rule:?} cannot be emitted"
                    );
                    checked += 1;
                }
                // This product ships upstream's checksum-bound CIS 1.11 node
                // profile and runs only `--targets node`, so the reachable
                // check ids are exactly those in its real execution fixture.
                // The previous value, `1.2.1`, is a control-plane check that
                // this path can never emit.
                "kube-bench" => {
                    let defined = kube_bench_cis_1_11_check_ids();
                    assert_eq!(defined.len(), 26, "upstream node profile coverage drifted");
                    assert!(
                        defined.iter().any(|id| id == source_rule),
                        "the shipped upstream node benchmark defines no check {source_rule:?}, \
                         so kube-bench can never emit it; it defines {defined:?}"
                    );
                    checked += 1;
                }
                "trivy" | "grype" if match_kind == "prefix" => {
                    assert_eq!(source_rule, "CVE-");
                    checked += 1;
                }
                // Greenbone names every Community Feed test under the OID arc
                // of IANA Private Enterprise Number 25623, which is Greenbone.
                // The launcher copies that OID verbatim, and an OID-less result
                // falls back to the CVE the feed entry names, so these are the
                // only two identifier families the adapter can emit.
                "greenbone" if match_kind == "prefix" => {
                    assert!(
                        source_rule == "1.3.6.1.4.1.25623." || source_rule == "CVE-",
                        "Greenbone emits an NVT OID under the 25623 arc or a CVE; \
                         {source_rule:?} cannot match real output"
                    );
                    checked += 1;
                }
                // The garak adapter builds `{probe}/{detector}`, and a probe is
                // always `{module}.{Class}` from `garak/probes/`. So a mapping
                // may name a whole probe module (`dan.`) or one probe class
                // (`divergence.Repeat/`), and nothing else can match. The
                // terminator carries the weight: without the slash,
                // `divergence.Repeat` also swallows `divergence.RepeatedToken`,
                // which measures stability rather than leakage and belongs to
                // no control here.
                "garak" => {
                    assert_eq!(
                        match_kind, "prefix",
                        "garak source rules name a probe namespace, not one probe/detector pair; \
                         {source_rule:?} is declared as {match_kind}"
                    );
                    let module_scoped = source_rule.ends_with('.')
                        && source_rule.matches('.').count() == 1
                        && !source_rule.contains('/');
                    let class_scoped = source_rule.ends_with('/')
                        && source_rule.matches('/').count() == 1
                        && source_rule.matches('.').count() == 1;
                    assert!(
                        module_scoped || class_scoped,
                        "a garak mapping matches a probe module as `module.` or a probe class \
                         as `module.Class/`; {source_rule:?} matches neither, so it would \
                         either miss every real probe or reach past the one it names"
                    );
                    assert!(
                        source_rule
                            .split(['.', '/'])
                            .next()
                            .is_some_and(|module| !module.is_empty()
                                && module.bytes().all(|byte| byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || byte == b'_')),
                        "garak probe modules are lowercase Python module names; \
                         {source_rule:?} cannot match real output"
                    );
                    checked += 1;
                }
                _ => {}
            }
        }
        assert!(
            checked >= 8,
            "expected the remaining engines whose identifier shape upstream fixes to be checked, saw {checked}"
        );
    }

    #[test]
    fn exact_and_standardized_prefix_rules_map_deterministically() {
        let overprivileged_policy = lookup(
            "prowler",
            "iam_customer_attached_policy_no_administrative_privileges",
            false,
            false,
        );
        assert_eq!(overprivileged_policy.len(), 4);
        assert!(
            overprivileged_policy
                .iter()
                .any(|item| item.control_id == "1.16"
                    && item.framework == "CIS Amazon Web Services Foundations Benchmark")
        );
        assert!(overprivileged_policy.iter().all(|item| {
            item.relationship == "related"
                && item.mapping_version == "2026-09-13.2"
                && item.mapping_provenance.as_ref().is_some_and(|provenance| {
                    provenance.catalog_sha256
                        == "fc3ef6df01553677ac2cbc1d3b42b824d97be13e5742420258456ca5c65e59a4"
                })
                && !item.rationale.to_ascii_lowercase().contains("compliant")
        }));

        let ordinary_cve = lookup("trivy", "CVE-2026-12345", false, false);
        assert_eq!(ordinary_cve.len(), 3);
        assert!(
            ordinary_cve
                .iter()
                .any(|item| item.control_id == "A06:2021")
        );
        assert!(
            ordinary_cve
                .iter()
                .any(|item| item.control_id == "ID.RA-01")
        );
        assert!(ordinary_cve.iter().all(|item| item.framework != "AIDEFEND"));

        let ai_system_cve = lookup("trivy", "CVE-2026-12345", true, false);
        assert_eq!(ai_system_cve.len(), 6);
        assert!(
            ai_system_cve
                .iter()
                .any(|item| item.control_id == "LLM03:2025")
        );
        assert!(
            ai_system_cve
                .iter()
                .any(|item| item.control_id == "AID-H-003.001")
        );

        let generated_code_secret = lookup("gitleaks", "generic-api-key", false, true);
        assert!(
            generated_code_secret
                .iter()
                .any(|item| item.control_id == "AID-H-031.002")
        );
        assert!(
            lookup("gitleaks", "generic-api-key", true, false)
                .iter()
                .all(|item| item.framework != "AIDEFEND")
        );

        let dangerous_construct_rules = [
            "ai-security-scanner.python.dynamic-code-execution",
            "ai-security-scanner.python.shell-true",
            "ai-security-scanner.javascript.child-process-exec",
        ];
        for source_rule in dangerous_construct_rules {
            let ordinary = lookup("semgrep", source_rule, false, false);
            assert!(
                !ordinary.is_empty(),
                "shipped Semgrep rule {source_rule} must have a reviewed mapping"
            );
            assert!(ordinary.iter().all(|item| item.framework != "AIDEFEND"));

            let ai_system = lookup("semgrep", source_rule, true, false);
            assert!(
                ai_system
                    .iter()
                    .any(|item| item.control_id == "AID-H-025.001"),
                "shipped Semgrep rule {source_rule} must expose its reviewed AI-system coordinate"
            );
            assert!(
                ai_system
                    .iter()
                    .all(|item| item.control_id != "AID-H-031.002"),
                "AI-system applicability alone must not imply AI-generated code"
            );

            let both = lookup("semgrep", source_rule, true, true);
            assert!(
                both.iter().any(|item| item.control_id == "AID-H-031.002"),
                "an explicit AI-generated-artifact answer enables the reviewed coordinate"
            );
        }

        let generated_private_key = lookup(
            "semgrep",
            "ai-security-scanner.generic.private-key",
            false,
            true,
        );
        assert!(
            generated_private_key
                .iter()
                .any(|item| item.control_id == "AID-H-031.002")
        );
    }

    #[test]
    fn every_catalog_rationale_has_a_traditional_chinese_presentation() {
        let parsed: MappingCatalog =
            serde_json::from_str(CATALOG_JSON).expect("embedded control mapping catalog");
        // A lower bound, not the catalog's size: the pinned hash guards the
        // entry list, and this test should fail only for a missing translation.
        assert!(parsed.entries.len() >= 20, "{}", parsed.entries.len());
        for entry in parsed.entries {
            assert!(
                crate::finding_narrative::control_mapping_rationale_zh_hant(&entry.rationale)
                    .is_some(),
                "no Traditional Chinese for catalog rationale: {}",
                entry.rationale
            );
        }
    }

    /// The shape census above reads the entries that exist, so it is blind to
    /// an engine with none. Greenbone shipped that way: it produced real
    /// vulnerability findings while every framework relationship for the
    /// internal-host path was silently empty. Ask the producer side instead —
    /// every engine whose results become security findings must be represented.
    ///
    /// The exemptions are the six engines whose output is inventory rather
    /// than findings (`beginner_report::task_result_kind`). They are excluded
    /// by name so that adding an engine to that list is a visible decision.
    #[test]
    fn every_finding_producing_engine_has_at_least_one_mapping_entry() {
        const INVENTORY_ONLY: [&str; 6] = [
            "cloudquery",
            "steampipe",
            "syft",
            "naabu",
            "httpx",
            "agentic-radar",
        ];
        let catalog = catalog().expect("embedded control mapping catalog");
        let mapped = catalog
            .entries
            .iter()
            .map(|entry| entry.engine_id.as_str())
            .collect::<BTreeSet<_>>();
        let unmapped = ENGINES
            .iter()
            .copied()
            .filter(|engine| !INVENTORY_ONLY.contains(engine) && !mapped.contains(engine))
            .collect::<Vec<_>>();
        assert!(
            unmapped.is_empty(),
            "these engines produce security findings with no control mapping, so their \
             findings reach the framework report with no NIST, ISO, or AIDEFEND \
             relationship at all: {unmapped:?}"
        );
    }

    #[test]
    fn unknown_or_observation_rules_are_not_guessed() {
        assert!(lookup("prowler", "new-unknown-check", false, false).is_empty());
        assert!(lookup("httpx", "http-service-observed", false, false).is_empty());
        assert!(lookup("naabu", "open-tcp-port", false, false).is_empty());
    }

    #[test]
    fn catalog_rejects_invalid_calendar_dates_historical_order_and_digest_mismatch() {
        let mut invalid_mapping_date = catalog_fixture();
        invalid_mapping_date["mapping_version"] = Value::String("2026-02-30.1".into());
        let error =
            parse_and_validate_json(&catalog_json_with_recalculated_digest(invalid_mapping_date))
                .unwrap_err();
        assert!(error.contains("real YYYY-MM-DD calendar date"));

        let mut invalid_review_date = catalog_fixture();
        invalid_review_date["provenance"]["reviewed_at"] = Value::String("2026-02-30".into());
        let error =
            parse_and_validate_json(&catalog_json_with_recalculated_digest(invalid_review_date))
                .unwrap_err();
        assert!(error.contains("real YYYY-MM-DD calendar date"));

        let mut predating_review = catalog_fixture();
        // Derive the version date from the catalog's own review date so this
        // stays a real ordering violation after any future review bump, rather
        // than quietly becoming a valid catalog that asserts nothing.
        let day_after_review = NaiveDate::parse_from_str(
            predating_review["provenance"]["reviewed_at"]
                .as_str()
                .expect("catalog review date"),
            "%Y-%m-%d",
        )
        .expect("catalog review date is a real calendar date")
        .succ_opt()
        .expect("a day after the catalog review date");
        predating_review["mapping_version"] =
            Value::String(format!("{}.1", day_after_review.format("%Y-%m-%d")));
        let error =
            parse_and_validate_json(&catalog_json_with_recalculated_digest(predating_review))
                .unwrap_err();
        assert!(error.contains("cannot predate"));

        let mut digest_mismatch = catalog_fixture();
        digest_mismatch["entries"][0]["rationale"] = Value::String(
            "Changed relationship text that must invalidate the canonical digest.".into(),
        );
        let error = parse_and_validate_json(
            &serde_json::to_string(&digest_mismatch).expect("digest mismatch JSON"),
        )
        .unwrap_err();
        assert!(error.contains("canonical SHA-256 mismatch"));
    }

    #[test]
    fn catalog_control_coordinates_remain_unique_even_when_titles_match() {
        let mut duplicate = catalog_fixture();
        let mut alias = duplicate["controls"][0].clone();
        alias["key"] = Value::String("nist-id-ra-01-alias".into());
        duplicate["controls"]
            .as_array_mut()
            .expect("controls array")
            .push(alias);
        let error =
            parse_and_validate_json(&catalog_json_with_recalculated_digest(duplicate)).unwrap_err();
        assert!(error.contains("duplicate framework coordinate"));
    }

    #[test]
    fn catalog_rejects_more_cwe_derived_controls_than_the_schema_allows() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../mappings/control-mappings.schema.json"
        ))
        .expect("control mapping schema JSON");
        assert_eq!(
            schema["properties"]["cwe_derived_controls"]["maxItems"].as_u64(),
            Some(MAX_CWE_DERIVED_CONTROLS as u64),
            "Rust and JSON Schema must enforce the same CWE-derived control limit"
        );

        let mut oversized = catalog_fixture();
        let derived = oversized["cwe_derived_controls"]
            .as_array()
            .and_then(|entries| entries.first())
            .expect("embedded catalog has a CWE-derived mapping")
            .clone();
        oversized["cwe_derived_controls"] =
            Value::Array(vec![derived; MAX_CWE_DERIVED_CONTROLS + 1]);

        let error =
            parse_and_validate_json(&catalog_json_with_recalculated_digest(oversized)).unwrap_err();
        assert_eq!(error, "CWE-derived mappings exceed the 1024-control limit");
    }
}
