//! Typed, immutable input selection for MCP Armor's configuration-only mode.
//!
//! Discovery is bounded to repository-relative configuration filenames. A
//! selection is not authorization: the existing `LocalArtifactRead` grant
//! still authorizes the immutable repository snapshot. These records only
//! prevent the launcher from discovering or substituting another file.

use crate::domain::{Asset, AssetIdentifier, AssetKind};
use crate::error::{AppError, AppResult};
use crate::workspace_snapshot::{WorkspaceSnapshotFile, WorkspaceSnapshotManifest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub const MCP_ARMOR_ENGINE_ID: &str = "mcp-armor";
pub const MCP_CONFIGURATION_PATH_NAMESPACE: &str =
    "ai-security-scanner:mcp-configuration-relative-path";
pub const MCP_CONFIGURATION_SHA256_NAMESPACE: &str = "ai-security-scanner:mcp-configuration-sha256";
pub const MCP_CONFIGURATION_CANDIDATES_METADATA_KEY: &str = "mcp_configuration_candidates";
pub const MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY: &str =
    "mcp_configuration_discovery_complete";
pub const MCP_CONFIGURATION_SELECTED_METADATA_KEY: &str = "mcp_configuration_selected";
pub const MAX_MCP_CONFIGURATION_CANDIDATES: usize = 64;
pub const MAX_MCP_CONFIGURATION_BYTES: u64 = 10 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpConfigurationCandidate {
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpConfigurationDiscovery {
    pub candidates: Vec<McpConfigurationCandidate>,
    pub complete: bool,
}

pub fn discover_mcp_configurations(
    manifest: &WorkspaceSnapshotManifest,
) -> McpConfigurationDiscovery {
    let mut candidates = manifest
        .files
        .iter()
        .filter(|file| {
            file.byte_length <= MAX_MCP_CONFIGURATION_BYTES
                && is_mcp_configuration_relative_path(&file.relative_path)
        })
        .map(candidate_from_file)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    candidates.dedup_by(|left, right| left.relative_path == right.relative_path);
    let complete = candidates.len() <= MAX_MCP_CONFIGURATION_CANDIDATES;
    if !complete {
        candidates.clear();
    }
    McpConfigurationDiscovery {
        candidates,
        complete,
    }
}

pub fn annotate_repository_asset(
    asset: &mut Asset,
    manifest: &WorkspaceSnapshotManifest,
) -> AppResult<()> {
    if asset.kind != AssetKind::Repository {
        return Ok(());
    }
    let discovery = discover_mcp_configurations(manifest);
    asset.metadata.insert(
        MCP_CONFIGURATION_CANDIDATES_METADATA_KEY.into(),
        serde_json::to_value(&discovery.candidates)?,
    );
    asset.metadata.insert(
        MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY.into(),
        Value::Bool(discovery.complete),
    );
    clear_selection(asset);
    if discovery.complete && discovery.candidates.len() == 1 {
        write_selection(asset, &discovery.candidates[0])?;
    }
    Ok(())
}

pub fn select_mcp_configuration(
    asset: &mut Asset,
    manifest: &WorkspaceSnapshotManifest,
    relative_path: &str,
) -> AppResult<McpConfigurationCandidate> {
    if asset.kind != AssetKind::Repository {
        return Err(AppError::InvalidRequest(
            "MCP configuration selection requires a repository snapshot".into(),
        ));
    }
    let discovery = discover_mcp_configurations(manifest);
    if !discovery.complete {
        return Err(AppError::InvalidRequest(format!(
            "repository contains more than {MAX_MCP_CONFIGURATION_CANDIDATES} MCP configuration candidates"
        )));
    }
    let selected = discovery
        .candidates
        .into_iter()
        .find(|candidate| candidate.relative_path == relative_path)
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "selected MCP configuration is not an exact candidate in the immutable snapshot"
                    .into(),
            )
        })?;
    asset.metadata.insert(
        MCP_CONFIGURATION_CANDIDATES_METADATA_KEY.into(),
        serde_json::to_value(&discover_mcp_configurations(manifest).candidates)?,
    );
    asset.metadata.insert(
        MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY.into(),
        Value::Bool(true),
    );
    clear_selection(asset);
    write_selection(asset, &selected)?;
    Ok(selected)
}

/// Why MCP Armor cannot bind a repository asset yet. Distinct from ownership
/// and permission: those grants already authorized the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpConfigurationPlanStatus {
    Selected,
    /// Discovery finished and found no configuration file.
    Absent,
    /// Discovery finished with more than one candidate and none is selected.
    Unselected,
    /// Discovery did not finish, so absence was never established.
    DiscoveryIncomplete,
}

pub fn mcp_configuration_plan_status(asset: &Asset) -> McpConfigurationPlanStatus {
    if selected_mcp_configuration(asset).ok().flatten().is_some() {
        return McpConfigurationPlanStatus::Selected;
    }
    let complete = asset
        .metadata
        .get(MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !complete {
        return McpConfigurationPlanStatus::DiscoveryIncomplete;
    }
    match candidates_from_asset(asset) {
        Ok(candidates) if candidates.is_empty() => McpConfigurationPlanStatus::Absent,
        Ok(_) => McpConfigurationPlanStatus::Unselected,
        Err(_) => McpConfigurationPlanStatus::DiscoveryIncomplete,
    }
}

pub fn selected_mcp_configuration(asset: &Asset) -> AppResult<Option<McpConfigurationCandidate>> {
    let paths = exact_identifier_values(asset, MCP_CONFIGURATION_PATH_NAMESPACE);
    let digests = exact_identifier_values(asset, MCP_CONFIGURATION_SHA256_NAMESPACE);
    if paths.is_empty() && digests.is_empty() {
        return Ok(None);
    }
    if paths.len() != 1 || digests.len() != 1 {
        return Err(AppError::InvalidRequest(
            "repository asset has an ambiguous MCP configuration selection".into(),
        ));
    }
    let relative_path = paths[0].to_owned();
    let sha256 = digests[0].to_owned();
    if !is_mcp_configuration_relative_path(&relative_path) || !valid_sha256(&sha256) {
        return Err(AppError::InvalidRequest(
            "repository asset has a malformed MCP configuration selection".into(),
        ));
    }
    let candidates = candidates_from_asset(asset)?;
    let Some(candidate) = candidates
        .into_iter()
        .find(|candidate| candidate.relative_path == relative_path && candidate.sha256 == sha256)
    else {
        return Err(AppError::InvalidRequest(
            "repository asset MCP selection is not bound to its candidate ledger".into(),
        ));
    };
    if asset
        .metadata
        .get(MCP_CONFIGURATION_SELECTED_METADATA_KEY)
        .and_then(Value::as_str)
        != Some(candidate.relative_path.as_str())
    {
        return Err(AppError::InvalidRequest(
            "repository asset MCP selection metadata disagrees with its identifiers".into(),
        ));
    }
    Ok(Some(candidate))
}

pub fn verify_mcp_configuration_selection(
    asset: &Asset,
    manifest: &WorkspaceSnapshotManifest,
) -> AppResult<McpConfigurationCandidate> {
    let selected = selected_mcp_configuration(asset)?.ok_or_else(|| {
        AppError::NotAuthorized(
            "MCP Armor requires one exact configuration file selected from the repository snapshot"
                .into(),
        )
    })?;
    let manifest_entry = manifest
        .files
        .iter()
        .find(|file| file.relative_path == selected.relative_path)
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "selected MCP configuration is absent from the verified repository snapshot".into(),
            )
        })?;
    if manifest_entry.sha256 != selected.sha256
        || manifest_entry.byte_length != selected.byte_length
        || manifest_entry.byte_length > MAX_MCP_CONFIGURATION_BYTES
    {
        return Err(AppError::NotAuthorized(
            "selected MCP configuration differs from its verified snapshot evidence".into(),
        ));
    }
    Ok(selected)
}

pub fn candidates_from_asset(asset: &Asset) -> AppResult<Vec<McpConfigurationCandidate>> {
    let complete = asset
        .metadata
        .get(MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let candidates = asset
        .metadata
        .get(MCP_CONFIGURATION_CANDIDATES_METADATA_KEY)
        .cloned()
        .map(serde_json::from_value::<Vec<McpConfigurationCandidate>>)
        .transpose()
        .map_err(|_| {
            AppError::InvalidRequest(
                "repository asset MCP configuration candidate ledger is malformed".into(),
            )
        })?
        .unwrap_or_default();
    if !complete && !candidates.is_empty() {
        return Err(AppError::InvalidRequest(
            "incomplete MCP configuration discovery cannot expose candidates".into(),
        ));
    }
    if candidates.len() > MAX_MCP_CONFIGURATION_CANDIDATES {
        return Err(AppError::InvalidRequest(
            "repository asset MCP configuration candidate ledger is unbounded".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    for candidate in &candidates {
        if !paths.insert(candidate.relative_path.as_str())
            || !is_mcp_configuration_relative_path(&candidate.relative_path)
            || !valid_sha256(&candidate.sha256)
            || candidate.byte_length > MAX_MCP_CONFIGURATION_BYTES
        {
            return Err(AppError::InvalidRequest(
                "repository asset MCP configuration candidate ledger is invalid".into(),
            ));
        }
    }
    Ok(candidates)
}

pub fn is_mcp_configuration_relative_path(relative_path: &str) -> bool {
    if relative_path.is_empty()
        || relative_path.len() > MAX_RELATIVE_PATH_BYTES
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains('\0')
    {
        return false;
    }
    let path = Path::new(relative_path);
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::CurDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return false;
    }
    let components = relative_path.split('/').collect::<Vec<_>>();
    if components.iter().any(|component| component.is_empty()) {
        return false;
    }
    let filename = components
        .last()
        .copied()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parent = components
        .get(components.len().saturating_sub(2))
        .copied()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        (parent.as_str(), filename.as_str()),
        (".cursor", "mcp.json")
            | (".vscode", "mcp.json")
            | (".gemini", "settings.json")
            | (".claude", "settings.json")
    ) {
        return true;
    }
    filename == "mcp.json"
        || filename == "mcp_servers.json"
        || matches_mcp_glob(&filename, ".json")
        || matches_mcp_glob(&filename, ".yaml")
        || matches_mcp_glob(&filename, ".yml")
}

fn matches_mcp_glob(filename: &str, extension: &str) -> bool {
    filename.ends_with(extension)
        && (filename.starts_with("mcp") || filename.ends_with(&format!(".mcp{extension}")))
}

fn candidate_from_file(file: &WorkspaceSnapshotFile) -> McpConfigurationCandidate {
    McpConfigurationCandidate {
        relative_path: file.relative_path.clone(),
        sha256: file.sha256.clone(),
        byte_length: file.byte_length,
    }
}

fn exact_identifier_values<'a>(asset: &'a Asset, namespace: &str) -> Vec<&'a str> {
    asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == namespace)
        .map(|identifier| identifier.value.as_str())
        .collect()
}

fn clear_selection(asset: &mut Asset) {
    asset.identifiers.retain(|identifier| {
        identifier.namespace != MCP_CONFIGURATION_PATH_NAMESPACE
            && identifier.namespace != MCP_CONFIGURATION_SHA256_NAMESPACE
    });
    asset
        .metadata
        .remove(MCP_CONFIGURATION_SELECTED_METADATA_KEY);
}

fn write_selection(asset: &mut Asset, selected: &McpConfigurationCandidate) -> AppResult<()> {
    if !is_mcp_configuration_relative_path(&selected.relative_path)
        || !valid_sha256(&selected.sha256)
    {
        return Err(AppError::InvalidRequest(
            "MCP configuration selection is malformed".into(),
        ));
    }
    asset.identifiers.push(AssetIdentifier {
        namespace: MCP_CONFIGURATION_PATH_NAMESPACE.into(),
        value: selected.relative_path.clone(),
    });
    asset.identifiers.push(AssetIdentifier {
        namespace: MCP_CONFIGURATION_SHA256_NAMESPACE.into(),
        value: selected.sha256.clone(),
    });
    asset.metadata.insert(
        MCP_CONFIGURATION_SELECTED_METADATA_KEY.into(),
        Value::String(selected.relative_path.clone()),
    );
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AssetKind, LocalInputProfile};
    use crate::workspace_snapshot::WorkspaceSnapshotManifest;
    use std::collections::BTreeMap;

    fn manifest(files: &[(&str, &str)]) -> WorkspaceSnapshotManifest {
        let files = files
            .iter()
            .map(|(relative_path, digest)| WorkspaceSnapshotFile {
                relative_path: (*relative_path).into(),
                byte_length: 20,
                sha256: (*digest).into(),
            })
            .collect::<Vec<_>>();
        WorkspaceSnapshotManifest {
            schema_version: "1".into(),
            content_semantics: "working_tree".into(),
            input_profile: LocalInputProfile::RepositoryWorkingTree,
            exclusion_policy: None,
            excluded_entries: vec![],
            exclusions: vec![],
            ignore_rule_sources: vec![],
            directories: vec![],
            directory_count: 0,
            file_count: files.len(),
            total_bytes: files.iter().map(|file| file.byte_length).sum(),
            files,
        }
    }

    fn asset() -> Asset {
        Asset {
            id: "asset-1".into(),
            kind: AssetKind::Repository,
            name: "fixture".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec!["source-1".into()],
            candidate: true,
            owner_confirmed: false,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn one_candidate_is_selected_without_a_second_beginner_question() {
        let digest = "a".repeat(64);
        let manifest = manifest(&[(".cursor/mcp.json", &digest), ("src/main.ts", &digest)]);
        let mut asset = asset();
        annotate_repository_asset(&mut asset, &manifest).unwrap();
        let selected = verify_mcp_configuration_selection(&asset, &manifest).unwrap();
        assert_eq!(selected.relative_path, ".cursor/mcp.json");
        assert_eq!(selected.sha256, digest);
    }

    #[test]
    fn multiple_candidates_require_one_explicit_typed_choice() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let manifest = manifest(&[
            ("mcp.json", &first),
            ("apps/agent/service.mcp.yaml", &second),
        ]);
        let mut asset = asset();
        annotate_repository_asset(&mut asset, &manifest).unwrap();
        assert!(selected_mcp_configuration(&asset).unwrap().is_none());
        let selected =
            select_mcp_configuration(&mut asset, &manifest, "apps/agent/service.mcp.yaml").unwrap();
        assert_eq!(selected.sha256, second);
        verify_mcp_configuration_selection(&asset, &manifest).unwrap();
    }

    #[test]
    fn arbitrary_json_and_tampered_selection_fail_closed() {
        let digest = "a".repeat(64);
        let manifest = manifest(&[("package.json", &digest), ("mcp.json", &digest)]);
        let discovered = discover_mcp_configurations(&manifest);
        assert_eq!(discovered.candidates.len(), 1);
        let mut asset = asset();
        annotate_repository_asset(&mut asset, &manifest).unwrap();
        asset
            .identifiers
            .iter_mut()
            .find(|identifier| identifier.namespace == MCP_CONFIGURATION_SHA256_NAMESPACE)
            .unwrap()
            .value = "b".repeat(64);
        assert!(verify_mcp_configuration_selection(&asset, &manifest).is_err());
    }
}
