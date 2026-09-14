import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import assert from "node:assert/strict";

const load = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
const sha256 = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

test("MCP Armor local image remains offline, non-root, and unpublished", async () => {
  const [catalogText, planText, dockerfile, requirements, patch, launcher, scopeText, input] = await Promise.all([
    load("engines/catalog.json"),
    load("engines/images/mcp-armor/plan.json"),
    load("engines/images/mcp-armor/Dockerfile"),
    load("engines/images/mcp-armor/requirements.lock"),
    load("docs/research/patches/mcp-armor-1.0.2-config-only.patch"),
    load("engines/images/mcp-armor/launcher/main.go"),
    load("engines/images/mcp-armor/testdata/scope.json"),
    load("engines/images/mcp-armor/testdata/workspace/mcp.json"),
  ]);
  const engine = JSON.parse(catalogText).find((entry) => entry.id === "mcp-armor");
  const plan = JSON.parse(planText);
  assert.equal(engine.compatibility.runnable, false);
  assert.equal(engine.status, "experimental");
  assert.equal(engine.image, null);
  assert.equal(plan.publish_state, "managed_artifact_not_published");
  assert.deepEqual(plan.final_artifact, {
    repository: "ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor",
    tag: null,
    digest: null,
  });
  assert.equal(plan.blockers.length, 1);
  assert.match(plan.blockers[0], /not been published/u);
  assert.equal(plan.dockerfile.sha256, sha256(dockerfile));
  assert.equal(plan.build_recipe.dependency_lock.sha256, sha256(requirements));
  assert.equal(plan.build_recipe.source_patch.sha256, sha256(patch));
  assert.equal(plan.wrapper.launcher_sha256, sha256(launcher));
  const scope = JSON.parse(scopeText);
  const inputDigest = scope.assets[0].identifiers.find(({ namespace }) => (
    namespace === "ai-security-scanner:mcp-configuration-sha256"
  ));
  assert.equal(inputDigest.value, sha256(input).replace("sha256:", ""));
  const syntheticInput = JSON.parse(input);
  assert.deepEqual(syntheticInput.mcpServers["fixture-safe"].permissions, ["terminal:exec"]);
  assert.match(plan.local_build_evidence.result, /one excessive-permission finding/u);
  assert.equal(plan.managed_runtime.network_mode, "disabled");
  assert.equal(plan.managed_runtime.non_root_user, "65532:65532");
  assert.match(dockerfile, /USER 65532:65532/u);
  assert.match(dockerfile, /--require-hashes/u);
  assert.match(dockerfile, /--only-binary=:all:/u);
  for (const absent of ["fastmcp==", "thefuzz==", "transformers==", "torch=="]) {
    assert.equal(requirements.toLowerCase().includes(absent), false, absent);
  }
});

test("MCP Armor production path binds one exact snapshot file before invocation", async () => {
  const [rust, launcher, commands, coverage, service] = await Promise.all([
    load("src-tauri/src/mcp_armor_input.rs"),
    load("engines/images/mcp-armor/launcher/main.go"),
    load("src-tauri/src/commands.rs"),
    load("src/pages/CoveragePage.tsx"),
    load("src/services/scanner.ts"),
  ]);
  const pathNamespace = "ai-security-scanner:mcp-configuration-relative-path";
  const digestNamespace = "ai-security-scanner:mcp-configuration-sha256";
  for (const value of [pathNamespace, digestNamespace]) {
    assert.ok(rust.includes(value), value);
    assert.ok(launcher.includes(value), value);
  }
  assert.match(rust, /MAX_MCP_CONFIGURATION_BYTES: u64 = 10 \* 1024 \* 1024/u);
  assert.match(rust, /candidates\.len\(\) == 1/u);
  assert.match(rust, /selected MCP configuration differs from its verified snapshot evidence/u);
  assert.match(commands, /verify_mcp_configuration_selection\(asset, &resolved\.manifest\)/u);
  assert.match(launcher, /"--config-only"/u);
  assert.match(launcher, /requireReadOnlyWorkspace/u);
  assert.match(launcher, /verifySelectedConfiguration/u);
  assert.match(launcher, /validateTerminalEvidence/u);
  assert.match(coverage, /manifest\.id === "mcp-armor" && manifest\.runnable === true/u);
  assert.match(coverage, /asset\.selectedMcpConfiguration/u);
  assert.match(coverage, /mcpSelectionRequired/u);
  assert.match(coverage, /!externalScopeReady \|\| mcpSelectionRequired/u);
  assert.match(service, /selectMcpConfiguration: "select_mcp_configuration"/u);
});
