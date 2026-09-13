import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));

const CURRENT_PRODUCT_DOCUMENTS = [
  "AGENTS.md",
  "CLAUDE.md",
  "README.md",
  "README.zh-TW.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "THIRD_PARTY.md",
  ".codex/skills/ai-security-scanner/SKILL.md",
  ".claude/skills/ai-security-scanner/SKILL.md",
  "mappings/README.md",
  "docs/README.md",
  "docs/README.zh-TW.md",
  "docs/architecture.md",
  "docs/engine-catalog.md",
  "docs/engine-maintenance.md",
  "docs/managed-runtime.md",
  "docs/product-audit.md",
  "docs/product-spec.md",
  "docs/provider-authorization.md",
  "docs/getting-started.md",
  "docs/getting-started.zh-TW.md",
  "docs/scanning-scope.md",
  "docs/scanning-scope.zh-TW.md",
  "docs/results-and-exports.md",
  "docs/results-and-exports.zh-TW.md",
  "docs/releasing.md",
  "docs/releasing.zh-TW.md",
  "docs/release/README.md",
  "docs/release/engine-image-supply-chain.md",
  "docs/research/agentic-radar-upstream-drafts.md",
  "docs/research/agentic-radar-evaluation.md",
  "docs/research/augustus-evaluation.md",
  "docs/research/fixtures/agentic-radar/README.md",
  "docs/research/fixtures/augustus/README.md",
  "docs/research/fixtures/mcp-armor/README.md",
  "docs/research/mcp-armor-evaluation.md",
  "docs/research/vibescan-evaluation.md",
  "docs/threat-model.md",
  "docs/usability/iam-naive-first-run.md",
];

async function load(relativePath) {
  return readFile(path.join(REPOSITORY_ROOT, relativePath), "utf8");
}

const AGENTIC_RADAR_RESEARCH_FIXTURES = {
  "autogen.json": [
    "autogen",
    "workflow_found",
    true,
    "640bc21afd1f7d3f588d68c38c188be922ee2be626e73fc2530207c25fd1b34e",
  ],
  "crewai.json": [
    "crewai",
    "workflow_found",
    false,
    "f8c7db002564e9968ac39cad5bd8a48b945190428a14acfa4d1446c1a02a47a8",
  ],
  "langgraph.json": [
    "langgraph",
    "workflow_found",
    true,
    "62e9fb05cd4d6896359f2c1fc8179358ba74a31c98ec5506f3caaebd568fe046",
  ],
  "n8n.json": [
    "n8n",
    "workflow_found",
    true,
    "303b48d29c05c8b5020e77964c3c43080f201abac2d5cb7697f6c29800e2c275",
  ],
  "no-supported-workflow.json": [
    "langgraph",
    "no_supported_workflow",
    true,
    "5c243e84dbb28ec1142a1335cea56519a0f415c43c45de8fb710d6098d103618",
  ],
  "openai-agents.json": [
    "openai-agents",
    "workflow_found",
    true,
    "f344d79b24d604a2ea24a216e273da766d6d309fe857fcf2d3a2812e57611127",
  ],
};
const AGENTIC_RADAR_RESEARCH_PATCH_SHA256 =
  "d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72";
const AUGUSTUS_RESEARCH_PATCH_SHA256 =
  "4f6c1e0d16014ac2a638ec50ebbab053b7a3c6a7320911fbff14b8541f45b59a";
const AUGUSTUS_RESEARCH_PROFILE_SHA256 =
  "9dedd3695cd38575ba4137754803e50114c5a0f868a0f71ce5fd6305377e55b4";
const AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256 =
  "cd212569b48ad8186df0924cf0c86b2cbcac9bb7cb9a1bd71e1faed8a85240df";
const AUGUSTUS_RESEARCH_FIXTURES = {
  "machine-complete.json": [
    true,
    [],
    "8482446756cdcd079d8349aa5ac4c828092e7ec4236dae3b43ea5d7f0921f52b",
  ],
  "machine-count-mismatch.json": [
    false,
    ["count_mismatch"],
    "d94b8616c134194f7c8a0ce11e2d2167fd611a4b1117c067347cd4d006eade19",
  ],
  "machine-detector-warning.json": [
    false,
    ["detector_failed"],
    "1fc37120cb27660f1958f30f6ccdbd03aa5d64ff446e637aff671d81342dd2f7",
  ],
};
const MCP_ARMOR_RESEARCH_PATCH_SHA256 =
  "ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122";
const MCP_ARMOR_RESEARCH_FIXTURES = {
  "config-clean.json": [true, "7df09184de483652621090124e0b5aa593ad08552a3fe4527865b0712f78742f"],
  "config-disabled.json": [true, "1932bd98c099da927f00f4e6c94f2dbbe9a8eb3d87c5039d0b60a0561f0c5550"],
  "config-findings.json": [true, "8a94b0b7aa717b106896bf3e86c5da063ab5f8023fcff2b97cac85990a72cffa"],
  "config-partial.json": [false, "804519c14a8e265ef82010c5836a7354aa23732273bf9a3a2e3e487957258669"],
};

function localMarkdownTargets(markdown) {
  const targets = [];
  const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/g;
  for (const match of markdown.matchAll(linkPattern)) {
    let target = match[1].trim();
    if (target.startsWith("<")) {
      target = target.slice(1, target.indexOf(">"));
    } else {
      target = target.split(/\s+["']/u, 1)[0];
    }
    if (target === "" || target.startsWith("#") || /^(?:https?:|mailto:)/iu.test(target)) continue;
    targets.push(decodeURIComponent(target.split("#", 1)[0]));
  }
  return targets;
}

test("the product specification records the owner's five product decisions", async () => {
  const specification = await load("docs/product-spec.md");

  assert.match(specification, /beginner quickly completes a meaningful scan and understands the result/i);
  assert.match(specification, /integrations stay as close to upstream behavior as practical/i);
  assert.match(specification, /one professional, product-owned report/i);
  assert.match(
    specification,
    /Versioning, publication, certification, and compliance positioning belong to the product owner/i,
  );
  assert.match(specification, /concise first and detailed on demand/i);
  assert.match(specification, /socket connection.*not a vulnerability scan/is);
});

test("Codex, Claude, contributors, and the operator skill use the same priorities", async () => {
  for (const document of [
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    ".codex/skills/ai-security-scanner/SKILL.md",
    ".claude/skills/ai-security-scanner/SKILL.md",
  ]) {
    const content = await load(document);
    assert.match(content, /meaningful (?:security )?scan/i, `${document} must prioritize a meaningful scan`);
    assert.match(content, /upstream/i, `${document} must preserve upstream scanner meaning`);
    assert.match(content, /professional report|shared report/i, `${document} must use the shared report layer`);
    assert.match(content, /product owner|product-owner/i, `${document} must preserve owner authority`);
    assert.match(content, /unless the (?:product )?owner explicitly requests/i, `${document} must not invent release work`);
    assert.match(content, /active work stays in Progress|active scans remain in Progress|keep active work in Progress/i, `${document} must keep active scans out of reports`);
    assert.match(content, /defensive caveat walls/i, `${document} must keep defensive prose out of the primary path`);
  }

  assert.equal(
    await load(".codex/skills/ai-security-scanner/SKILL.md"),
    await load(".claude/skills/ai-security-scanner/SKILL.md"),
    "Codex and Claude must operate the product with identical guidance",
  );
});

test("beginner documentation leads with the three scan paths and one report", async () => {
  const english = await load("README.md");
  const chinese = await load("README.zh-TW.md");

  for (const content of [english, chinese]) {
    assert.match(content, /website|網站/iu);
    assert.match(content, /project|專案/iu);
    assert.match(content, /report|報告/iu);
    assert.match(content, /TCP/u);
    assert.match(content, /Nuclei/u);
    assert.match(content, /read-only|唯讀/u);
    assert.match(content, /internal system|內部系統/iu);
    assert.match(content, /Start scan|開始掃描/u);
    assert.match(content, /scanning-scope(?:\.zh-TW)?\.md/u);
  }
  assert.match(english, /One report for every selected asset/u);
  assert.match(chinese, /所有資產集中在一份報告/u);
});

test("scope documentation keeps exact website and connectivity boundaries in technical detail", async () => {
  const english = await load("docs/scanning-scope.md");
  const chinese = await load("docs/scanning-scope.zh-TW.md");

  for (const content of [english, chinese]) {
    assert.match(content, /scheme:\/\/host:port/u);
    assert.match(content, /Nuclei/u);
    assert.match(content, /read-only|唯讀/u);
    assert.match(content, /follow redirects|跟隨重新導向/u);
    assert.match(content, /127\.0\.0\.1:9001/u);
    assert.match(content, /not a vulnerability scan|不是弱點掃描/u);
  }
  assert.match(english, /other paths on the same origin/u);
  assert.match(chinese, /同一 origin 內的其他 path/u);
});

test("release records and optional mappings do not choose the roadmap", async () => {
  const releaseIndex = await load("docs/release/README.md");
  assert.match(releaseIndex, /historical release records/i);
  assert.match(releaseIndex, /not the product roadmap/i);
  assert.match(releaseIndex, /product owner controls version numbers, release timing/is);

  const mappings = await load("mappings/README.md");
  assert.match(mappings, /optional/i);
  assert.match(mappings, /not a compliance result|不是合規結果/i);
});

test("current product documents do not contain broken local Markdown links", async () => {
  for (const document of CURRENT_PRODUCT_DOCUMENTS) {
    const content = await load(document);
    const documentDirectory = path.dirname(path.join(REPOSITORY_ROOT, document));
    for (const target of localMarkdownTargets(content)) {
      const resolved = path.resolve(documentDirectory, target);
      assert.ok(
        resolved === REPOSITORY_ROOT || resolved.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
        `${document} has a local link outside the repository: ${target}`,
      );
      await assert.doesNotReject(stat(resolved), `${document} has a broken local Markdown link: ${target}`);
    }
  }
});

test("Augustus research keeps hosted model testing fail closed", async () => {
  const decision = await load("docs/research/augustus-evaluation.md");
  const patchContent = await load("docs/research/patches/augustus-0.14.29-machine-json.patch");
  const profileContent = await load("docs/research/augustus-single-destination-profile.json");
  const enforcementContent = await load(
    "docs/research/augustus-launcher-egress-enforcement.json",
  );
  const profile = JSON.parse(profileContent);
  const enforcement = JSON.parse(enforcementContent);

  assert.match(decision, /f032fc6373aaa9983868282b31dc9c59503c78a2/u);
  assert.match(decision, /tagged `v0\.14\.29`/u);
  assert.match(decision, /RESEARCH \/ NOT_DISTRIBUTED/u);
  assert.match(decision, /Do not add Augustus to the engine\s+catalog or adapter registry/u);
  assert.match(decision, /rest\.Rest.*out of scope/su);
  assert.match(decision, /SkipOnError/su);
  assert.match(decision, /complete: false/u);
  assert.match(decision, /test\.Repeat/u);
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_PATCH_SHA256, "u"));
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_PROFILE_SHA256, "u"));
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256, "u"));
  assert.match(decision, /13c96bc6a36f880e7f016e02da63eadd64b73674/u);
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    AUGUSTUS_RESEARCH_PATCH_SHA256,
  );
  assert.match(patchContent, /machine-json/u);
  assert.match(patchContent, /detector_failed/u);
  assert.match(patchContent, /count_mismatch/u);
  assert.match(patchContent, /test\.Repeat/u);
  assert.match(patchContent, /func \(h \*hijackProbe\) ExpectedAttempts\(\) int/u);
  assert.match(patchContent, /TestHijackLongPromptMachinePlanHasExactAttemptCount/u);
  assert.match(patchContent, /testgenerator\.NewRepeat/u);
  assert.match(patchContent, /func \(sw \*StreamWriter\) Append\(a \*attempt\.Attempt\) error/u);
  assert.match(patchContent, /sw\.file\.Sync\(\)/u);
  assert.equal(
    createHash("sha256").update(profileContent).digest("hex"),
    AUGUSTUS_RESEARCH_PROFILE_SHA256,
  );
  assert.equal(profile.schema_version, "1");
  assert.equal(profile.profile_id, "augustus-openai-promptinject-v1");
  assert.equal(profile.normative_status, "research_only_blocked");
  assert.equal(profile.source_revision, "f032fc6373aaa9983868282b31dc9c59503c78a2");
  assert.equal(profile.machine_patch_sha256, AUGUSTUS_RESEARCH_PATCH_SHA256);
  assert.equal(
    createHash("sha256").update(enforcementContent).digest("hex"),
    AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256,
  );
  assert.equal(enforcement.schema_version, "1");
  assert.equal(enforcement.normative_status, "research_only_blocked");
  assert.equal(enforcement.profile_id, profile.profile_id);
  assert.equal(enforcement.profile_sha256, AUGUSTUS_RESEARCH_PROFILE_SHA256);
  assert.equal(enforcement.dispatch_enabled, false);

  const leafPaths = (value, prefix = "") => {
    if (Array.isArray(value)) {
      if (value.length === 0 || value.every((item) => item === null || typeof item !== "object")) {
        return [`${prefix}[]`];
      }
      return [...new Set(value.flatMap((item) => leafPaths(item, `${prefix}[]`)))];
    }
    if (value !== null && typeof value === "object") {
      return Object.entries(value).flatMap(([key, item]) =>
        leafPaths(item, prefix ? `${prefix}.${key}` : key));
    }
    return [prefix];
  };
  const mappedPaths = enforcement.rules.flatMap(({ profile_fields: fields }) => fields);
  assert.equal(new Set(mappedPaths).size, mappedPaths.length, "each profile field has one owner");
  assert.deepEqual(mappedPaths.toSorted(), leafPaths(profile).toSorted());
  assert.equal(mappedPaths.length, 50);
  assert.deepEqual(
    enforcement.rules.map(({ rule_id: ruleId }) => ruleId),
    [
      "profile_identity_and_provenance",
      "exact_destination_and_model_binding",
      "base_url_and_redirect_denial",
      "single_connection_execution",
      "probe_detector_allowlist",
      "attempt_shape",
      "prompt_corpus_attestation",
      "token_request_and_cost_budget",
      "request_rate_retry_and_timeout",
      "probe_scanner_and_process_deadlines",
      "process_resource_sandbox",
      "response_and_process_output_bounds",
      "denied_capabilities",
      "unresolved_dispatch_blockers",
    ],
  );
  for (const rule of enforcement.rules) {
    assert.ok(rule.profile_fields.length > 0, rule.rule_id);
    assert.ok(rule.required_action.length > 0, rule.rule_id);
    assert.ok(rule.reject_conditions.length > 0, rule.rule_id);
    assert.ok(
      rule.enforcement_points.every((point) => /^(?:typed_launcher|egress_gate)\./u.test(point)),
      rule.rule_id,
    );
  }
  assert.match(enforcement.current_gateway_assessment.decision, /Dispatch remains disabled/u);
  assert.match(
    enforcement.current_gateway_assessment.insufficient_controls.join(" "),
    /TCP connection.*HTTP provider request.*redirect.*token budget.*monetary ceiling/su,
  );
  assert.deepEqual(profile.destination, {
    generator: "openai.OpenAI",
    scheme: "https",
    host: "api.openai.com",
    port: 443,
    api_base_path: "/v1",
    model_binding: "exact_scope_grant",
    custom_base_url_allowed: false,
    redirects_allowed: false,
    maximum_concurrent_connections: 1,
  });
  assert.deepEqual(
    profile.allowlist.map(({ probe, detectors }) => ({ probe, detectors })),
    [{
      probe: "promptinject.HijackLongPrompt",
      detectors: ["promptinject.AttackRogueString"],
    }],
  );
  const allowed = profile.allowlist[0];
  assert.deepEqual(allowed.detector_config, { case_sensitive: false });
  assert.equal(allowed.expected_attempts, 15);
  assert.equal(allowed.turns_per_attempt, 1);
  assert.equal(allowed.generations_per_attempt, 1);
  assert.equal(allowed.tools_allowed, false);
  assert.deepEqual(allowed.prompt_corpus, {
    canonicalization: "UTF-8 JSON array in source order with no insignificant whitespace",
    sha256: "8c8c6136d30d94639587e20101d4716589c282ce4e8941d7766758de421c0278",
    count: 15,
    total_utf8_bytes: 3212,
    maximum_prompt_utf8_bytes: 233,
  });

  const cost = profile.cost_limits;
  assert.equal(cost.maximum_provider_requests, allowed.expected_attempts);
  assert.equal(cost.maximum_total_input_tokens, cost.maximum_input_tokens_per_request * 15);
  assert.equal(cost.maximum_total_output_tokens, cost.maximum_output_tokens_per_request * 15);
  assert.equal(
    cost.maximum_total_tokens,
    cost.maximum_total_input_tokens + cost.maximum_total_output_tokens,
  );
  assert.equal(cost.maximum_estimated_charge_usd_micros, 250000);
  assert.match(cost.pricing_requirement, /Refuse dispatch/u);

  assert.deepEqual(profile.execution_limits, {
    concurrency: 1,
    maximum_requests_per_second: 1,
    scanner_retry_count: 0,
    request_timeout_seconds: 20,
    probe_timeout_seconds: 300,
    scanner_timeout_seconds: 300,
    process_timeout_seconds: 330,
    memory_mib: 512,
    cpu_millis: 1000,
    pids: 128,
    writable_tmp_mib: 16,
    maximum_response_body_bytes: 262144,
    maximum_stdout_bytes: 1048576,
    maximum_stderr_bytes: 1048576,
  });
  for (const denied of [
    "all_other_generators",
    "all_other_probes",
    "all_other_detectors",
    "custom_base_url",
    "redirects",
    "reconnaissance",
    "buffs",
    "runtime_hooks",
    "tools",
    "multi_turn",
    "attacker_or_judge_models",
    "detector_network_access",
    "configuration_files",
    "inline_configuration",
    "wildcards",
    "retries",
  ]) {
    assert.ok(profile.denied_capabilities.includes(denied), denied);
  }
  assert.ok(!profile.dispatch_blockers.some((item) => /ExpectedAttemptCounter/u.test(item)));
  assert.ok(profile.dispatch_blockers.some((item) => /scope-grant/u.test(item)));
  assert.ok(profile.dispatch_blockers.some((item) => /credential-delivery/u.test(item)));

  const fixtures = new Map();
  for (const [name, [expectedComplete, expectedWarnings, expectedSha256]] of Object.entries(
    AUGUSTUS_RESEARCH_FIXTURES,
  )) {
    const content = await load(`docs/research/fixtures/augustus/${name}`);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );
    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "v0.14.29", name);
    assert.equal(fixture.source_revision, "f032fc6373aaa9983868282b31dc9c59503c78a2", name);
    assert.deepEqual(fixture.target, {
      generator: "test.Repeat",
      endpoint: "local://test-repeat",
    });
    assert.equal(fixture.complete, expectedComplete, name);
    assert.deepEqual(fixture.warnings.map(({ code }) => code), expectedWarnings, name);
    assert.equal(fixture.counts.emitted_attempts, fixture.attempts.length, name);
    assert.ok(fixture.attempts.every(({ prompt, response }) => prompt === response), name);
    assert.ok(!/api[_-]?key|bearer |sk-[a-z0-9]/iu.test(content), `${name} contains credential-shaped text`);
    for (const warning of fixture.warnings) {
      assert.ok(["count_mismatch", "detector_failed"].includes(warning.code), name);
      assert.ok(!Object.hasOwn(warning, "message"), `${name} exposes unbounded error text`);
    }

    const counts = fixture.counts;
    const countsComplete =
      counts.expected_probes === fixture.plan.length
      && counts.started_probes === counts.expected_probes
      && counts.completed_probes === counts.expected_probes
      && counts.succeeded_probes === counts.expected_probes
      && counts.failed_probes === 0
      && counts.produced_attempts === counts.expected_attempts
      && counts.processed_attempts === counts.produced_attempts
      && counts.emitted_attempts === counts.produced_attempts
      && counts.not_tested_attempts === 0
      && counts.errored_attempts === 0;
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0 && countsComplete,
      `${name} must fail closed`,
    );
  }

  assert.equal(fixtures.get("machine-complete.json").attempts[0].verdict, "safe");
  assert.equal(fixtures.get("machine-detector-warning.json").attempts[0].verdict, "safe");
  assert.equal(fixtures.get("machine-detector-warning.json").complete, false);
});

test("Agentic Radar research patch and fixtures retain the audited machine-output contract", async () => {
  const patchContent = await load(
    "docs/research/patches/agentic-radar-0.14.1-machine-json.patch",
  );
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    AGENTIC_RADAR_RESEARCH_PATCH_SHA256,
  );
  assert.match(
    await load("docs/research/agentic-radar-evaluation.md"),
    new RegExp(AGENTIC_RADAR_RESEARCH_PATCH_SHA256, "u"),
  );

  const fixtures = new Map();
  for (const [name, [framework, status, complete, expectedSha256]] of Object.entries(
    AGENTIC_RADAR_RESEARCH_FIXTURES,
  )) {
    const relativePath = `docs/research/fixtures/agentic-radar/${name}`;
    const content = await load(relativePath);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );

    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "0.14.1", name);
    assert.equal(fixture.framework, framework, name);
    assert.equal(fixture.status, status, name);
    assert.equal(fixture.complete, complete, name);
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0,
      `${name} must fail closed`,
    );
    for (const warning of fixture.warnings) {
      assert.deepEqual(Object.keys(warning).sort(), ["code", "message"]);
      assert.equal(warning.code, "analyzer_diagnostic");
      assert.equal(typeof warning.message, "string");
      assert.notEqual(warning.message.trim(), "");
    }
    assert.equal(typeof fixture.graph, "object", name);
    for (const record of [...fixture.graph.nodes, ...fixture.graph.tools, ...fixture.graph.agents]) {
      assert.deepEqual(
        record.vulnerabilities,
        [],
        `${name} unexpectedly contains vulnerability claims`,
      );
    }
  }

  const n8n = fixtures.get("n8n.json");
  const n8nNodeNames = new Set(n8n.graph.nodes.map(({ name }) => name));
  assert.ok(
    n8n.graph.tools.every(({ name }) => n8nNodeNames.has(name)),
    "n8n must retain its duplicate tool collection",
  );

  const openAiAgents = fixtures.get("openai-agents.json");
  assert.ok(openAiAgents.graph.agents.some(({ system_prompt }) => system_prompt.length > 0));

  const autogen = fixtures.get("autogen.json");
  assert.ok(
    autogen.graph.nodes.some(({ description }) =>
      /Authorization.*your-api-key/su.test(description ?? ""),
    ),
  );

  const crewAi = fixtures.get("crewai.json");
  assert.equal(
    crewAi.graph.agents.length,
    0,
    "CrewAI fixture must retain its observed metadata shortfall",
  );
  assert.equal(crewAi.warnings.length, 5);
  assert.ok(crewAi.warnings.some(({ message }) => /Skipping agent metadata/u.test(message)));
  assert.ok(crewAi.warnings.some(({ message }) => /<ast\.Name object>/u.test(message)));
  assert.ok(crewAi.warnings.every(({ message }) => !/0x[0-9a-f]+/iu.test(message)));
  assert.ok(crewAi.graph.nodes.some(({ node_type }) => node_type === "agent"));

  const empty = fixtures.get("no-supported-workflow.json");
  assert.deepEqual(empty.graph, { name: "input", nodes: [], edges: [], agents: [], tools: [] });
});

test("MCP Armor research patch and fixtures retain the model-free fail-closed contract", async () => {
  const patchContent = await load(
    "docs/research/patches/mcp-armor-1.0.2-config-only.patch",
  );
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    MCP_ARMOR_RESEARCH_PATCH_SHA256,
  );
  assert.match(patchContent, /--config-only/u);
  assert.match(patchContent, /prompt-injection/u);
  assert.match(patchContent, /CONFIGURATION_CHECKS/u);
  const decision = await load("docs/research/mcp-armor-evaluation.md");
  assert.match(decision, new RegExp(MCP_ARMOR_RESEARCH_PATCH_SHA256, "u"));
  assert.match(decision, /d5fbb944d35c98495a64f97a4270112c48fcdcda/u);

  const fixtures = new Map();
  for (const [name, [expectedComplete, expectedSha256]] of Object.entries(
    MCP_ARMOR_RESEARCH_FIXTURES,
  )) {
    const content = await load(`docs/research/fixtures/mcp-armor/${name}`);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );
    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "1.0.2", name);
    assert.equal(fixture.mode, "configuration_only", name);
    assert.equal(fixture.input_count, 1, name);
    assert.equal(fixture.evaluated_input_count, 1, name);
    assert.equal(fixture.complete, expectedComplete, name);
    assert.deepEqual(
      fixture.checks.map(({ id }) => id),
      ["hardcoded_secrets", "excessive_tool_permissions"],
      name,
    );
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0
        && fixture.checks.every(({ status }) => status === "completed"),
      `${name} must fail closed`,
    );
    for (const warning of fixture.warnings) {
      assert.deepEqual(
        Object.keys(warning).sort(),
        ["check_id", "code", "config_file", "message"],
      );
      assert.ok(["config_invalid", "server_config_invalid", "check_failed"].includes(warning.code));
      assert.equal(typeof warning.message, "string");
      assert.notEqual(warning.message.trim(), "");
    }
  }

  const findings = fixtures.get("config-findings.json");
  assert.deepEqual(
    findings.findings.map(({ check_id, severity }) => [check_id, severity]),
    [["hardcoded_secrets", "high"], ["excessive_tool_permissions", "critical"]],
  );
  assert.equal(findings.findings[0].affected_entities.matched_text_redacted, 'sk-A...BBB"');
  assert.deepEqual(fixtures.get("config-clean.json").findings, []);
  assert.deepEqual(
    fixtures.get("config-disabled.json").findings.map(({ check_id, severity }) => [check_id, severity]),
    [["excessive_tool_permissions", "low"]],
  );
  assert.deepEqual(
    fixtures.get("config-partial.json").warnings.map(({ code }) => code),
    ["server_config_invalid"],
  );
});
