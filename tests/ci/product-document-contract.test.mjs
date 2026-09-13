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
  "docs/research/agentic-radar-evaluation.md",
  "docs/research/fixtures/agentic-radar/README.md",
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
    "c3f66da0493ffaa2dcf85680fad1f4c104cf766429c7048bb24c239861d45411",
  ],
  "crewai.json": [
    "crewai",
    "workflow_found",
    "e85bc1db3b40306a6a628fa66b4707e553933fead7cf8ef5981fae41f020e1c4",
  ],
  "langgraph.json": [
    "langgraph",
    "workflow_found",
    "7c56fbc7662b068fcf9d194bf5234c902af1c74c8a25d9a00dcccab6a478a6d3",
  ],
  "n8n.json": [
    "n8n",
    "workflow_found",
    "f266b59815482a675f951ecd6425785612862a1ae8810831f774f97023217584",
  ],
  "no-supported-workflow.json": [
    "langgraph",
    "no_supported_workflow",
    "3b11f0e3eea835961bdd83ea810e9e74df703ad1e1aabcc08254a8d55b3572fa",
  ],
  "openai-agents.json": [
    "openai-agents",
    "workflow_found",
    "050501da928effaf5b0e55013a1d87adc0b5a3ec63e86b7d3bf0558a9e1e646b",
  ],
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

test("Agentic Radar research fixtures retain the audited machine-output contract", async () => {
  const fixtures = new Map();
  for (const [name, [framework, status, expectedSha256]] of Object.entries(
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
  assert.ok(crewAi.graph.nodes.some(({ node_type }) => node_type === "agent"));

  const empty = fixtures.get("no-supported-workflow.json");
  assert.deepEqual(empty.graph, { name: "input", nodes: [], edges: [], agents: [], tools: [] });
});
