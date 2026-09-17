import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

import {
  REQUIRED_VERIFICATIONS,
  prReasons,
  refreshEngine,
  refreshEngines,
} from "../../scripts/upstream-refresh-lib.mjs";
import { main as proposeMain } from "../../scripts/upstream-propose.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const fixedNow = new Date("2026-09-17T12:34:56.000Z");

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    throw new Error(result.error?.message ?? (result.stderr || `${command} exited ${result.status}`));
  }
  return result.stdout.trim();
}

function commit(repository, message) {
  run("git", ["init", "--quiet"], { cwd: repository });
  run("git", ["add", "--all"], { cwd: repository });
  run("git", [
    "-c", "user.name=Refresh Test",
    "-c", "user.email=refresh-test@invalid",
    "commit", "--quiet", "-m", message,
  ], { cwd: repository });
  return run("git", ["rev-parse", "HEAD"], { cwd: repository });
}

function passedVerification(overrides = {}) {
  return REQUIRED_VERIFICATIONS.map((name) => ({
    name,
    status: overrides[name]?.status ?? "passed",
    reason: overrides[name]?.reason ?? null,
    command: `fixture ${name}`,
    output: "fixture completed",
    output_truncated: false,
  }));
}

function createFixture({ engineIds = ["sample"], absentCheckout = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "upstream-refresh-test-"));
  mkdirSync(join(root, "engines", "images"), { recursive: true });
  const repositories = [];
  const revisions = new Map();
  for (const engineId of engineIds) {
    const checkoutRelative = `.upstreams/example/${engineId}`;
    const checkout = join(root, ...checkoutRelative.split("/"));
    let pinned = "1".repeat(40);
    let candidate = null;
    if (!absentCheckout) {
      mkdirSync(checkout, { recursive: true });
      writeFileSync(join(checkout, "adapter.txt"), "pinned adapter\n");
      pinned = commit(checkout, "pinned");
      writeFileSync(join(checkout, "adapter.txt"), "refreshed adapter\n");
      run("git", ["add", "adapter.txt"], { cwd: checkout });
      run("git", [
        "-c", "user.name=Refresh Test",
        "-c", "user.email=refresh-test@invalid",
        "commit", "--quiet", "-m", "candidate",
      ], { cwd: checkout });
      candidate = run("git", ["rev-parse", "HEAD"], { cwd: checkout });
    }
    const engineDirectory = join(root, "engines", "images", engineId);
    mkdirSync(engineDirectory, { recursive: true });
    writeFileSync(join(engineDirectory, "Dockerfile"), "FROM scratch\n");
    const plan = {
      schema_version: 1,
      engine_id: engineId,
      knowledge_date: "2026-01-01",
      support_until: "2026-04-01",
      publish_state: "published_managed_artifact",
      source: {
        repository: `https://example.invalid/example/${engineId}`,
        revision: pinned,
        acquisition_source: `https://example.invalid/example/${engineId}/commit/${pinned}`,
        local_research_checkout: checkoutRelative,
      },
      final_artifact: {
        repository: `ghcr.io/example/${engineId}`,
        tag: "1.0.0",
        digest: `sha256:${"2".repeat(64)}`,
      },
      build_recipe: {
        dependency_lock: {
          path: "adapter.txt",
          sha256: sha256("pinned adapter\n"),
        },
      },
    };
    writeFileSync(join(engineDirectory, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
    repositories.push({
      id: `example/${engineId}`,
      path: checkoutRelative,
      remote: plan.source.repository,
      revision: candidate ?? pinned,
    });
    revisions.set(engineId, { pinned, candidate });
  }
  writeFileSync(join(root, "engines", "upstreams.lock.json"), `${JSON.stringify({ repositories }, null, 2)}\n`);
  return {
    root,
    revisions,
    bundleRoot: join(root, "bundles"),
    cleanup() {
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function policy(entries) {
  return {
    schema_version: 1,
    engines: entries.map(([id, status, reason = `${id} fixture policy.`]) => ({ id, status, reason })),
  };
}

test("a frozen engine is refused with its stated reason and cannot become a PR", async () => {
  const frozenReason = "CloudQuery is deliberately pinned to v2.0.31 (knowledge_date 2023-01-10), the last fully public CloudQuery CLI before the project stopped being fully open source. A refresh would move the product onto a non-open-source upstream.";
  const result = await refreshEngine({
    root: repositoryRoot,
    engineId: "cloudquery",
    now: fixedNow,
    bundleRoot: mkdtempSync(join(tmpdir(), "upstream-refresh-frozen-")),
  });
  try {
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      policyReason: result.proposal.policy.reason,
      patch: result.patch,
      checks: result.proposal.verification.map(({ status }) => status),
    }, {
      outcome: "frozen",
      eligible: false,
      policyReason: frozenReason,
      patch: "",
      checks: ["not_run", "not_run", "not_run"],
    });
  } finally {
    rmSync(dirname(dirname(result.bundlePath)), { recursive: true, force: true });
  }
});

test("a frozen engine remains ineligible when the early return is not what stops it", async () => {
  const frozenReason = "Deliberately pinned to a last fully public upstream.";
  const setup = createFixture({ engineIds: ["frozen-one"] });
  try {
    const proceeded = await refreshEngine({
      root: setup.root,
      engineId: "frozen-one",
      policy: policy([["frozen-one", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    const reasons = prReasons({
      policy: { id: "frozen-one", status: "frozen", reason: frozenReason },
      changes: new Map(proceeded.proposal.changes.files.map((file) => [file, { produced: true }])),
      verifications: proceeded.proposal.verification,
      providerError: null,
    });
    assert.deepEqual({
      proceededEligible: proceeded.proposal.pr_eligible,
      proceededChecks: proceeded.proposal.verification.map(({ status }) => status),
      produced: proceeded.proposal.changes.produced,
      frozenEligible: reasons.length === 0,
      reasons,
    }, {
      proceededEligible: true,
      proceededChecks: ["passed", "passed", "passed"],
      produced: true,
      frozenEligible: false,
      reasons: [`Policy status is frozen: ${frozenReason}`],
    });
  } finally {
    setup.cleanup();
  }
});

test("an unknown engine id is refused closed", async () => {
  const setup = createFixture({ engineIds: ["known"] });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "unknown",
      policy: policy([["known", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      outcome: result.proposal.outcome,
      status: result.proposal.policy.status,
      eligible: result.proposal.pr_eligible,
      reason: result.proposal.policy.reason,
    }, {
      outcome: "unsupported",
      status: "unsupported",
      eligible: false,
      reason: "No refresh-policy entry exists for engine unknown; unknown engines fail closed.",
    });
  } finally {
    setup.cleanup();
  }
});

test("an experimental failure stays experimental and does not change an eligible engine outcome", async () => {
  const setup = createFixture({ engineIds: ["experimental-one", "eligible-one"] });
  try {
    const productPolicy = JSON.parse(readFileSync(join(repositoryRoot, "engines", "upstream-refresh-policy.json")));
    const encodedProductFacts = Object.fromEntries(productPolicy.engines
      .filter(({ id }) => ["agentic-radar", "garak", "mcp-armor"].includes(id))
      .map(({ id, status, reason }) => [id, { status, cannotRelease: reason.includes("cannot reach a release") }]));
    const runResult = await refreshEngines({
      root: setup.root,
      engineIds: ["experimental-one", "eligible-one"],
      policy: policy([
        ["experimental-one", "experimental", "Its managed artifact is not published, so it cannot reach a release."],
        ["eligible-one", "eligible"],
      ]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: ({ engineId }) => engineId === "experimental-one"
        ? passedVerification({ "validate:engine-catalog": { status: "failed", reason: "fixture failure" } })
        : passedVerification(),
    });
    assert.deepEqual({
      exitCode: runResult.exitCode,
      experimental: {
        outcome: runResult.results[0].proposal.outcome,
        eligible: runResult.results[0].proposal.pr_eligible,
        failedCheck: runResult.results[0].proposal.verification[1].status,
        releaseStatement: runResult.results[0].proposal.policy.reason,
      },
      eligible: {
        outcome: runResult.results[1].proposal.outcome,
        eligible: runResult.results[1].proposal.pr_eligible,
      },
      encodedProductFacts,
    }, {
      exitCode: 0,
      experimental: {
        outcome: "experimental",
        eligible: false,
        failedCheck: "failed",
        releaseStatement: "Its managed artifact is not published, so it cannot reach a release.",
      },
      eligible: { outcome: "ready", eligible: true },
      encodedProductFacts: {
        "agentic-radar": { status: "experimental", cannotRelease: true },
        garak: { status: "experimental", cannotRelease: true },
        "mcp-armor": { status: "experimental", cannotRelease: true },
      },
    });
  } finally {
    setup.cleanup();
  }
});

test("an experimental engine with passing verification cannot become a PR and still emits a readable proposal", async () => {
  const experimentalReason = "Its managed artifact is not published, so it cannot reach a release.";
  const setup = createFixture({ engineIds: ["experimental-one"] });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "experimental-one",
      policy: policy([["experimental-one", "experimental", experimentalReason]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    const proposed = JSON.parse(readFileSync(join(result.bundlePath, "proposal.json"), "utf8"));
    const report = readFileSync(join(result.bundlePath, "report.md"), "utf8");
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      reasons: result.proposal.pr_ineligibility_reasons,
      checks: result.proposal.verification.map(({ name, status }) => `${name}:${status}`),
      produced: result.proposal.changes.produced,
      files: result.proposal.changes.files,
      patchEmpty: result.patch.length === 0,
      bundleFiles: readdirSync(result.bundlePath).sort(),
      persistedEligible: proposed.pr_eligible,
      persistedOutcome: proposed.outcome,
      reportOutcome: report.includes("Outcome: **experimental**"),
      reportForbidsPr: report.includes("May not become a PR"),
      reportNamesExperimental: report.includes(`Policy status is experimental: ${experimentalReason}`),
    }, {
      outcome: "experimental",
      eligible: false,
      reasons: [`Policy status is experimental: ${experimentalReason}`],
      checks: [
        "validate:engine-input-hashes:passed",
        "validate:engine-catalog:passed",
        "validate:engine-line-endings:passed",
      ],
      produced: true,
      files: ["engines/images/experimental-one/plan.json"],
      patchEmpty: false,
      bundleFiles: ["changes.patch", "proposal.json", "report.md"],
      persistedEligible: false,
      persistedOutcome: "experimental",
      reportOutcome: true,
      reportForbidsPr: true,
      reportNamesExperimental: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("an absent upstream checkout is unavailable rather than no drift", async () => {
  const setup = createFixture({ engineIds: ["sample"], absentCheckout: true });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      checkoutStatus: result.proposal.inputs.local_research_checkout.status,
      checkoutComparison: result.proposal.inputs.local_research_checkout.comparison,
      driftStatus: result.proposal.drift.status,
      driftSummary: result.proposal.drift.summary,
      outcome: result.proposal.outcome,
    }, {
      checkoutStatus: "unavailable",
      checkoutComparison: "unavailable",
      driftStatus: "unavailable",
      driftSummary: "At least one offline source was unavailable; this is not a no-drift result.",
      outcome: "no_change",
    });
  } finally {
    setup.cleanup();
  }
});

test("a failing verification check forces PR ineligibility and names the check", async () => {
  const setup = createFixture();
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification({ "validate:engine-catalog": { status: "failed", reason: "catalog mismatch" } }),
    });
    assert.deepEqual({
      eligible: result.proposal.pr_eligible,
      status: result.proposal.verification.find(({ name }) => name === "validate:engine-catalog").status,
      reasons: result.proposal.pr_ineligibility_reasons,
    }, {
      eligible: false,
      status: "failed",
      reasons: ["Verification check validate:engine-catalog failed."],
    });
  } finally {
    setup.cleanup();
  }
});

test("a verification check that could not run is not passed and forces PR ineligibility", async () => {
  const setup = createFixture();
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification({
        "validate:engine-line-endings": { status: "not_run", reason: "validator executable unavailable" },
      }),
    });
    const check = result.proposal.verification.find(({ name }) => name === "validate:engine-line-endings");
    assert.deepEqual({
      eligible: result.proposal.pr_eligible,
      status: check.status,
      reason: check.reason,
      eligibilityReason: result.proposal.pr_ineligibility_reasons.at(-1),
    }, {
      eligible: false,
      status: "not_run",
      reason: "validator executable unavailable",
      eligibilityReason: "Verification check validate:engine-line-endings was not run: validator executable unavailable",
    });
  } finally {
    setup.cleanup();
  }
});

test("the cli provider uses an injected double and attributes model edits", async () => {
  const setup = createFixture();
  let calls = 0;
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      providerId: "cli",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
      cliRunner: ({ command, input }) => {
        calls += 1;
        return {
          rationale: `Reviewed without spawning ${command ?? "any executable"}; request ${JSON.parse(input).engine}.`,
          edits: [{ path: "engines/images/sample/Dockerfile", content: "FROM scratch\n# model review\n", reason: "Rebased the adapter recipe." }],
        };
      },
    });
    assert.deepEqual({
      calls,
      provider: result.proposal.provider,
      files: result.proposal.changes.files,
      attributionProviders: [...new Set(result.proposal.changes.attributions.map(({ provider }) => provider))],
    }, {
      calls: 1,
      provider: {
        selected: "cli",
        status: "completed",
        rationale: "Reviewed without spawning any executable; request sample.",
        model_invoked: true,
      },
      files: ["engines/images/sample/Dockerfile", "engines/images/sample/plan.json"],
      attributionProviders: ["mechanical", "cli"],
    });
  } finally {
    setup.cleanup();
  }
});

test("changes.patch applies cleanly with git apply --check", async () => {
  const setup = createFixture();
  const target = mkdtempSync(join(tmpdir(), "upstream-refresh-apply-"));
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    cpSync(join(setup.root, "engines"), join(target, "engines"), { recursive: true });
    commit(target, "target baseline");
    const applyCheck = spawnSync("git", ["apply", "--check", join(result.bundlePath, "changes.patch")], {
      cwd: target,
      encoding: "utf8",
    });
    const proposedPlan = JSON.parse(readFileSync(join(result.bundlePath, "proposal.json")));
    assert.deepEqual({
      applyStatus: applyCheck.status,
      applyError: applyCheck.stderr,
      changedFiles: proposedPlan.changes.files,
      digestUpdated: proposedPlan.changes.attributions.some(({ field }) => field === "build_recipe.dependency_lock.sha256"),
      artifactCoordinate: proposedPlan.inputs.plan.final_artifact_coordinate,
    }, {
      applyStatus: 0,
      applyError: "",
      changedFiles: ["engines/images/sample/plan.json"],
      digestUpdated: true,
      artifactCoordinate: `ghcr.io/example/sample:1.0.0@sha256:${"2".repeat(64)}`,
    });
  } finally {
    setup.cleanup();
    rmSync(target, { recursive: true, force: true });
  }
});

test("upstream:propose prints commands without network or git-write operations", () => {
  const root = mkdtempSync(join(tmpdir(), "upstream-propose-test-"));
  try {
    const bundle = join(root, "bundle");
    mkdirSync(bundle);
    const proposal = {
      generated_at: fixedNow.toISOString(),
      engine: { id: "sample" },
      policy: { status: "eligible" },
      changes: { produced: true, files: ["engines/images/sample/plan.json"] },
      verification: passedVerification(),
      artifacts: [{ path: "changes.patch", sha256: sha256("diff --git a/file b/file\n") }],
      pr_eligible: true,
    };
    writeFileSync(join(bundle, "proposal.json"), `${JSON.stringify(proposal)}\n`);
    writeFileSync(join(bundle, "changes.patch"), "diff --git a/file b/file\n");
    writeFileSync(join(bundle, "report.md"), "# Review\n");
    let stdout = "";
    const status = proposeMain(["--bundle", bundle], { write(value) { stdout += value; } });
    const entrySource = readFileSync(join(repositoryRoot, "scripts", "upstream-propose.mjs"), "utf8");
    const librarySource = readFileSync(join(repositoryRoot, "scripts", "upstream-propose-lib.mjs"), "utf8");
    assert.deepEqual({
      status,
      eligible: stdout.startsWith("PR eligible: yes\n"),
      printsPush: stdout.includes("git push -u origin"),
      printsPr: stdout.includes("gh pr create --fill --head"),
      importsProcessOrNetwork: /node:(?:child_process|http|https|net)|\b(?:writeFile|rmSync|unlinkSync|renameSync)\b/.test(`${entrySource}\n${librarySource}`),
      bundleFiles: readdirSync(bundle).sort(),
    }, {
      status: 0,
      eligible: true,
      printsPush: true,
      printsPr: true,
      importsProcessOrNetwork: false,
      bundleFiles: ["changes.patch", "proposal.json", "report.md"],
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
