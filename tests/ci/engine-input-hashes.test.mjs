import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { validateEngineInputHashes } from "../../scripts/validate-engine-input-hashes.mjs";

const exclusions = [{
  id: "provenance-record",
  match: "exact",
  value: "plan.json",
  reason: "The plan cannot record its own digest.",
}];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fixture(files, { baseline = [], support = [] } = {}) {
  const root = mkdtempSync(join(tmpdir(), "engine-input-hashes-test-"));
  const trackedPaths = [];
  for (const [relativePath, content] of Object.entries(files)) {
    const path = join(root, ...relativePath.split("/"));
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, content);
    trackedPaths.push(relativePath);
  }
  const policy = {
    schema_version: 1,
    exclusions,
    directories_without_plans: support,
    uncovered_baseline: baseline,
  };
  return {
    root,
    trackedPaths,
    policy,
    validate() {
      return validateEngineInputHashes({ root, trackedPaths, policy });
    },
    cleanup() {
      rmSync(root, { force: true, recursive: true });
    },
  };
}

test("a covered engine input passes", () => {
  const dockerfile = "FROM scratch\n";
  const setup = fixture({
    "engines/images/example/Dockerfile": dockerfile,
    "engines/images/example/plan.json": JSON.stringify({ sha256: `sha256:${sha256(dockerfile)}` }),
  });
  try {
    const report = setup.validate();
    assert.deepEqual({
      errors: report.errors,
      status: report.records.find(({ relativePath }) => relativePath === "Dockerfile")?.status,
    }, { errors: [], status: "covered" });
  } finally {
    setup.cleanup();
  }
});

test("an uncovered engine input outside the baseline fails", () => {
  const setup = fixture({
    "engines/images/example/Dockerfile": "FROM scratch\n",
    "engines/images/example/plan.json": "{}\n",
  });
  try {
    assert.ok(
      setup.validate().errors.includes("new uncovered engine input: engines/images/example/Dockerfile"),
    );
  } finally {
    setup.cleanup();
  }
});

test("a baseline entry naming a file that no longer exists fails", () => {
  const missingPath = "engines/images/example/removed.sh";
  const setup = fixture(
    { "engines/images/example/plan.json": "{}\n" },
    { baseline: [{ path: missingPath, reason: "Known gap pending a plan schema update." }] },
  );
  try {
    assert.ok(
      setup.validate().errors.includes(`uncovered baseline entry no longer names a tracked file: ${missingPath}`),
    );
  } finally {
    setup.cleanup();
  }
});

test("an unrecorded engine directory with no plan fails explicitly", () => {
  const setup = fixture({ "engines/images/example/Dockerfile": "FROM scratch\n" });
  try {
    const report = setup.validate();
    assert.deepEqual({
      missingPlan: report.errors.includes(
        "engines/images/example has tracked files but no plan.json and is not recorded in directories_without_plans",
      ),
      reasonId: report.records[0]?.reasonId,
    }, { missingPlan: true, reasonId: "missing-plan" });
  } finally {
    setup.cleanup();
  }
});
