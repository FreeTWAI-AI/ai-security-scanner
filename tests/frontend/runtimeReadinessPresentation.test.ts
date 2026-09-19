import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyRuntimeReadiness,
  runtimeReadinessCheckingPhases,
  runtimeReadinessNeedsSetupPhases,
  runtimeReadinessReadyPhases,
} from "../../src/runtimeReadinessPresentation.ts";

test("every backend runtime phase classifies without a setup fallthrough surprise", () => {
  assert.deepEqual([...runtimeReadinessReadyPhases].sort(), ["running"]);
  assert.deepEqual([...runtimeReadinessCheckingPhases].sort(), ["checking", "error", "starting"]);
  assert.deepEqual(
    [...runtimeReadinessNeedsSetupPhases].sort(),
    ["corrupt", "installed", "not_installed", "stopped", "unavailable", "unsupported"],
  );

  assert.equal(classifyRuntimeReadiness(true, "running"), "ready");
  for (const phase of runtimeReadinessCheckingPhases) {
    assert.equal(classifyRuntimeReadiness(false, phase), "checking", phase);
  }
  for (const phase of runtimeReadinessNeedsSetupPhases) {
    assert.equal(classifyRuntimeReadiness(false, phase), "needsSetup", phase);
  }
});

test("an unrecognised runtime phase is checking, never a setup demand", () => {
  for (const phase of [undefined, "", "preparing", "mystery", "READY"]) {
    assert.equal(classifyRuntimeReadiness(false, phase), "checking", String(phase));
  }
});

test("an available runtime is ready regardless of phase", () => {
  const phases = [
    ...runtimeReadinessReadyPhases,
    ...runtimeReadinessCheckingPhases,
    ...runtimeReadinessNeedsSetupPhases,
    undefined,
    "",
    "mystery",
  ];
  for (const phase of phases) {
    assert.equal(classifyRuntimeReadiness(true, phase), "ready", String(phase));
  }
});
