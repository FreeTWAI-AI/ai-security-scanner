import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyRuntimeReadiness,
  classifyRuntimeReadyBadgeKey,
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

test("a ready managed local runtime keeps the advanced tools label", () => {
  assert.equal(classifyRuntimeReadyBadgeKey("managed_local"), "runtime.badge.ready");
});

test("a ready docker or podman runtime uses the compatibility label", () => {
  assert.equal(classifyRuntimeReadyBadgeKey("docker"), "runtime.badge.readyCompatibility");
  assert.equal(classifyRuntimeReadyBadgeKey("podman"), "runtime.badge.readyCompatibility");
});

test("an unrecognised ready provider keeps the existing ready label", () => {
  for (const provider of [undefined, "", "none", "mystery", "MANAGED_LOCAL", "Docker"]) {
    assert.equal(classifyRuntimeReadyBadgeKey(provider), "runtime.badge.ready", String(provider));
  }
});

test("an unavailable compatibility runtime is not ready", () => {
  // Docker/Podman only rename a badge that is already in the ready arm.
  // An unavailable reading still follows the existing not-ready rules.
  for (const phase of runtimeReadinessNeedsSetupPhases) {
    assert.equal(classifyRuntimeReadiness(false, phase), "needsSetup", phase);
  }
  for (const phase of runtimeReadinessCheckingPhases) {
    assert.equal(classifyRuntimeReadiness(false, phase), "checking", phase);
  }
  assert.equal(classifyRuntimeReadiness(false, "running"), "needsSetup");
  assert.notEqual(classifyRuntimeReadiness(false, "running"), "ready");
});
