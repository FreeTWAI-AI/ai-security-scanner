export type RuntimeReadiness = "ready" | "checking" | "needsSetup";

export const runtimeReadinessReadyPhases: ReadonlySet<string> = new Set(["running"]);

export const runtimeReadinessCheckingPhases: ReadonlySet<string> = new Set([
  "checking",
  "starting",
  "error",
]);

export const runtimeReadinessNeedsSetupPhases: ReadonlySet<string> = new Set([
  "not_installed",
  "installed",
  "stopped",
  "unavailable",
  "corrupt",
  "unsupported",
]);

export const classifyRuntimeReadiness = (
  available: boolean | undefined,
  phase: string | undefined,
): RuntimeReadiness => {
  if (available === true) {
    return "ready";
  }
  if (phase !== undefined && runtimeReadinessCheckingPhases.has(phase)) {
    return "checking";
  }
  if (
    phase !== undefined
    && (runtimeReadinessNeedsSetupPhases.has(phase) || runtimeReadinessReadyPhases.has(phase))
  ) {
    return "needsSetup";
  }
  // Unrecognised, empty, or missing phases are readings we have not understood.
  // Fail safe toward honesty: do not demand setup from them.
  return "checking";
};
