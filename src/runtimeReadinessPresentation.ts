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

export type RuntimeReadyBadgeKey =
  | "runtime.badge.ready"
  | "runtime.badge.readyCompatibility";

const runtimeReadyCompatibilityProviders: ReadonlySet<string> = new Set(["docker", "podman"]);

export const classifyRuntimeReadyBadgeKey = (
  provider: string | undefined,
): RuntimeReadyBadgeKey => {
  if (provider !== undefined && runtimeReadyCompatibilityProviders.has(provider)) {
    return "runtime.badge.readyCompatibility";
  }
  // Unrecognised providers, including none, keep the existing ready label
  // rather than inventing a claim about which runtime is running.
  return "runtime.badge.ready";
};
