import { isTerminalResultRun } from "./runLifecycle.ts";
import type { EngineRun, EngineRunStatus, ScanRun } from "./types";

/**
 * Engine outcomes that mean planned work was attempted and will not continue.
 * Matches scanLifecycleDisposition's terminal-vs-stale set except cancelled:
 * a stop mid-run must keep the measured mean.
 */
const attemptedTerminalEngineStatuses = new Set<EngineRunStatus>([
  "completed",
  "partial",
  "failed",
  "not_executed",
]);

const measuredMeanProgress = (engineRuns: ReadonlyArray<Pick<EngineRun, "progress">>): number =>
  engineRuns.length > 0
    ? Math.round(
      engineRuns.reduce((total, engineRun) => total + engineRun.progress, 0) / engineRuns.length,
    )
    : 0;

/**
 * Overall progress answers whether work is still in flight.
 * Once every check has a terminal outcome, the number is 100.
 * A cancelled run, or any run with an engine that never reached a terminal
 * outcome, keeps the measured mean.
 */
export const scanRunOverallProgress = (
  run: Pick<ScanRun, "status" | "engineRuns">,
): number => {
  const measured = measuredMeanProgress(run.engineRuns);
  if (
    !isTerminalResultRun(run)
    || run.status === "cancelled"
    || run.engineRuns.length === 0
    || !run.engineRuns.every((engineRun) => attemptedTerminalEngineStatuses.has(engineRun.status))
  ) {
    return measured;
  }
  return 100;
};
