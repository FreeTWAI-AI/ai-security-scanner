export const findRunCreatedAfterStart = (
  runs: ReadonlyArray<{ id: string }>,
  existingRunIds: ReadonlySet<string>,
): string | undefined => runs.find((run) => !existingRunIds.has(run.id))?.id;

const liveRunStatuses = new Set(["queued", "running", "paused", "preparing"]);
const liveEngineStatuses = new Set(["pending", "queued", "running", "paused", "preparing"]);
const plannedEngineStatuses = new Set(["pending", "queued"]);
const startedEngineStatuses = new Set(["preparing", "running", "paused", "partial", "completed"]);
const startBlockingReasons = new Set([
  "demo_case",
  "archived_case",
  "scan_already_active",
  "no_effective_scope_grants",
  "no_ownership_confirmed_targets",
  "no_compatible_authorized_targets",
]);

type ScanWorkEngine = {
  status: string;
  startedAt?: string;
};

type ScanWorkRun = {
  status: string;
  startedAt?: string;
  finishedAt?: string;
  progress?: number;
  engineRuns?: ReadonlyArray<ScanWorkEngine>;
};

const hasRecordedStart = (value?: string): boolean => typeof value === "string" && value.length > 0;

/** Missing timestamps alone cannot override a check's recorded execution state. */
export const isNeverStartedScanRun = (run: ScanWorkRun): boolean => {
  const engines = run.engineRuns;
  if (!engines || engines.length === 0) return false;
  return engines.every((engine) =>
    !startedEngineStatuses.has(engine.status) && !hasRecordedStart(engine.startedAt));
};

/** A saved plan that nothing is dispatching is not live scan work. */
export const isUndispatchedScanPlan = (run: ScanWorkRun): boolean => {
  if (run.status !== "queued") return false;
  if (run.progress !== undefined && run.progress > 0) return false;
  if (hasRecordedStart(run.finishedAt)) return false;
  if (!isNeverStartedScanRun(run)) return false;
  const engines = run.engineRuns;
  return engines?.every((engine) => plannedEngineStatuses.has(engine.status)) === true;
};

export const hasActiveScanWork = (
  runs: ReadonlyArray<ScanWorkRun>,
): boolean => runs.some((run) =>
  !isUndispatchedScanPlan(run)
  && (
    liveRunStatuses.has(run.status)
    || run.engineRuns?.some((engineRun) => liveEngineStatuses.has(engineRun.status)) === true
  ));

export const canStartPreparedScan = (
  readiness: { ready: boolean; blockerCode?: string } | undefined,
  _readinessCheckFailed: boolean,
  runs: ReadonlyArray<ScanWorkRun>,
): boolean => {
  if (hasActiveScanWork(runs)) return false;
  const blocker = readiness?.blockerCode;
  if (blocker === "scan_already_active" && runs.some(isUndispatchedScanPlan)) return true;
  return !blocker || !startBlockingReasons.has(blocker);
};
