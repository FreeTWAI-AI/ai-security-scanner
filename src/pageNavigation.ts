import type { PageId, ScanRun } from "./types";

export interface PageTransitionFocusTarget {
  focus: (options?: FocusOptions) => void;
}

export interface PageTransitionMainContent extends PageTransitionFocusTarget {
  querySelector: (selector: string) => PageTransitionFocusTarget | null;
}

export interface PageTransitionViewport {
  scrollTo: (options: ScrollToOptions) => void;
}

const activeRunStatuses = new Set<ScanRun["status"]>(["queued", "running", "paused"]);
const terminalRunStatuses = new Set<ScanRun["status"]>([
  "completed",
  "no_checks_completed",
  "partial",
  "failed",
  "cancelled",
]);

export type TerminalRunPage = Extract<PageId, "findings" | "export">;

type LifecycleRun = Pick<ScanRun, "id" | "status" | "sequence" | "startedAt" | "finishedAt">;

export interface DeferredTerminalPageRequest {
  runId: string;
  requestedPage: TerminalRunPage;
}

export interface SelectedRunLifecycleResolution<TRun extends LifecycleRun> {
  page: PageId;
  run: TRun | undefined;
  awaitedRun: TRun | undefined;
  showingFinishedRunWhileActive: boolean;
}

const newestTerminalRun = <TRun extends LifecycleRun>(runs: readonly TRun[]): TRun | undefined =>
  runs
    .filter((run) => terminalRunStatuses.has(run.status))
    .reduce<TRun | undefined>((newest, candidate) => {
      if (!newest) return candidate;
      if (candidate.sequence !== undefined && newest.sequence !== undefined) {
        if (candidate.sequence !== newest.sequence) {
          return candidate.sequence > newest.sequence ? candidate : newest;
        }
      }
      if (candidate.startedAt !== newest.startedAt) {
        return candidate.startedAt > newest.startedAt ? candidate : newest;
      }
      if ((candidate.finishedAt ?? "") !== (newest.finishedAt ?? "")) {
        return (candidate.finishedAt ?? "") > (newest.finishedAt ?? "") ? candidate : newest;
      }
      return candidate.id > newest.id ? candidate : newest;
    }, undefined);

/** Active work stays in Progress; a saved terminal run remains available to Results and Export. */
export const pageForSelectedRunLifecycle = <TRun extends LifecycleRun>(
  requestedPage: PageId,
  selectedRun: TRun | undefined,
  runs: readonly TRun[],
  deferredRequest?: DeferredTerminalPageRequest,
): SelectedRunLifecycleResolution<TRun> => {
  const deferredRun = deferredRequest
    ? runs.find((run) => run.id === deferredRequest.runId)
    : undefined;
  const terminalPage = requestedPage === "findings" || requestedPage === "export";

  if (deferredRequest && deferredRun && terminalRunStatuses.has(deferredRun.status) && (
    requestedPage === "progress" || terminalPage
  )) {
    return {
      page: terminalPage ? requestedPage : deferredRequest.requestedPage,
      run: deferredRun,
      awaitedRun: undefined,
      showingFinishedRunWhileActive: false,
    };
  }

  if (deferredRequest && deferredRun && activeRunStatuses.has(deferredRun.status) && requestedPage === "progress") {
    return {
      page: "progress",
      run: deferredRun,
      awaitedRun: deferredRun,
      showingFinishedRunWhileActive: false,
    };
  }

  if (
    (requestedPage === "findings" || requestedPage === "export")
    && selectedRun
    && activeRunStatuses.has(selectedRun.status)
  ) {
    const finishedRun = newestTerminalRun(runs);
    if (finishedRun) {
      return {
        page: requestedPage,
        run: finishedRun,
        awaitedRun: selectedRun,
        showingFinishedRunWhileActive: true,
      };
    }
    return {
      page: "progress",
      run: selectedRun,
      awaitedRun: selectedRun,
      showingFinishedRunWhileActive: false,
    };
  }

  if (
    deferredRequest
    && deferredRun
    && activeRunStatuses.has(deferredRun.status)
    && terminalPage
    && selectedRun
    && terminalRunStatuses.has(selectedRun.status)
  ) {
    return {
      page: requestedPage,
      run: selectedRun,
      awaitedRun: deferredRun,
      showingFinishedRunWhileActive: true,
    };
  }

  return {
    page: requestedPage,
    run: selectedRun,
    awaitedRun: undefined,
    showingFinishedRunWhileActive: false,
  };
};

/**
 * Restores the beginning of a newly rendered page for sighted and keyboard users.
 * Same-page state updates deliberately do nothing so form input and reading
 * position are not disturbed by background refreshes or ordinary rerenders.
 */
export const completePageTransition = ({
  previousKey,
  nextKey,
  mainContent,
  viewport,
}: {
  previousKey: string;
  nextKey: string;
  mainContent: PageTransitionMainContent | null;
  viewport: PageTransitionViewport;
}): boolean => {
  if (previousKey === nextKey) return false;

  const focusTarget = mainContent?.querySelector("[data-page-heading]") ?? mainContent;
  focusTarget?.focus({ preventScroll: true });
  viewport.scrollTo({ top: 0, left: 0, behavior: "auto" });
  return true;
};
