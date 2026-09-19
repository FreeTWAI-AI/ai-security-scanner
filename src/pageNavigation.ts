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

/** Active work has one destination; Results and Export are terminal-run pages. */
export const pageForSelectedRunLifecycle = (
  requestedPage: PageId,
  selectedRun: Pick<ScanRun, "status"> | undefined,
  deferredPage?: TerminalRunPage,
): PageId => {
  if (
    (requestedPage === "findings" || requestedPage === "export")
    && selectedRun
    && activeRunStatuses.has(selectedRun.status)
  ) return "progress";

  if (
    requestedPage === "progress"
    && deferredPage
    && selectedRun
    && terminalRunStatuses.has(selectedRun.status)
  ) return deferredPage;

  return requestedPage;
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
