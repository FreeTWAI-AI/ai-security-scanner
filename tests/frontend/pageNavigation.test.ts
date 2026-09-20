import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  completePageTransition,
  pageForSelectedRunLifecycle,
  type PageTransitionFocusTarget,
  type PageTransitionMainContent,
} from "../../src/pageNavigation.ts";

const source = async (path: string): Promise<string> =>
  readFile(new URL(path, import.meta.url), "utf8");

const run = (
  id: string,
  status: "queued" | "running" | "paused" | "completed" | "no_checks_completed" | "partial" | "failed" | "cancelled",
  sequence: number,
) => ({
  id,
  status,
  sequence,
  startedAt: `2026-09-${String(sequence).padStart(2, "0")}T12:00:00Z`,
  finishedAt: ["queued", "running", "paused"].includes(status)
    ? undefined
    : `2026-09-${String(sequence).padStart(2, "0")}T12:01:00Z`,
});

test("an active Results request selects the newest terminal run for every active status", () => {
  for (const status of ["queued", "running", "paused"] as const) {
    const active = run("active", status, 4);
    const older = run("older-terminal", "completed", 1);
    const newest = run("newest-terminal", "partial", 3);
    const resolution = pageForSelectedRunLifecycle(
      "findings",
      active,
      [older, active, newest],
    );
    assert.equal(resolution.page, "findings");
    assert.equal(resolution.run?.id, newest.id);
    assert.equal(resolution.awaitedRun?.id, active.id);
    assert.equal(resolution.showingFinishedRunWhileActive, true);
  }
});

test("an active Export request selects the same newest terminal run and never the active run", () => {
  for (const status of ["queued", "running", "paused"] as const) {
    const active = run("active", status, 4);
    const newest = run("newest-terminal", "completed", 3);
    const resolution = pageForSelectedRunLifecycle("export", active, [active, newest]);
    assert.equal(resolution.page, "export");
    assert.equal(resolution.run?.id, newest.id);
    assert.notEqual(resolution.run?.id, active.id);
    assert.equal(resolution.awaitedRun?.id, active.id);
  }
});

test("the deferred promise survives the visible finished-run selection and opens the requested page on completion", () => {
  for (const requestedPage of ["findings", "export"] as const) {
    const active = run("active", "running", 2);
    const saved = run("saved", "completed", 1);
    const deferredRequest = { runId: active.id, requestedPage };

    const whileRunning = pageForSelectedRunLifecycle(
      requestedPage,
      saved,
      [active, saved],
      deferredRequest,
    );
    assert.equal(whileRunning.page, requestedPage);
    assert.equal(whileRunning.run?.id, saved.id);
    assert.equal(whileRunning.awaitedRun?.id, active.id);
    assert.equal(whileRunning.showingFinishedRunWhileActive, true);

    const finished = run("active", "completed", 2);
    const afterCompletion = pageForSelectedRunLifecycle(
      requestedPage,
      saved,
      [finished, saved],
      deferredRequest,
    );
    assert.equal(afterCompletion.page, requestedPage);
    assert.equal(afterCompletion.run?.id, finished.id);
    assert.equal(afterCompletion.awaitedRun, undefined);
    assert.equal(afterCompletion.showingFinishedRunWhileActive, false);
  }
});

test("terminal selections and unrelated routes keep their requested destination", () => {
  for (const status of ["completed", "no_checks_completed", "partial", "failed", "cancelled"] as const) {
    const terminal = run("terminal", status, 1);
    assert.equal(pageForSelectedRunLifecycle("findings", terminal, [terminal]).page, "findings");
    assert.equal(pageForSelectedRunLifecycle("export", terminal, [terminal]).page, "export");
  }

  assert.equal(pageForSelectedRunLifecycle("findings", undefined, []).page, "findings");
  assert.equal(pageForSelectedRunLifecycle("export", undefined, []).page, "export");
  const active = run("active", "running", 1);
  assert.equal(pageForSelectedRunLifecycle("coverage", active, [active]).page, "coverage");
});

test("automatic report navigation waits for the terminal report projection, keeping saved Results readable", () => {
  const finished = run("new", "completed", 2);
  const saved = run("saved", "completed", 1);
  for (const requestedPage of ["findings", "export"] as const) {
    const deferred = { runId: finished.id, requestedPage };
    const waiting = pageForSelectedRunLifecycle(requestedPage, saved, [finished, saved], deferred, [saved.id]);
    assert.equal(waiting.page, requestedPage);
    assert.equal(waiting.run?.id, saved.id);
    assert.equal(waiting.awaitedRun?.id, finished.id);
    assert.equal(waiting.showingFinishedRunWhileActive, true);
    const ready = pageForSelectedRunLifecycle(requestedPage, saved, [finished, saved], deferred, [saved.id, finished.id]);
    assert.equal(ready.run?.id, finished.id);
    assert.equal(ready.awaitedRun, undefined);

    const firstReportWaiting = pageForSelectedRunLifecycle("progress", finished, [finished], deferred, []);
    assert.equal(firstReportWaiting.page, "progress");
    assert.equal(firstReportWaiting.awaitedRun?.id, finished.id);
    const firstReportReady = pageForSelectedRunLifecycle("progress", finished, [finished], deferred, [finished.id]);
    assert.equal(firstReportReady.page, requestedPage);
  }
});

test("an active request with no terminal run still deflects, records its promise, and opens when the run ends", () => {
  for (const deferredPage of ["findings", "export"] as const) {
    const active = run("active", "running", 1);
    const deflected = pageForSelectedRunLifecycle(deferredPage, active, [active]);
    assert.equal(deflected.page, "progress");
    assert.equal(deflected.run?.id, active.id);
    assert.equal(deflected.awaitedRun?.id, active.id);

    const deferredRequest = { runId: active.id, requestedPage: deferredPage };
    assert.equal(
      pageForSelectedRunLifecycle("progress", active, [active], deferredRequest).page,
      "progress",
    );

    for (const status of ["completed", "no_checks_completed", "partial", "failed", "cancelled"] as const) {
      const finished = run("active", status, 1);
      const opened = pageForSelectedRunLifecycle("progress", finished, [finished], deferredRequest);
      assert.equal(opened.page, deferredPage);
      assert.equal(opened.run?.id, finished.id);
      assert.equal(opened.awaitedRun, undefined);
    }
  }

  assert.equal(pageForSelectedRunLifecycle("progress", undefined, []).page, "progress");
  const completed = run("completed", "completed", 1);
  assert.equal(pageForSelectedRunLifecycle("progress", completed, [completed]).page, "progress");
});

test("a real page transition focuses the new heading and scrolls to the viewport origin once", () => {
  const focusOptions: FocusOptions[] = [];
  const scrollOptions: ScrollToOptions[] = [];
  let mainFocusCount = 0;
  const heading: PageTransitionFocusTarget = {
    focus: (options) => focusOptions.push(options ?? {}),
  };
  const mainContent: PageTransitionMainContent = {
    querySelector: (selector) => {
      assert.equal(selector, "[data-page-heading]");
      return heading;
    },
    focus: () => { mainFocusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "start:case-a",
    nextKey: "cases:case-a",
    mainContent,
    viewport: { scrollTo: (options) => scrollOptions.push(options) },
  }), true);

  assert.deepEqual(focusOptions, [{ preventScroll: true }]);
  assert.equal(mainFocusCount, 0);
  assert.deepEqual(scrollOptions, [{ top: 0, left: 0, behavior: "auto" }]);
});

test("same-page rerenders preserve reading position and focus", () => {
  let focusCount = 0;
  let scrollCount = 0;
  const mainContent: PageTransitionMainContent = {
    querySelector: () => ({ focus: () => { focusCount += 1; } }),
    focus: () => { focusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "findings:case-a",
    nextKey: "findings:case-a",
    mainContent,
    viewport: { scrollTo: () => { scrollCount += 1; } },
  }), false);
  assert.equal(focusCount, 0);
  assert.equal(scrollCount, 0);
});

test("a page without a marked heading falls back to the main landmark", () => {
  const focusOptions: FocusOptions[] = [];
  const mainContent: PageTransitionMainContent = {
    querySelector: () => null,
    focus: (options) => focusOptions.push(options ?? {}),
  };

  assert.equal(completePageTransition({
    previousKey: "cases:case-a",
    nextKey: "progress:case-a",
    mainContent,
    viewport: { scrollTo: () => undefined },
  }), true);
  assert.deepEqual(focusOptions, [{ preventScroll: true }]);
});

test("switching projects on the same page resets focus and scroll for the new content", () => {
  let focusCount = 0;
  let scrollCount = 0;
  const mainContent: PageTransitionMainContent = {
    querySelector: () => ({ focus: () => { focusCount += 1; } }),
    focus: () => { focusCount += 1; },
  };

  assert.equal(completePageTransition({
    previousKey: "findings:case-a",
    nextKey: "findings:case-b",
    mainContent,
    viewport: { scrollTo: () => { scrollCount += 1; } },
  }), true);
  assert.equal(focusCount, 1);
  assert.equal(scrollCount, 1);
});

test("the shell settles navigation after render and all primary page headings are focusable", async () => {
  const [app, shell, shared, startPage] = await Promise.all([
    source("../../src/App.tsx"),
    source("../../src/components/AppShell.tsx"),
    source("../../src/components/Shared.tsx"),
    source("../../src/pages/StartPage.tsx"),
  ]);

  assert.doesNotMatch(app, /document\.getElementById\("main-content"\)\?\.focus/u);
  assert.match(shell, /pageTransitionKey = `\$\{page\}:\$\{selectedCase\?\.id \?\? ""\}`/u);
  assert.match(shell, /useLayoutEffect\(\(\) => \{[\s\S]*completePageTransition\(\{[\s\S]*previousKey: previousPageTransitionKey\.current,[\s\S]*nextKey: pageTransitionKey,[\s\S]*previousPageTransitionKey\.current = pageTransitionKey;[\s\S]*\}, \[pageTransitionKey\]\);/u);
  assert.match(shared, /<h1 data-page-heading tabIndex=\{-1\}>\{title\}<\/h1>/u);
  assert.match(startPage, /<h1 id="start-page-title" data-page-heading tabIndex=\{-1\}>/u);
});

test("progress links to localized results only after a run reaches a terminal outcome", async () => {
  const progress = await source("../../src/pages/ProgressPage.tsx");
  const statusesStart = progress.indexOf("const terminalRunStatuses");
  const statusesEnd = progress.indexOf("]);", statusesStart);
  const terminalStatuses = progress.slice(statusesStart, statusesEnd);

  assert.ok(statusesStart >= 0 && statusesEnd > statusesStart);
  for (const status of ["completed", "no_checks_completed", "partial", "failed", "cancelled"]) {
    assert.ok(terminalStatuses.includes(`"${status}"`), status);
  }
  assert.match(progress, /selectedRunReport = report\?\.runId === selectedRun\?\.id \? report : undefined/u);
  assert.match(progress, /showResultsAction = Boolean\([\s\S]*terminalRunStatuses\.has\(selectedRun\.status\)/u);
  assert.doesNotMatch(progress, /activeRunHasUsefulSecurityResult/u);
  assert.match(progress, /href="#findings"[\s\S]*text\(copy\.viewResults\)/u);
});
