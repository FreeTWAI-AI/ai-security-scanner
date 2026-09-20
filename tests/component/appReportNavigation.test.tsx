import { act, cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import App from "../../src/App";
import { getDemoSnapshot } from "../../src/data/demo";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { AppSnapshot, ScanRun } from "../../src/types";

let snapshot: AppSnapshot;
let active: ScanRun;
let saved: ScanRun;

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
  window.history.replaceState(null, "", "#progress");
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  snapshot = getDemoSnapshot();
  saved = { ...snapshot.workspace!.runs[0], id: "saved-run", label: "Scan 1", sequence: 1, status: "completed" };
  active = { ...saved, id: "active-run", label: "Scan 2", sequence: 2, status: "running", progress: 50, finishedAt: undefined };
  snapshot.workspace!.runs = [active, saved];
  vi.spyOn(scannerService, "isNative").mockReturnValue(false);
  vi.spyOn(scannerService, "getSnapshot").mockImplementation(async () => ({ mode: "native", data: structuredClone(snapshot) }));
  const previewExport = scannerService.previewExport.bind(scannerService);
  vi.spyOn(scannerService, "previewExport").mockImplementation(async (...args) => ({
    ...await previewExport(...args), mode: "native",
  }));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  window.history.replaceState(null, "", "/");
});

const openApp = async () => {
  const view = render(<I18nProvider><App /></I18nProvider>);
  await view.findByRole("heading", { name: "Follow your scan" });
  return view;
};

const finishActiveRun = async () => {
  snapshot.workspace!.runs = [{ ...active, status: "completed", progress: 100, finishedAt: "2026-09-19T23:59:00Z" }, saved];
  await act(async () => { window.dispatchEvent(new Event("focus")); });
};

test("three sidebar Results clicks stay in findings, and Export follows the finished report until completion", async () => {
  const view = await openApp();
  const resultsButton = within(view.getByRole("navigation")).getByRole("button", { name: "Results" });
  for (let click = 0; click < 3; click += 1) {
    fireEvent.click(resultsButton);
    await waitFor(() => expect(window.location.hash).toBe("#findings"));
    expect((view.getByLabelText("Report run") as HTMLSelectElement).value).toBe(saved.id);
    expect(view.getByText(/Showing a finished scan/)).toBeTruthy();
  }
  fireEvent.change(view.getByLabelText("Report run"), { target: { value: active.id } });
  await waitFor(() => expect((view.getByLabelText("Report run") as HTMLSelectElement).value).toBe(saved.id));
  expect(window.location.hash).toBe("#findings");

  fireEvent.click(view.getByRole("button", { name: "Save or share report" }));
  await waitFor(() => expect(window.location.hash).toBe("#export"));
  expect(view.getByText(/Showing a finished scan/)).toBeTruthy();
  await waitFor(() => expect(scannerService.previewExport).toHaveBeenLastCalledWith(
    expect.objectContaining({ runId: saved.id }), expect.anything(),
  ));
  await finishActiveRun();
  await waitFor(() => expect(view.queryByText(/Showing a finished scan/)).toBeNull());
  await waitFor(() => expect(scannerService.previewExport).toHaveBeenLastCalledWith(
    expect.objectContaining({ runId: active.id }), expect.anything(),
  ));
  expect(window.location.hash).toBe("#export");
});

test("choosing a saved run explicitly cancels the automatic switch to the running scan", async () => {
  const view = await openApp();
  fireEvent.click(within(view.getByRole("navigation")).getByRole("button", { name: "Results" }));
  await view.findByLabelText("Report run");
  fireEvent.change(view.getByLabelText("Report run"), { target: { value: saved.id } });
  await finishActiveRun();
  await waitFor(() => expect((view.getByLabelText("Report run") as HTMLSelectElement).value).toBe(saved.id));
  expect(view.queryByText(/Showing a finished scan/)).toBeNull();
});

test("without a saved report each Results click focuses the waiting notice, then completion opens Results", async () => {
  snapshot.workspace!.runs = [active];
  const view = await openApp();
  const resultsButton = within(view.getByRole("navigation")).getByRole("button", { name: "Results" });
  for (let click = 0; click < 3; click += 1) {
    resultsButton.focus();
    fireEvent.click(resultsButton);
    await waitFor(() => expect(window.location.hash).toBe("#progress"));
    const notice = await view.findByText("Results are not open yet");
    expect(document.activeElement?.contains(notice)).toBe(true);
  }
  await finishActiveRun();
  await waitFor(() => expect(window.location.hash).toBe("#findings"));
  expect((view.getByLabelText("Report run") as HTMLSelectElement).value).toBe(active.id);
});
