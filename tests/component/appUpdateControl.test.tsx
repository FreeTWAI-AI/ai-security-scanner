import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { AppUpdateControl } from "../../src/components/AppUpdateControl";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { AppUpdateState } from "../../src/services/appUpdater";

const renderControl = (state: AppUpdateState) =>
  render(
    <I18nProvider>
      <AppUpdateControl state={state} onCheck={() => {}} onInstall={() => {}} />
    </I18nProvider>,
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("an unreachable update check is not presented as a product failure", () => {
  const { container } = renderControl({ phase: "unreachable" });
  const button = container.querySelector("button");

  expect(button).not.toBeNull();
  expect(button!.className).toBe("update-control");
  expect(button!.className).not.toContain("update-control--error");
  expect(button!.textContent).toContain("Could not reach the update service");
  expect(button!.textContent).not.toContain("Update check failed");
  expect(button!.getAttribute("title")).toContain("offline");
  expect(button!.querySelector("svg")?.innerHTML).not.toContain("M10.3 3.6");
});

test("an untrusted update check stays a warning", () => {
  const { container } = renderControl({ phase: "error" });
  const button = container.querySelector("button");

  expect(button).not.toBeNull();
  expect(button!.className).toContain("update-control--error");
  expect(button!.textContent).toContain("Update check failed");
  expect(button!.querySelector("svg")?.innerHTML).toContain("M10.3 3.6");
});
