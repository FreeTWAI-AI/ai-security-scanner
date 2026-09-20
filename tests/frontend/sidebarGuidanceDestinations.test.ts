import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { pageForSelectedRunLifecycle } from "../../src/pageNavigation.ts";
import type { PageId, ScanRun } from "../../src/types.ts";

// Active work has one destination; the sidebar does not list it. Routing takes
// the reader there. Guidance that names that page's label as a place to open
// sends a beginner to a menu item that is not there.

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const readSrc = (relative: string): string => readFileSync(join(repoRoot, relative), "utf8");
const appShellSource = readSrc("src/components/AppShell.tsx");
const englishMessages = readSrc("src/i18n/locales/en.ts");
const chineseMessages = readSrc("src/i18n/locales/zh-TW.ts");

const activeRunStatuses = ["queued", "running", "paused"] as const satisfies ReadonlyArray<
  ScanRun["status"]
>;

const parseBlock = (source: string, startMarker: string, endMarker: string): string => {
  const start = source.indexOf(startMarker);
  assert.ok(start >= 0, `missing ${startMarker}`);
  const end = source.indexOf(endMarker, start);
  assert.ok(end > start, `missing ${endMarker} after ${startMarker}`);
  return source.slice(start, end);
};

const navigation = [...parseBlock(
  appShellSource,
  "const navigation = [",
  "] as const",
).matchAll(/\{\s*id:\s*"(?<id>[^"]+)",\s*labelKey:\s*"(?<labelKey>[^"]+)"/gu)].map((match) => {
  assert.ok(match.groups?.id && match.groups.labelKey);
  return { id: match.groups.id as PageId, labelKey: match.groups.labelKey };
});

const pageLabelKeys = Object.fromEntries(
  [...parseBlock(
    appShellSource,
    "const pageLabelKeys = {",
    "} as const",
  ).matchAll(/^\s*(?<id>[a-z]+):\s*"(?<labelKey>[^"]+)"/gmu)].map((match) => {
    assert.ok(match.groups?.id && match.groups.labelKey);
    return [match.groups.id as PageId, match.groups.labelKey];
  }),
) as Record<PageId, string>;

const bilingualValues = (source: string): Array<{ locale: "en" | "zhTW"; text: string }> => {
  const values: Array<{ locale: "en" | "zhTW"; text: string }> = [];
  for (const locale of ["en", "zhTW"] as const) {
    const quoted = new RegExp(String.raw`\b${locale}:\s*"((?:\\.|[^"\\])*)"`, "gu");
    for (const match of source.matchAll(quoted)) values.push({ locale, text: match[1] ?? "" });
  }
  return values;
};

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const messageFor = (source: string, key: string): string => {
  const match = source.match(new RegExp(String.raw`"${escapeRegExp(key)}":\s*"((?:\\.|[^"\\])*)"`, "u"));
  assert.ok(match?.[1], `${key} should exist in the locale file`);
  return match[1];
};

const namesAsDestination = (text: string, label: string, locale: "en" | "zhTW"): boolean => {
  if (!text.includes(label)) return false;
  if (locale === "en") {
    return new RegExp(
      String.raw`(?:open|go to|from|return to|continue in)\s+${escapeRegExp(label)}`,
      "iu",
    ).test(text);
  }
  if (text.includes(`「${label}」`) && /請到|打開|開啟|回到|再到|從|可以到|可到/u.test(text)) return true;
  return new RegExp(`(?:請到|打開|開啟|回到|再到|可以到|可到)${escapeRegExp(label)}`, "u").test(text);
};

const listCopyFiles = (): string[] => {
  const files: string[] = [];
  const visit = (relativeDir: string) => {
    for (const entry of readdirSync(join(repoRoot, relativeDir), { withFileTypes: true })) {
      const relative = `${relativeDir}/${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name === "i18n") continue;
        visit(relative);
        continue;
      }
      if (!/\.(?:ts|tsx)$/u.test(entry.name)) continue;
      // AppShell defines the sidebar the test reads. ProgressPage is the
      // routed destination itself, so its heading may name that page.
      if (
        relative === "src/components/AppShell.tsx"
        || relative === "src/pages/ProgressPage.tsx"
      ) continue;
      files.push(relative);
    }
  };
  visit("src");
  return files.sort();
};

test("user-facing guidance does not name a destination absent from the sidebar", () => {
  assert.ok(navigation.length > 0, "the sidebar navigation array should be present");
  const sidebarIds = new Set(navigation.map((item) => item.id));
  const sidebarLabels = {
    en: new Set(navigation.map((item) => messageFor(englishMessages, item.labelKey))),
    zhTW: new Set(navigation.map((item) => messageFor(chineseMessages, item.labelKey))),
  };
  assert.equal(sidebarLabels.en.size, navigation.length);
  assert.equal(sidebarLabels.zhTW.size, navigation.length);

  const routedAbsentIds = new Set<PageId>();
  for (const item of navigation) {
    for (const status of activeRunStatuses) {
      const destination = pageForSelectedRunLifecycle(item.id, { status });
      if (!sidebarIds.has(destination)) routedAbsentIds.add(destination);
    }
  }
  assert.ok(
    routedAbsentIds.size > 0,
    "routing still sends the reader to a page the sidebar does not list",
  );

  const deadEndLabels = [...routedAbsentIds].flatMap((id) => {
    const labelKey = pageLabelKeys[id];
    assert.ok(labelKey, `${id} should have a page label key`);
    return [
      { locale: "en" as const, label: messageFor(englishMessages, labelKey) },
      { locale: "zhTW" as const, label: messageFor(chineseMessages, labelKey) },
    ];
  });
  for (const { label } of deadEndLabels) assert.ok(label.length > 0);

  const hits: string[] = [];
  for (const relative of listCopyFiles()) {
    const source = readFileSync(join(repoRoot, relative), "utf8");
    for (const { locale, text } of bilingualValues(source)) {
      for (const deadEnd of deadEndLabels) {
        if (deadEnd.locale !== locale) continue;
        if (!namesAsDestination(text, deadEnd.label, locale)) continue;
        hits.push(`${relative}: ${JSON.stringify(text)} names ${JSON.stringify(deadEnd.label)}`);
      }
    }
  }

  assert.deepEqual(hits, []);
});

test("Chinese 可到 copy names a destination absent from the sidebar, and in-place refresh copy does not", () => {
  const label = messageFor(chineseMessages, pageLabelKeys.progress);
  assert.equal(
    namesAsDestination(`可到「${label}」查看每個工具的狀態。`, label, "zhTW"),
    true,
  );
  assert.equal(
    namesAsDestination("請重新整理「掃描進度」。", label, "zhTW"),
    false,
  );
});
