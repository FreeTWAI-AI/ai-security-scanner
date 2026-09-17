#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_ROOT = resolve(import.meta.dirname, "..");
const DEFAULT_POLICY_PATH = "engines/image-input-hash-policy.json";
const IMAGE_PREFIX = "engines/images/";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseTrackedPaths(bytes) {
  const paths = bytes.toString("utf8").split("\0");
  if (paths.at(-1) === "") paths.pop();
  return paths;
}

function validatePolicy(policy) {
  const errors = [];
  if (policy?.schema_version !== 1) errors.push("hash policy schema_version must be 1");
  for (const field of ["exclusions", "directories_without_plans", "uncovered_baseline"]) {
    if (!Array.isArray(policy?.[field])) errors.push(`hash policy ${field} must be an array`);
  }
  if (errors.length > 0) return errors;

  const exclusionIds = new Set();
  for (const rule of policy.exclusions) {
    if (!rule || typeof rule.id !== "string" || rule.id.length === 0) {
      errors.push("every exclusion rule requires a non-empty id");
    } else if (exclusionIds.has(rule.id)) {
      errors.push(`duplicate exclusion rule id: ${rule.id}`);
    } else {
      exclusionIds.add(rule.id);
    }
    if (!["exact", "suffix", "path-segment", "basename-pattern"].includes(rule?.match)) {
      errors.push(`exclusion ${rule?.id ?? "<unknown>"} has unsupported match ${rule?.match ?? "<missing>"}`);
    }
    if (typeof rule?.value !== "string" || rule.value.length === 0) {
      errors.push(`exclusion ${rule?.id ?? "<unknown>"} requires a match value`);
    }
    if (typeof rule?.reason !== "string" || rule.reason.trim().length === 0) {
      errors.push(`exclusion ${rule?.id ?? "<unknown>"} requires a reason`);
    }
  }

  for (const [field, key] of [
    ["directories_without_plans", "directory"],
    ["uncovered_baseline", "path"],
  ]) {
    const values = new Set();
    for (const entry of policy[field]) {
      const value = entry?.[key];
      if (typeof value !== "string" || value.length === 0) {
        errors.push(`every ${field} entry requires a non-empty ${key}`);
      } else if (values.has(value)) {
        errors.push(`duplicate ${field} entry: ${value}`);
      } else {
        values.add(value);
      }
      if (typeof entry?.reason !== "string" || entry.reason.trim().length === 0) {
        errors.push(`${field} entry ${value ?? "<unknown>"} requires a reason`);
      }
      if (field === "directories_without_plans") {
        if (!Array.isArray(entry?.files) || entry.files.length === 0) {
          errors.push(`directories_without_plans entry ${value ?? "<unknown>"} requires exact files`);
        } else {
          const filePaths = new Set();
          for (const file of entry.files) {
            if (typeof file?.path !== "string" || file.path.length === 0 || file.path.includes("/")) {
              errors.push(`directories_without_plans entry ${value ?? "<unknown>"} has an invalid file path`);
            } else if (filePaths.has(file.path)) {
              errors.push(`directories_without_plans entry ${value ?? "<unknown>"} repeats ${file.path}`);
            } else {
              filePaths.add(file.path);
            }
            if (typeof file?.reason !== "string" || file.reason.trim().length === 0) {
              errors.push(
                `directories_without_plans file ${value ?? "<unknown>"}/${file?.path ?? "<unknown>"} requires a reason`,
              );
            }
          }
        }
      }
    }
  }
  return errors;
}

function matchingExclusion(relativePath, rules) {
  for (const rule of rules) {
    const matches = rule.match === "exact"
      ? relativePath === rule.value
      : rule.match === "suffix"
        ? relativePath.endsWith(rule.value)
        : rule.match === "path-segment"
          ? relativePath.split("/").includes(rule.value)
          : rule.match === "basename-pattern"
            ? rule.value === "test_*.py"
              && basename(relativePath).startsWith("test_")
              && basename(relativePath).endsWith(".py")
            : false;
    if (matches) return rule;
  }
  return null;
}

function safeTrackedPath(path) {
  return path.startsWith(IMAGE_PREFIX)
    && !path.includes("\\")
    && !path.includes("\0")
    && !path.split("/").includes("..")
    && path.split("/").length >= 4;
}

export function validateEngineInputHashes({ root, trackedPaths, policy }) {
  const errors = validatePolicy(policy);
  const records = [];
  const directories = new Map();
  const trackedSet = new Set();

  for (const path of trackedPaths) {
    if (!safeTrackedPath(path)) {
      errors.push(`unsafe or out-of-scope tracked engine-image path: ${path}`);
      continue;
    }
    if (trackedSet.has(path)) {
      errors.push(`git returned a duplicate tracked engine-image path: ${path}`);
      continue;
    }
    trackedSet.add(path);
    const [, , directory, ...rest] = path.split("/");
    if (!directories.has(directory)) directories.set(directory, []);
    directories.get(directory).push({ path, relativePath: rest.join("/") });
  }
  if (trackedSet.size === 0) errors.push("git found no tracked files under engines/images");

  const supportByDirectory = new Map(
    (policy?.directories_without_plans ?? []).map((entry) => [entry.directory, entry]),
  );
  const baselineByPath = new Map(
    (policy?.uncovered_baseline ?? []).map((entry) => [entry.path, entry]),
  );

  for (const directory of supportByDirectory.keys()) {
    if (!directories.has(directory)) {
      errors.push(`directories_without_plans entry ${directory} no longer names a tracked directory`);
    }
  }

  for (const [directory, files] of [...directories].sort(([left], [right]) => left.localeCompare(right))) {
    const planPath = `${IMAGE_PREFIX}${directory}/plan.json`;
    const hasPlan = trackedSet.has(planPath);
    const support = supportByDirectory.get(directory);

    if (!hasPlan) {
      if (!support) {
        errors.push(
          `${IMAGE_PREFIX}${directory} has tracked files but no plan.json and is not recorded in directories_without_plans`,
        );
      }
      const supportFiles = new Map((support?.files ?? []).map((file) => [file.path, file]));
      for (const supportFile of supportFiles.values()) {
        const path = `${IMAGE_PREFIX}${directory}/${supportFile.path}`;
        if (!trackedSet.has(path)) {
          errors.push(`directories_without_plans file no longer exists: ${path}`);
        }
      }
      for (const file of files) {
        const exclusion = matchingExclusion(file.relativePath, policy?.exclusions ?? []);
        const supportFile = supportFiles.get(file.relativePath);
        const recorded = Boolean(exclusion || supportFile);
        records.push({
          ...file,
          directory,
          status: recorded ? "excluded" : "uncovered",
          reason: exclusion?.reason ?? supportFile?.reason
            ?? "No plan.json exists in which this file digest could be recorded.",
          reasonId: exclusion?.id ?? (supportFile ? "directory-without-plan" : "missing-plan"),
          baseline: false,
        });
        if (support && !recorded) {
          errors.push(`new uncovered input in recorded directory without plan: ${file.path}`);
        }
      }
      continue;
    }
    if (support) {
      errors.push(`directories_without_plans entry ${directory} is stale because the directory now has plan.json`);
    }

    let planText = "";
    try {
      planText = readFileSync(resolve(root, planPath), "utf8");
      JSON.parse(planText);
    } catch (error) {
      errors.push(`${planPath} could not be read as JSON: ${error.message}`);
    }

    for (const file of files) {
      const exclusion = matchingExclusion(file.relativePath, policy?.exclusions ?? []);
      if (exclusion?.id === "provenance-record") {
        records.push({
          ...file,
          directory,
          status: "excluded",
          reason: exclusion.reason,
          reasonId: exclusion.id,
          baseline: false,
        });
        continue;
      }

      let digest = null;
      try {
        const absolutePath = resolve(root, file.path);
        if (!lstatSync(absolutePath).isFile()) {
          throw new Error("tracked path is not a regular file");
        }
        digest = sha256(readFileSync(absolutePath));
      } catch (error) {
        errors.push(`${file.path} could not be hashed: ${error.message}`);
      }

      const covered = digest !== null && planText.includes(digest);
      const status = covered ? "covered" : exclusion ? "excluded" : "uncovered";
      const baseline = status === "uncovered" && baselineByPath.has(file.path);
      records.push({
        ...file,
        directory,
        digest,
        status,
        reason: covered
          ? "Its SHA-256 digest appears in this engine's plan.json."
          : exclusion?.reason ?? baselineByPath.get(file.path)?.reason
            ?? "Its SHA-256 digest does not appear in this engine's plan.json.",
        reasonId: covered ? "recorded-hash" : exclusion?.id ?? baseline ? "uncovered-baseline" : "uncovered",
        baseline,
      });
    }
  }

  const recordByPath = new Map(records.map((record) => [record.path, record]));
  for (const baselineEntry of policy?.uncovered_baseline ?? []) {
    const record = recordByPath.get(baselineEntry.path);
    if (!record) {
      errors.push(`uncovered baseline entry no longer names a tracked file: ${baselineEntry.path}`);
    } else if (record.status !== "uncovered") {
      errors.push(
        `uncovered baseline entry is stale because the file is now ${record.status}: ${baselineEntry.path}`,
      );
    }
  }
  for (const record of records) {
    if (record.status === "uncovered" && !record.baseline && record.reasonId !== "missing-plan") {
      errors.push(`new uncovered engine input: ${record.path}`);
    }
  }

  const summaries = [...directories.keys()].sort().map((directory) => {
    const matching = records.filter((record) => record.directory === directory);
    return {
      directory,
      kind: trackedSet.has(`${IMAGE_PREFIX}${directory}/plan.json`) ? "engine" : "support",
      covered: matching.filter((record) => record.status === "covered").length,
      excluded: matching.filter((record) => record.status === "excluded").length,
      uncovered: matching.filter((record) => record.status === "uncovered").length,
    };
  });

  return { errors, records, summaries };
}

function printReport(report, policy) {
  const widths = {
    directory: Math.max("Directory".length, ...report.summaries.map(({ directory }) => directory.length)),
    kind: Math.max("Kind".length, ...report.summaries.map(({ kind }) => kind.length)),
  };
  console.log("Engine image input hash coverage:");
  console.log(
    `${"Directory".padEnd(widths.directory)}  ${"Kind".padEnd(widths.kind)}  Covered  Excluded  Uncovered`,
  );
  for (const summary of report.summaries) {
    console.log(
      `${summary.directory.padEnd(widths.directory)}  ${summary.kind.padEnd(widths.kind)}  `
      + `${String(summary.covered).padStart(7)}  ${String(summary.excluded).padStart(8)}  `
      + String(summary.uncovered).padStart(9),
    );
  }

  console.log("\nExplicit exclusion rules:");
  for (const rule of policy.exclusions) console.log(`- ${rule.id}: ${rule.reason}`);
  for (const entry of policy.directories_without_plans) {
    console.log(`- directory-without-plan (${entry.directory}): ${entry.reason}`);
  }

  const excluded = report.records.filter((record) => record.status === "excluded");
  console.log(`\nExcluded tracked files (${excluded.length}):`);
  for (const record of excluded) console.log(`- ${record.path}: ${record.reason}`);

  const baseline = report.records.filter((record) => record.baseline);
  console.log(`\nRecorded uncovered baseline (${baseline.length}):`);
  for (const record of baseline) console.log(`- ${record.path}: ${record.reason}`);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const policy = JSON.parse(readFileSync(resolve(DEFAULT_ROOT, DEFAULT_POLICY_PATH), "utf8"));
  // The npm script pipes `git ls-files -z` into stdin. Keeping Git outside the
  // Node process makes the command portable to restricted build sandboxes, and
  // an empty or failed listing is rejected below instead of becoming a pass.
  const trackedPaths = parseTrackedPaths(readFileSync(0));
  const report = validateEngineInputHashes({ root: DEFAULT_ROOT, trackedPaths, policy });
  printReport(report, policy);
  if (report.errors.length > 0) {
    console.error(`\nEngine input hash validation failed with ${report.errors.length} error(s):`);
    for (const error of report.errors) console.error(`- ${error}`);
    process.exitCode = 1;
  } else {
    const engineCount = report.summaries.filter(({ kind }) => kind === "engine").length;
    const trackedCount = report.records.length;
    const baselineCount = report.records.filter(({ baseline }) => baseline).length;
    console.log(
      `\nVerified ${trackedCount} tracked files across ${engineCount} engine plans; `
      + `${baselineCount} known uncovered inputs remain explicitly baselined.`,
    );
  }
}
