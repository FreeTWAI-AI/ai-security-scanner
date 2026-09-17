import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

import { validateEngineInputHashes } from "./validate-engine-input-hashes.mjs";
import { validateEngineLineEndings } from "./validate-engine-line-endings.mjs";

export const REQUIRED_VERIFICATIONS = Object.freeze([
  "validate:engine-input-hashes",
  "validate:engine-catalog",
  "validate:engine-line-endings",
]);

const POLICY_STATUSES = new Set(["eligible", "frozen", "experimental"]);
const REFRESH_KINDS = new Set(["revision", "provenance"]);
const ENGINE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const INPUT_HASH_POLICY_PATH = "engines/image-input-hash-policy.json";
const REVISION_CATALOG_INTERPRETATION = "Completing an upstream revision refresh requires a re-pinned source archive with a new SHA-256 checksum, a Dockerfile revision update, and a rebuilt image; those network, registry, and owner-authorized publication steps are outside this offline pipeline.";

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function isoDate(value) {
  return new Date(value).toISOString().slice(0, 10);
}

function addUtcDays(dateString, days) {
  const date = new Date(`${dateString}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function timestampPath(value) {
  return new Date(value).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function isSafeRelativePath(path) {
  return typeof path === "string"
    && path.length > 0
    && !isAbsolute(path)
    && !path.includes("\\")
    && !path.includes("\0")
    && !path.split("/").includes("..");
}

function inside(parent, child) {
  const path = relative(parent, child);
  return path === "" || !path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path);
}

function artifactCoordinate(artifact) {
  if (!artifact || typeof artifact.repository !== "string") return null;
  const tag = artifact.tag === null ? "<unpublished>" : artifact.tag;
  const digest = artifact.digest === null ? "<unpublished>" : artifact.digest;
  return `${artifact.repository}:${tag}@${digest}`;
}

export function validateRefreshPolicy(policy) {
  const errors = [];
  if (policy?.schema_version !== 1) errors.push("refresh policy schema_version must be 1");
  if (!Array.isArray(policy?.engines)) {
    errors.push("refresh policy engines must be an array");
    return errors;
  }
  const seen = new Set();
  for (const [index, entry] of policy.engines.entries()) {
    const label = `refresh policy engines[${index}]`;
    if (!ENGINE_ID_PATTERN.test(entry?.id ?? "")) errors.push(`${label}.id is invalid`);
    if (seen.has(entry?.id)) errors.push(`${label}.id duplicates ${entry.id}`);
    seen.add(entry?.id);
    if (!POLICY_STATUSES.has(entry?.status)) errors.push(`${label}.status is invalid`);
    if (typeof entry?.reason !== "string" || entry.reason.trim() !== entry.reason || entry.reason.length === 0) {
      errors.push(`${label}.reason must be a non-empty trimmed string`);
    }
  }
  return errors;
}

function policyForEngine(policy, engineId) {
  const entry = policy.engines.find(({ id }) => id === engineId);
  return entry ?? {
    id: engineId,
    status: "unsupported",
    reason: `No refresh-policy entry exists for engine ${engineId}; unknown engines fail closed.`,
  };
}

function gitRead(repository, args) {
  const result = spawnSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0) {
    return {
      ok: false,
      reason: result.error?.message ?? (result.stderr.trim() || `git exited ${result.status}`),
    };
  }
  return { ok: true, value: result.stdout.trim() };
}

function normalizeRepository(value) {
  return typeof value === "string" ? value.replace(/\.git$/, "").replace(/\/$/, "") : value;
}

function resolveInputs(root, engineId, policy, now) {
  const planRelative = `engines/images/${engineId}/plan.json`;
  const planPath = resolve(root, planRelative);
  const policyEntry = policyForEngine(policy, engineId);
  if (!existsSync(planPath)) {
    return {
      plan: null,
      planText: null,
      planRelative,
      policy: policyEntry,
      generatedAt: new Date(now).toISOString(),
      error: `Engine plan is unavailable at ${planRelative}.`,
    };
  }

  let plan;
  let planText;
  try {
    planText = readFileSync(planPath, "utf8");
    plan = JSON.parse(planText);
  } catch (error) {
    return {
      plan: null,
      planText: null,
      planRelative,
      policy: policyEntry,
      generatedAt: new Date(now).toISOString(),
      error: `Engine plan could not be read as JSON: ${error.message}`,
    };
  }

  const pinnedRevision = plan.source?.revision ?? null;
  const checkoutRelative = plan.source?.local_research_checkout ?? null;
  const checkoutPath = checkoutRelative && isSafeRelativePath(checkoutRelative)
    ? resolve(root, checkoutRelative)
    : null;
  let checkout;
  if (!checkoutPath || !inside(root, checkoutPath)) {
    checkout = {
      status: "unavailable",
      path: checkoutRelative,
      reason: "The plan does not name a safe local research checkout.",
      revision: null,
      comparison: "unavailable",
    };
  } else if (!existsSync(checkoutPath)) {
    checkout = {
      status: "unavailable",
      path: checkoutRelative,
      reason: "The local research checkout is absent; upstream drift could not be inspected there.",
      revision: null,
      comparison: "unavailable",
    };
  } else {
    const revision = gitRead(checkoutPath, ["rev-parse", "HEAD"]);
    const worktree = gitRead(checkoutPath, ["status", "--porcelain"]);
    if (!revision.ok || !REVISION_PATTERN.test(revision.value)) {
      checkout = {
        status: "unavailable",
        path: checkoutRelative,
        reason: `The local research checkout could not provide a commit: ${revision.reason ?? "invalid revision"}`,
        revision: null,
        comparison: "unavailable",
      };
    } else {
      checkout = {
        status: "available",
        path: checkoutRelative,
        revision: revision.value,
        comparison: revision.value === pinnedRevision ? "match" : "different",
        worktree: worktree.ok ? worktree.value.length === 0 ? "clean" : "dirty" : "unavailable",
        worktree_reason: worktree.ok ? null : worktree.reason,
      };
    }
  }

  const lockPath = resolve(root, "engines/upstreams.lock.json");
  let lock = {
    status: "unavailable",
    path: "engines/upstreams.lock.json",
    revision: null,
    comparison: "unavailable",
    reason: "The upstream lock could not be read.",
  };
  try {
    const lockDocument = readJson(lockPath);
    const repository = normalizeRepository(plan.source?.repository);
    const match = (lockDocument.repositories ?? []).find((entry) =>
      entry.path === checkoutRelative || normalizeRepository(entry.remote) === repository
    );
    if (match) {
      lock = {
        status: "available",
        path: "engines/upstreams.lock.json",
        repository_path: match.path,
        repository: match.remote,
        revision: match.revision,
        comparison: match.revision === pinnedRevision ? "match" : "different",
        checkout_comparison: checkout.revision === null
          ? "unavailable"
          : match.revision === checkout.revision ? "match" : "different",
      };
    } else {
      lock.reason = "No lock entry matches the plan repository or local checkout.";
    }
  } catch (error) {
    lock.reason = `The upstream lock could not be read: ${error.message}`;
  }

  const comparisons = [checkout.comparison, lock.comparison];
  const driftStatus = comparisons.includes("different")
    ? "detected"
    : comparisons.includes("unavailable") ? "unavailable" : "none";
  const driftSummary = driftStatus === "detected"
    ? "At least one available offline source differs from the pinned plan revision."
    : driftStatus === "unavailable"
      ? "At least one offline source was unavailable; this is not a no-drift result."
      : "Every available required offline source matches the pinned plan revision.";

  return {
    plan,
    planText,
    planRelative,
    planPath,
    policy: policyEntry,
    generatedAt: new Date(now).toISOString(),
    inputs: {
      plan: {
        status: "available",
        path: planRelative,
        source_repository: plan.source?.repository ?? null,
        source_revision: pinnedRevision,
        knowledge_date: plan.knowledge_date ?? null,
        support_until: plan.support_until ?? null,
        publish_state: plan.publish_state ?? null,
        final_artifact: clone(plan.final_artifact ?? null),
        final_artifact_coordinate: artifactCoordinate(plan.final_artifact),
      },
      local_research_checkout: checkout,
      upstream_lock: lock,
    },
    drift: {
      status: driftStatus,
      summary: driftSummary,
      pinned_revision: pinnedRevision,
      checkout_revision: checkout.revision,
      lock_revision: lock.revision,
    },
  };
}

function findDigestRecords(value, path = "", records = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => findDigestRecords(entry, `${path}[${index}]`, records));
  } else if (value && typeof value === "object") {
    if (isSafeRelativePath(value.path) && SHA256_PATTERN.test(value.sha256 ?? "")) {
      records.push({ object: value, field: path ? `${path}.sha256` : "sha256", filePath: value.path });
    }
    for (const [key, entry] of Object.entries(value)) {
      findDigestRecords(entry, path ? `${path}.${key}` : key, records);
    }
  }
  return records;
}

function digestSourcePath(root, checkoutPath, filePath) {
  const rootCandidate = resolve(root, filePath);
  if (inside(root, rootCandidate) && existsSync(rootCandidate) && lstatSync(rootCandidate).isFile()) {
    return { path: rootCandidate, source: "repository_worktree" };
  }
  if (checkoutPath) {
    const checkoutCandidate = resolve(checkoutPath, filePath);
    if (inside(checkoutPath, checkoutCandidate) && existsSync(checkoutCandidate) && lstatSync(checkoutCandidate).isFile()) {
      return { path: checkoutCandidate, source: "local_research_checkout" };
    }
  }
  return null;
}

export function mechanicalProvider({ root, resolved }) {
  const proposedPlan = clone(resolved.plan);
  const attributions = [];
  const checkout = resolved.inputs.local_research_checkout;
  const checkoutPath = checkout.status === "available" ? resolve(root, checkout.path) : null;

  if (checkout.status === "available" && checkout.revision !== proposedPlan.source?.revision) {
    const beforeRevision = proposedPlan.source.revision;
    proposedPlan.source.revision = checkout.revision;
    attributions.push({
      provider: "mechanical",
      file: resolved.planRelative,
      field: "source.revision",
      before: beforeRevision,
      after: checkout.revision,
      reason: "The local research checkout HEAD is the offline refresh candidate.",
    });
    const acquisition = `${normalizeRepository(proposedPlan.source.repository)}/commit/${checkout.revision}`;
    if (proposedPlan.source.acquisition_source !== acquisition) {
      attributions.push({
        provider: "mechanical",
        file: resolved.planRelative,
        field: "source.acquisition_source",
        before: proposedPlan.source.acquisition_source ?? null,
        after: acquisition,
        reason: "The acquisition URL follows the selected exact upstream commit.",
      });
      proposedPlan.source.acquisition_source = acquisition;
    }
  }

  for (const record of findDigestRecords(proposedPlan)) {
    const source = digestSourcePath(root, checkoutPath, record.filePath);
    if (!source) continue;
    const digest = sha256(readFileSync(source.path));
    if (digest === record.object.sha256) continue;
    const before = record.object.sha256;
    record.object.sha256 = digest;
    attributions.push({
      provider: "mechanical",
      file: resolved.planRelative,
      field: record.field,
      input_file: record.filePath,
      input_source: source.source,
      before,
      after: digest,
      reason: "The recorded SHA-256 was recomputed from the current file bytes.",
    });
  }

  if (attributions.length > 0) {
    const knowledgeDate = isoDate(resolved.generatedAt);
    const supportUntil = addUtcDays(knowledgeDate, 90);
    for (const [field, after] of [["knowledge_date", knowledgeDate], ["support_until", supportUntil]]) {
      if (proposedPlan[field] === after) continue;
      attributions.push({
        provider: "mechanical",
        file: resolved.planRelative,
        field,
        before: proposedPlan[field] ?? null,
        after,
        reason: field === "knowledge_date"
          ? "The knowledge date records when the offline refresh proposal was produced."
          : "The support window retains the plan's 90-day maintenance interval.",
      });
      proposedPlan[field] = after;
    }
  }

  const text = `${JSON.stringify(proposedPlan, null, 2)}\n`;
  const changes = new Map();
  if (text !== resolved.planText) {
    changes.set(resolved.planRelative, { before: resolved.planText, after: text });
  }
  return {
    id: "mechanical",
    status: "completed",
    rationale: "Deterministic offline updates only: exact revision metadata, maintenance dates, and recorded file digests.",
    changes,
    attributions,
  };
}

function buildInputPurpose(reason) {
  return reason
    .replace(/; only .* is recorded\.$/u, ".")
    .replace(/,? but (?:has no digest in the plan|is absent from the plan|is not itself recorded in the plan|its own bytes are not recorded|absent from the plan)\.$/u, ".")
    .replace(/ but has no plan digest\.$/u, ".");
}

export function provenanceProvider({ root, engineId, resolved }) {
  const policyPath = resolve(root, INPUT_HASH_POLICY_PATH);
  const policyText = readFileSync(policyPath, "utf8");
  const hashPolicy = JSON.parse(policyText);
  if (!Array.isArray(hashPolicy?.uncovered_baseline)) {
    throw new Error(`${INPUT_HASH_POLICY_PATH} does not contain an uncovered_baseline array.`);
  }

  const enginePrefix = `engines/images/${engineId}/`;
  const baselineEntries = hashPolicy.uncovered_baseline.filter(({ path }) =>
    typeof path === "string" && path.startsWith(enginePrefix)
  );
  if (baselineEntries.length === 0) {
    return {
      id: "mechanical",
      status: "completed",
      rationale: `No baselined build-input gaps exist for engine ${engineId}; provenance is already recorded.`,
      noChangeReason: `No baselined build-input gaps exist for engine ${engineId}; provenance is already recorded.`,
      changes: new Map(),
      attributions: [],
    };
  }

  const proposedPlan = clone(resolved.plan);
  if (proposedPlan.build_inputs !== undefined && !Array.isArray(proposedPlan.build_inputs)) {
    throw new Error(`${resolved.planRelative}.build_inputs must be an array when present.`);
  }
  const recordsByPath = new Map((proposedPlan.build_inputs ?? []).map((entry) => [entry?.path, clone(entry)]));
  const attributions = [];
  for (const entry of baselineEntries) {
    if (!isSafeRelativePath(entry.path) || !entry.path.startsWith(enginePrefix)) {
      throw new Error(`Unsafe or cross-engine baseline path: ${entry.path}`);
    }
    const absolute = resolve(root, entry.path);
    if (!inside(root, absolute) || !existsSync(absolute) || !lstatSync(absolute).isFile()) {
      throw new Error(`Baselined build input is not an available regular file: ${entry.path}`);
    }
    const record = {
      path: entry.path,
      sha256: sha256(readFileSync(absolute)),
      purpose: buildInputPurpose(entry.reason),
    };
    recordsByPath.set(entry.path, record);
    attributions.push({
      provider: "mechanical",
      file: resolved.planRelative,
      field: `build_inputs[${entry.path}]`,
      input_file: entry.path,
      input_source: "repository_worktree",
      before: null,
      after: record.sha256,
      reason: `Recorded the exact build-input bytes: ${record.purpose}`,
    });
  }
  proposedPlan.build_inputs = [...recordsByPath.values()].sort((left, right) => left.path.localeCompare(right.path));

  const proposedPolicy = clone(hashPolicy);
  proposedPolicy.uncovered_baseline = proposedPolicy.uncovered_baseline.filter(({ path }) =>
    !baselineEntries.some((entry) => entry.path === path)
  );
  attributions.push({
    provider: "mechanical",
    file: INPUT_HASH_POLICY_PATH,
    field: "uncovered_baseline",
    before: baselineEntries.map(({ path }) => path),
    after: [],
    reason: `Removed only ${engineId}'s ${baselineEntries.length} now-recorded build-input gap${baselineEntries.length === 1 ? "" : "s"} from the uncovered baseline.`,
  });

  const planText = `${JSON.stringify(proposedPlan, null, 2)}\n`;
  const proposedPolicyText = `${JSON.stringify(proposedPolicy, null, 2)}\n`;
  return {
    id: "mechanical",
    status: "completed",
    rationale: `Recorded ${baselineEntries.length} deterministic SHA-256 build-input digest${baselineEntries.length === 1 ? "" : "s"} and removed only ${engineId}'s corresponding uncovered-baseline entries.`,
    changes: new Map([
      [resolved.planRelative, { before: resolved.planText, after: planText }],
      [INPUT_HASH_POLICY_PATH, { before: policyText, after: proposedPolicyText }],
    ]),
    attributions,
  };
}

function parseCliResponse(result) {
  if (result && Array.isArray(result.edits)) return result;
  if (result?.status !== 0) {
    throw new Error(result?.error?.message ?? (result?.stderr?.trim() || `AI CLI exited ${result?.status ?? "without a status"}`));
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`AI CLI did not return valid JSON: ${error.message}`);
  }
}

export function defaultCliRunner({ command, args, input }) {
  return spawnSync(command, args, {
    input,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
}

async function cliProvider({ root, engineId, resolved, base, cliRunner, cliCommand, cliArgs }) {
  if (typeof cliRunner !== "function") throw new Error("The cli provider requires a CLI runner.");
  if (!cliCommand && cliRunner === defaultCliRunner) {
    throw new Error("The cli provider requires --ai-cli <executable>; no AI CLI was invoked.");
  }
  const request = {
    task: "Review and update judgment-dependent adapter files for an offline upstream refresh proposal.",
    constraints: [
      `Only edit text files under engines/images/${engineId}/, excluding plan.json.`,
      "Do not edit engines/catalog.json or any final artifact coordinate.",
      "Return JSON with a rationale string and edits [{path, content, reason}].",
    ],
    engine: engineId,
    inputs: resolved.inputs,
    drift: resolved.drift,
    mechanical_changes: base.attributions,
  };
  const raw = await cliRunner({
    command: cliCommand,
    args: cliArgs ?? [],
    input: `${JSON.stringify(request, null, 2)}\n`,
  });
  const response = parseCliResponse(raw);
  if (typeof response.rationale !== "string" || response.rationale.trim().length === 0) {
    throw new Error("AI CLI response requires a non-empty rationale.");
  }
  const changes = new Map(base.changes);
  const attributions = [...base.attributions];
  for (const [index, edit] of response.edits.entries()) {
    const expectedPrefix = `engines/images/${engineId}/`;
    if (!isSafeRelativePath(edit?.path) || !edit.path.startsWith(expectedPrefix) || edit.path === resolved.planRelative) {
      throw new Error(`AI CLI edit ${index} is outside the permitted adapter directory.`);
    }
    if (typeof edit.content !== "string" || edit.content.includes("\0") || !edit.content.endsWith("\n")) {
      throw new Error(`AI CLI edit ${index} must contain newline-terminated text.`);
    }
    const absolute = resolve(root, edit.path);
    const existing = existsSync(absolute) ? readFileSync(absolute, "utf8") : null;
    const before = changes.get(edit.path)?.before ?? existing;
    if (before === edit.content) continue;
    changes.set(edit.path, { before, after: edit.content });
    attributions.push({
      provider: "cli",
      file: edit.path,
      field: null,
      before: before === null ? null : sha256(before),
      after: sha256(edit.content),
      reason: typeof edit.reason === "string" && edit.reason.trim() ? edit.reason.trim() : response.rationale.trim(),
    });
  }
  return {
    id: "cli",
    status: "completed",
    rationale: response.rationale.trim(),
    changes,
    attributions,
  };
}

function patchLines(text) {
  if (text === null) return [];
  if (!text.endsWith("\n")) throw new Error("Patch inputs must end with a newline.");
  return text.slice(0, -1).split("\n");
}

function diffOperations(oldLines, newLines) {
  const rows = oldLines.length + 1;
  const columns = newLines.length + 1;
  const lengths = Array.from({ length: rows }, () => new Uint32Array(columns));
  for (let oldIndex = oldLines.length - 1; oldIndex >= 0; oldIndex -= 1) {
    for (let newIndex = newLines.length - 1; newIndex >= 0; newIndex -= 1) {
      lengths[oldIndex][newIndex] = oldLines[oldIndex] === newLines[newIndex]
        ? lengths[oldIndex + 1][newIndex + 1] + 1
        : Math.max(lengths[oldIndex + 1][newIndex], lengths[oldIndex][newIndex + 1]);
    }
  }
  const operations = [];
  let oldIndex = 0;
  let newIndex = 0;
  while (oldIndex < oldLines.length || newIndex < newLines.length) {
    if (oldIndex < oldLines.length && newIndex < newLines.length && oldLines[oldIndex] === newLines[newIndex]) {
      operations.push({ type: " ", line: oldLines[oldIndex] });
      oldIndex += 1;
      newIndex += 1;
    } else if (newIndex < newLines.length && (oldIndex === oldLines.length || lengths[oldIndex][newIndex + 1] > lengths[oldIndex + 1][newIndex])) {
      operations.push({ type: "+", line: newLines[newIndex] });
      newIndex += 1;
    } else {
      operations.push({ type: "-", line: oldLines[oldIndex] });
      oldIndex += 1;
    }
  }
  return operations;
}

function unifiedHunks(oldLines, newLines) {
  const operations = diffOperations(oldLines, newLines);
  const changed = operations.flatMap((operation, index) => operation.type === " " ? [] : [index]);
  if (changed.length === 0) return [];
  const ranges = [];
  for (const index of changed) {
    const start = Math.max(0, index - 3);
    const end = Math.min(operations.length - 1, index + 3);
    const prior = ranges.at(-1);
    if (prior && start <= prior.end + 1) prior.end = Math.max(prior.end, end);
    else ranges.push({ start, end });
  }
  let oldLine = 1;
  let newLine = 1;
  const positions = operations.map((operation) => {
    const position = { oldLine, newLine };
    if (operation.type !== "+") oldLine += 1;
    if (operation.type !== "-") newLine += 1;
    return position;
  });
  return ranges.map(({ start, end }) => {
    const selected = operations.slice(start, end + 1);
    const oldCount = selected.filter(({ type }) => type !== "+").length;
    const newCount = selected.filter(({ type }) => type !== "-").length;
    const oldStart = oldCount === 0 ? Math.max(0, positions[start].oldLine - 1) : positions[start].oldLine;
    const newStart = newCount === 0 ? Math.max(0, positions[start].newLine - 1) : positions[start].newLine;
    return [
      `@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`,
      ...selected.map(({ type, line }) => `${type}${line}`),
    ];
  });
}

export function createUnifiedPatch(changes) {
  const chunks = [];
  for (const [path, change] of [...changes].sort(([left], [right]) => left.localeCompare(right))) {
    if (!isSafeRelativePath(path)) throw new Error(`Unsafe patch path: ${path}`);
    const oldLines = patchLines(change.before);
    const newLines = patchLines(change.after);
    chunks.push(`diff --git a/${path} b/${path}`);
    if (change.before === null) chunks.push("new file mode 100644");
    chunks.push(change.before === null ? "--- /dev/null" : `--- a/${path}`);
    chunks.push(`+++ b/${path}`);
    if (change.before === null) {
      chunks.push(`@@ -0,0 +1,${newLines.length} @@`);
      chunks.push(...newLines.map((line) => `+${line}`));
    } else {
      for (const hunk of unifiedHunks(oldLines, newLines)) chunks.push(...hunk);
    }
  }
  return chunks.length === 0 ? "" : `${chunks.join("\n")}\n`;
}

function copyRepositorySnapshot(root, scratch) {
  const listing = spawnSync("git", ["-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (listing.status !== 0) {
    throw new Error(listing.error?.message ?? (listing.stderr.toString("utf8").trim() || "git ls-files failed"));
  }
  const paths = listing.stdout.toString("utf8").split("\0").filter(Boolean);
  for (const path of paths) {
    if (!isSafeRelativePath(path)) throw new Error(`Repository snapshot contains unsafe path: ${path}`);
    const source = resolve(root, path);
    if (!existsSync(source)) continue;
    const destination = resolve(scratch, path);
    if (!inside(scratch, destination)) throw new Error(`Repository snapshot path escaped scratch tree: ${path}`);
    mkdirSync(dirname(destination), { recursive: true });
    const stat = lstatSync(source);
    if (stat.isSymbolicLink()) symlinkSync(readlinkSync(source), destination);
    else if (stat.isFile()) copyFileSync(source, destination);
  }
}

function runScratchCommand(scratch, command, args, input = undefined) {
  const result = spawnSync(command, args, {
    cwd: scratch,
    input,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 180_000,
  });
  const combined = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  const output = combined.length > 6000 ? combined.slice(-6000) : combined;
  if (result.status === null || result.status === undefined) {
    return {
      status: "not_run",
      reason: result.error.code === "ETIMEDOUT"
        ? "The check timed out before it could produce an outcome."
        : `The check could not start: ${result.error.message}`,
      output,
      output_truncated: combined.length > 6000,
    };
  }
  return {
    status: result.status === 0 ? "passed" : "failed",
    reason: result.status === 0 ? null : `The check exited with status ${result.status}.`,
    output,
    output_truncated: combined.length > 6000,
  };
}

function runCatalogWorker(scratch) {
  return new Promise((resolveResult) => {
    let output = "";
    let settled = false;
    let worker;
    const timer = setTimeout(() => {
      worker?.terminate();
      finish({ status: "not_run", reason: "The catalog validator timed out before it produced an outcome." });
    }, 180_000);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const trimmed = output.trim();
      resolveResult({
        ...result,
        output: trimmed.length > 6000 ? trimmed.slice(-6000) : trimmed,
        output_truncated: trimmed.length > 6000,
      });
    };
    worker = new Worker(pathToFileURL(resolve(scratch, "scripts/validate-engine-catalog.mjs")), {
      stdout: true,
      stderr: true,
    });
    worker.stdout.on("data", (chunk) => { output += chunk.toString("utf8"); });
    worker.stderr.on("data", (chunk) => { output += chunk.toString("utf8"); });
    worker.on("error", (error) => finish({
      status: "not_run",
      reason: `The catalog validator could not run: ${error.message}`,
    }));
    worker.on("exit", (code) => finish({
      status: code === 0 ? "passed" : "failed",
      reason: code === 0 ? null : `The check exited with status ${code}.`,
    }));
  });
}

function runHashVerification(scratch, trackedPaths) {
  try {
    const policy = readJson(resolve(scratch, "engines/image-input-hash-policy.json"));
    const report = validateEngineInputHashes({ root: scratch, trackedPaths, policy });
    return {
      status: report.errors.length === 0 ? "passed" : "failed",
      reason: report.errors.length === 0 ? null : `${report.errors.length} engine input hash error(s) were found.`,
      output: report.errors.length === 0
        ? `Verified ${report.records.length} tracked files across ${report.summaries.filter(({ kind }) => kind === "engine").length} engine plans.`
        : report.errors.map((error) => `ERROR ${error}`).join("\n"),
      output_truncated: false,
    };
  } catch (error) {
    return {
      status: "not_run",
      reason: `The engine input hash validator could not run: ${error.message}`,
      output: "",
      output_truncated: false,
    };
  }
}

function runLineEndingVerification(scratch) {
  try {
    const result = validateEngineLineEndings({
      root: scratch,
      gitRunner(args, options = {}) {
        const gitResult = spawnSync("git", ["-C", scratch, ...args], {
          encoding: null,
          maxBuffer: 32 * 1024 * 1024,
          timeout: 180_000,
          ...options,
        });
        if (gitResult.status !== 0) {
          const error = new Error(gitResult.error?.message ?? (gitResult.stderr?.toString("utf8").trim() || `git exited ${gitResult.status}`));
          error.verificationNotRun = Boolean(gitResult.error && gitResult.status === null);
          throw error;
        }
        return gitResult.stdout;
      },
    });
    return {
      status: "passed",
      reason: null,
      output: `Verified ${result.trackedPathCount} current engine inputs are byte-stable in a core.autocrlf=true checkout.`,
      output_truncated: false,
    };
  } catch (error) {
    return {
      status: error.verificationNotRun ? "not_run" : "failed",
      reason: error.verificationNotRun
        ? `The line-ending validator could not run: ${error.message}`
        : error.message,
      output: "",
      output_truncated: false,
    };
  }
}

export async function defaultVerificationRunner({ root, changes, bundleRoot }) {
  mkdirSync(bundleRoot, { recursive: true });
  const scratch = mkdtempSync(join(bundleRoot, ".scratch-"));
  try {
    copyRepositorySnapshot(root, scratch);
    const init = runScratchCommand(scratch, "git", ["init", "--quiet"]);
    if (init.status !== "passed") throw new Error(init.reason ?? init.output);
    let staged = runScratchCommand(scratch, "git", ["add", "--all"]);
    if (staged.status !== "passed") throw new Error(staged.reason ?? staged.output);
    const commit = runScratchCommand(scratch, "git", [
      "-c", "user.name=Upstream Refresh Verification",
      "-c", "user.email=upstream-refresh@invalid",
      "commit", "--quiet", "-m", "scratch baseline",
    ]);
    if (commit.status !== "passed") throw new Error(commit.reason ?? commit.output);

    for (const [path, change] of changes) {
      const destination = resolve(scratch, path);
      if (!inside(scratch, destination)) throw new Error(`Proposed path escaped scratch tree: ${path}`);
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, change.after, "utf8");
    }
    staged = runScratchCommand(scratch, "git", ["add", "--all"]);
    if (staged.status !== "passed") throw new Error(staged.reason ?? staged.output);

    const tracked = spawnSync("git", ["ls-files", "-z", "--", "engines/images"], {
      cwd: scratch,
      encoding: null,
      maxBuffer: 32 * 1024 * 1024,
    });
    const hashCheck = tracked.status !== 0
      ? {
          status: "not_run",
          reason: tracked.error?.message ?? "The tracked engine input list could not be produced.",
          output: tracked.stderr?.toString("utf8").trim() ?? "",
          output_truncated: false,
        }
      : runHashVerification(scratch, tracked.stdout.toString("utf8").split("\0").filter(Boolean));
    const catalogCheck = await runCatalogWorker(scratch);
    const lineEndingCheck = runLineEndingVerification(scratch);
    return [
      { name: REQUIRED_VERIFICATIONS[0], command: "git ls-files -z -- engines/images | node scripts/validate-engine-input-hashes.mjs", ...hashCheck },
      { name: REQUIRED_VERIFICATIONS[1], command: "node scripts/validate-engine-catalog.mjs", ...catalogCheck },
      { name: REQUIRED_VERIFICATIONS[2], command: "node scripts/validate-engine-line-endings.mjs", ...lineEndingCheck },
    ];
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function notRunVerifications(reason) {
  return REQUIRED_VERIFICATIONS.map((name) => ({ name, status: "not_run", reason, command: null, output: "", output_truncated: false }));
}

function allocateBundle(root, engineId, generatedAt, explicitBundleRoot) {
  const bundleRoot = resolve(explicitBundleRoot ?? resolve(root, ".upstream-refresh"));
  if (!explicitBundleRoot && !inside(root, bundleRoot)) throw new Error("Default bundle root escaped the repository.");
  const parent = resolve(bundleRoot, engineId);
  mkdirSync(parent, { recursive: true });
  const stem = timestampPath(generatedAt);
  for (let attempt = 0; attempt < 1000; attempt += 1) {
    const path = resolve(parent, attempt === 0 ? stem : `${stem}-${attempt}`);
    if (existsSync(path)) continue;
    mkdirSync(path);
    return { bundleRoot, bundlePath: path };
  }
  throw new Error("Could not allocate a unique refresh bundle path.");
}

export function prReasons({ policy, changes, verifications, providerError, refreshKind = "revision", noChangeReason }) {
  const reasons = [];
  if (policy.status !== "eligible") reasons.push(`Policy status is ${policy.status}: ${policy.reason}`);
  if (changes.size === 0) reasons.push(noChangeReason ?? "No adapter change was produced.");
  if (providerError) reasons.push(`The selected provider failed: ${providerError}`);
  for (const check of verifications) {
    if (check.status === "failed") {
      reasons.push(`Verification check ${check.name} failed.`);
      if (refreshKind === "revision" && check.name === "validate:engine-catalog") {
        reasons.push(REVISION_CATALOG_INTERPRETATION);
      }
    } else if (check.status === "not_run") reasons.push(`Verification check ${check.name} was not run: ${check.reason}`);
    else if (check.status !== "passed") reasons.push(`Verification check ${check.name} has unsupported status ${check.status}.`);
  }
  for (const name of REQUIRED_VERIFICATIONS) {
    if (!verifications.some((check) => check.name === name)) reasons.push(`Required verification check ${name} is missing.`);
  }
  return [...new Set(reasons)];
}

function riskFacts(policy, changes, verifications) {
  const files = [...changes.keys()].sort();
  const checks = Object.fromEntries(REQUIRED_VERIFICATIONS.map((name) => [
    name,
    verifications.find((check) => check.name === name)?.status ?? "missing",
  ]));
  return [
    { id: "policy_status", value: policy.status, detail: policy.reason },
    { id: "changed_files", value: files.length, detail: files },
    { id: "patch_file_changed", value: files.some((path) => path.endsWith(".patch")), detail: files.filter((path) => path.endsWith(".patch")) },
    { id: "dockerfile_changed", value: files.some((path) => /(^|\/)Dockerfile(?:\.|$)/.test(path)), detail: files.filter((path) => /(^|\/)Dockerfile(?:\.|$)/.test(path)) },
    { id: "verification", value: checks, detail: "A failed, missing, or not_run check prevents PR eligibility." },
  ];
}

function markdownCell(value) {
  return String(value ?? "—").replaceAll("|", "\\|").replaceAll("\n", " ");
}

export function renderReport(proposal) {
  const changed = proposal.changes.files.length === 0
    ? "No files changed."
    : proposal.changes.files.map((path) => `- \`${path}\``).join("\n");
  const attribution = proposal.changes.attributions.length === 0
    ? "No changes were attributed because no edit was produced."
    : proposal.changes.attributions.map((entry) =>
        `- **${entry.provider}** — \`${entry.file}${entry.field ? `:${entry.field}` : ""}\`: ${entry.reason}`
      ).join("\n");
  const verificationRows = proposal.verification.map((check) =>
    `| ${markdownCell(check.name)} | ${markdownCell(check.status)} | ${markdownCell(check.reason ?? "Completed")} |`
  ).join("\n");
  const verificationDetails = proposal.verification.filter((check) => check.output).map((check) =>
    `<details><summary>${check.name} output${check.output_truncated ? " (tail; truncated)" : ""}</summary>\n\n\`\`\`text\n${check.output}\n\`\`\`\n</details>`
  ).join("\n\n");
  const risk = proposal.risk.facts.map((fact) =>
    `- **${fact.id}:** ${typeof fact.value === "object" ? `\`${JSON.stringify(fact.value)}\`` : markdownCell(fact.value)}${Array.isArray(fact.detail) && fact.detail.length > 0 ? ` — ${fact.detail.map((item) => `\`${item}\``).join(", ")}` : typeof fact.detail === "string" ? ` — ${fact.detail}` : ""}`
  ).join("\n");
  const reasons = proposal.pr_ineligibility_reasons.length === 0
    ? "- None."
    : proposal.pr_ineligibility_reasons.map((reason) => `- ${reason}`).join("\n");
  const checkout = proposal.inputs.local_research_checkout;
  const lock = proposal.inputs.upstream_lock;
  return `# Upstream refresh proposal: ${proposal.engine.id}\n\n`
    + `Generated: ${proposal.generated_at}\n\n`
    + `Refresh kind: **${proposal.refresh_kind ?? "revision"}**\n\n`
    + `Outcome: **${proposal.outcome}**\n\n`
    + `Policy: **${proposal.policy.status}** — ${proposal.policy.reason}\n\n`
    + `Provider: **${proposal.provider.selected}** (${proposal.provider.status}) — ${proposal.provider.rationale}\n\n`
    + `## Inputs\n\n`
    + `| Input | Status | Revision or value | Detail |\n| --- | --- | --- | --- |\n`
    + `| Engine plan | available | ${markdownCell(proposal.inputs.plan.source_revision)} | \`${proposal.inputs.plan.path}\` |\n`
    + `| Adapter | available | ${markdownCell(proposal.adapter.plan)} | provider ${markdownCell(proposal.adapter.provider)} |\n`
    + `| Source repository | available | ${markdownCell(proposal.inputs.plan.source_repository)} | pinned plan input |\n`
    + `| Knowledge date | available | ${markdownCell(proposal.inputs.plan.knowledge_date)} | support until ${markdownCell(proposal.inputs.plan.support_until)} |\n`
    + `| Publish state | available | ${markdownCell(proposal.inputs.plan.publish_state)} | final artifact \`${markdownCell(proposal.inputs.plan.final_artifact_coordinate)}\` |\n`
    + `| Local research checkout | ${checkout.status} | ${markdownCell(checkout.revision)} | ${markdownCell(checkout.reason ?? `${checkout.comparison}; worktree ${checkout.worktree}`)} |\n`
    + `| Upstream lock | ${lock.status} | ${markdownCell(lock.revision)} | ${markdownCell(lock.reason ?? lock.comparison)} |\n\n`
    + `## Offline drift\n\n**${proposal.drift.status}** — ${proposal.drift.summary}\n\n`
    + `## Proposed changes\n\n${changed}\n\n### Attribution\n\n${attribution}\n\n`
    + `## Verification\n\n| Check | Outcome | Detail |\n| --- | --- | --- |\n${verificationRows}\n\n${verificationDetails ? `${verificationDetails}\n\n` : ""}`
    + `## Risk facts\n\n${risk}\n\n`
    + `## PR eligibility\n\n**${proposal.pr_eligible ? "May become a PR" : "May not become a PR"}**.\n\n${reasons}\n\n`
    + `## Bundle artifacts\n\n`
    + proposal.artifacts.map((artifact) => `- \`${artifact.path}\` — ${artifact.description}${artifact.sha256 ? ` (${artifact.sha256})` : ""}`).join("\n")
    + "\n";
}

function proposalForUnavailable({ engineId, resolved, providerId, refreshKind, bundlePath }) {
  const reason = resolved.error ?? resolved.policy.reason;
  const verification = notRunVerifications(reason);
  const changes = new Map();
  const patch = "";
  const reasons = prReasons({ policy: resolved.policy, changes, verifications: verification, providerError: resolved.error, refreshKind });
  return {
    proposal: {
      schema_version: 1,
      refresh_kind: refreshKind,
      generated_at: resolved.generatedAt,
      outcome: resolved.policy.status === "frozen" ? "frozen" : "unsupported",
      engine: { id: engineId, adapter_plan: resolved.planRelative },
      adapter: { plan: resolved.planRelative, changed_files: [], provider: providerId },
      policy: resolved.policy,
      provider: { selected: providerId, status: "not_run", rationale: reason },
      inputs: resolved.inputs ?? {
        plan: { status: "unavailable", path: resolved.planRelative },
        local_research_checkout: { status: "not_run", revision: null, comparison: "unavailable", reason },
        upstream_lock: { status: "not_run", revision: null, comparison: "unavailable", reason },
      },
      drift: resolved.drift ?? { status: "unavailable", summary: reason },
      changes: { produced: false, files: [], attributions: [] },
      verification,
      risk: { facts: riskFacts(resolved.policy, changes, verification) },
      artifacts: [
        { path: "proposal.json", description: "Structured proposal record." },
        { path: "changes.patch", description: "Empty patch because the refresh was refused or unsupported.", sha256: sha256(patch) },
        { path: "report.md", description: "Human-readable proposal report." },
      ],
      pr_eligible: false,
      pr_ineligibility_reasons: reasons,
      bundle_path: bundlePath,
    },
    patch,
  };
}

function writeBundle(bundlePath, proposal, patch) {
  const report = renderReport(proposal);
  writeFileSync(resolve(bundlePath, "changes.patch"), patch, "utf8");
  writeFileSync(resolve(bundlePath, "proposal.json"), `${JSON.stringify(proposal, null, 2)}\n`, "utf8");
  writeFileSync(resolve(bundlePath, "report.md"), report, "utf8");
  return report;
}

export async function refreshEngine({
  root,
  engineId,
  providerId = "mechanical",
  refreshKind = "revision",
  now = new Date(),
  policy: suppliedPolicy,
  cliRunner,
  cliCommand,
  cliArgs = [],
  verificationRunner = defaultVerificationRunner,
  bundleRoot: explicitBundleRoot,
}) {
  if (!ENGINE_ID_PATTERN.test(engineId ?? "")) throw new Error(`Invalid engine id: ${engineId}`);
  if (!REFRESH_KINDS.has(refreshKind)) throw new Error(`Unsupported refresh kind: ${refreshKind}`);
  if (!["mechanical", "cli"].includes(providerId)) throw new Error(`Unsupported provider: ${providerId}`);
  if (refreshKind === "provenance" && providerId !== "mechanical") {
    throw new Error("The provenance refresh kind supports only the deterministic mechanical provider.");
  }
  const policy = suppliedPolicy ?? readJson(resolve(root, "engines/upstream-refresh-policy.json"));
  const policyErrors = validateRefreshPolicy(policy);
  if (policyErrors.length > 0) throw new Error(policyErrors.join("\n"));
  const resolved = resolveInputs(root, engineId, policy, now);
  const { bundleRoot, bundlePath } = allocateBundle(root, engineId, resolved.generatedAt, explicitBundleRoot);

  if (!resolved.plan || resolved.policy.status === "frozen" || resolved.policy.status === "unsupported") {
    const { proposal, patch } = proposalForUnavailable({ engineId, resolved, providerId, refreshKind, bundlePath });
    const report = writeBundle(bundlePath, proposal, patch);
    return { proposal, patch, report, bundlePath };
  }

  let provider;
  let baseProvider;
  let providerError = null;
  try {
    baseProvider = refreshKind === "provenance"
      ? provenanceProvider({ root, engineId, resolved })
      : mechanicalProvider({ root, resolved });
    provider = providerId === "mechanical"
      ? baseProvider
      : await cliProvider({ root, engineId, resolved, base: baseProvider, cliRunner: cliRunner ?? defaultCliRunner, cliCommand, cliArgs });
  } catch (error) {
    providerError = error.message;
    provider = {
      id: providerId,
      status: "failed",
      rationale: error.message,
      changes: baseProvider?.changes ?? new Map(),
      attributions: baseProvider?.attributions ?? [],
    };
  }

  const patch = createUnifiedPatch(provider.changes);
  let verification;
  if (provider.changes.size === 0) {
    verification = notRunVerifications("No proposed changes were produced, so there was no proposed tree to verify.");
  } else {
    try {
      verification = await verificationRunner({ root, changes: provider.changes, bundleRoot, engineId });
    } catch (error) {
      verification = notRunVerifications(`The scratch verification tree could not be prepared: ${error.message}`);
    }
  }
  const reasons = prReasons({
    policy: resolved.policy,
    changes: provider.changes,
    verifications: verification,
    providerError,
    refreshKind,
    noChangeReason: provider.noChangeReason,
  });
  const prEligible = reasons.length === 0;
  const outcome = resolved.policy.status === "experimental"
    ? "experimental"
    : providerError ? "failed"
      : provider.changes.size === 0 ? "no_change"
        : prEligible ? "ready" : "verification_failed";
  const files = [...provider.changes.keys()].sort();
  const proposal = {
    schema_version: 1,
    refresh_kind: refreshKind,
    generated_at: resolved.generatedAt,
    outcome,
    engine: { id: engineId, adapter_plan: resolved.planRelative },
    adapter: { plan: resolved.planRelative, changed_files: files, provider: providerId },
    policy: resolved.policy,
    provider: {
      selected: providerId,
      status: provider.status,
      rationale: provider.rationale,
      model_invoked: providerId === "cli" && provider.status === "completed",
    },
    inputs: resolved.inputs,
    drift: resolved.drift,
    changes: { produced: files.length > 0, files, attributions: provider.attributions },
    verification,
    risk: { facts: riskFacts(resolved.policy, provider.changes, verification) },
    artifacts: [
      { path: "proposal.json", description: "Structured proposal record." },
      { path: "changes.patch", description: "Unified diff suitable for git apply.", sha256: sha256(patch) },
      { path: "report.md", description: "Human-readable proposal report." },
    ],
    pr_eligible: prEligible,
    pr_ineligibility_reasons: reasons,
    bundle_path: bundlePath,
  };
  const report = writeBundle(bundlePath, proposal, patch);
  return { proposal, patch, report, bundlePath };
}

export async function refreshEngines(options) {
  const results = [];
  for (const engineId of options.engineIds) {
    try {
      results.push(await refreshEngine({ ...options, engineId }));
    } catch (error) {
      results.push({ engineId, error });
    }
  }
  const exitCode = results.some((result) => {
    if (result.error) return true;
    const { proposal } = result;
    if (proposal.policy.status === "experimental") return false;
    if (proposal.policy.status === "frozen" || proposal.policy.status === "unsupported") return true;
    return proposal.outcome === "failed" || proposal.outcome === "verification_failed";
  }) ? 1 : 0;
  return { results, exitCode };
}

export function randomBundleRoot(root) {
  return resolve(root, ".upstream-refresh", `.run-${randomBytes(6).toString("hex")}`);
}
