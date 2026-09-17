import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const REQUIRED_VERIFICATIONS = Object.freeze([
  "validate:engine-input-hashes",
  "validate:engine-catalog",
  "validate:engine-line-endings",
]);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function timestampPath(value) {
  return new Date(value).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeAdapterPath(path, engineId) {
  return typeof path === "string"
    && path.startsWith(`engines/images/${engineId}/`)
    && !path.includes("\\")
    && !path.includes("\0")
    && !path.split("/").includes("..");
}

export function evaluateBundleForPr({ bundlePath }) {
  const absolute = resolve(bundlePath);
  const proposalPath = lstatSync(absolute).isDirectory() ? resolve(absolute, "proposal.json") : absolute;
  const directory = dirname(proposalPath);
  const proposal = readJson(proposalPath);
  const reasons = [];
  if (proposal?.policy?.status !== "eligible") reasons.push(`Policy status is ${proposal?.policy?.status ?? "missing"}.`);
  if (proposal?.changes?.produced !== true || !Array.isArray(proposal?.changes?.files) || proposal.changes.files.length === 0) {
    reasons.push("The bundle contains no proposed adapter change.");
  }
  const engineId = proposal?.engine?.id;
  if (typeof engineId !== "string" || !proposal?.changes?.files?.every?.((path) => safeAdapterPath(path, engineId))) {
    reasons.push("The proposed file list is missing or escapes the selected engine adapter directory.");
  }
  for (const name of REQUIRED_VERIFICATIONS) {
    const checks = proposal?.verification?.filter?.((entry) => entry?.name === name) ?? [];
    if (checks.length !== 1) reasons.push(`Required verification check ${name} must appear exactly once.`);
    else if (checks[0].status !== "passed") reasons.push(`Verification check ${name} is ${checks[0].status ?? "missing"}.`);
  }
  const patchPath = resolve(directory, "changes.patch");
  const patchBytes = existsSync(patchPath) ? readFileSync(patchPath) : null;
  if (!patchBytes || patchBytes.length === 0) reasons.push("changes.patch is missing or empty.");
  const recordedPatchDigest = proposal?.artifacts?.find?.(({ path }) => path === "changes.patch")?.sha256;
  if (!patchBytes || recordedPatchDigest !== sha256(patchBytes)) reasons.push("changes.patch does not match its recorded SHA-256 digest.");
  if (!existsSync(resolve(directory, "report.md"))) reasons.push("report.md is missing.");
  if (proposal?.pr_eligible !== true) reasons.push("The refresh pipeline did not mark this proposal PR-eligible.");
  const uniqueReasons = [...new Set(reasons)];
  const eligible = uniqueReasons.length === 0;
  const branch = `upstream-refresh/${proposal?.engine?.id ?? "unknown"}/${timestampPath(proposal?.generated_at ?? new Date())}`;
  const relativePatch = relative(process.cwd(), patchPath) || "changes.patch";
  const files = Array.isArray(proposal?.changes?.files) ? proposal.changes.files : [];
  const commands = eligible ? [
    `git apply --check ${shellQuote(relativePatch)}`,
    `git switch -c ${shellQuote(branch)}`,
    `git apply ${shellQuote(relativePatch)}`,
    `git add -- ${files.map(shellQuote).join(" ")}`,
    `git commit -m ${shellQuote(`Refresh ${proposal.engine.id} upstream adapter`)}`,
    `git push -u origin ${shellQuote(branch)}`,
    `gh pr create --fill --head ${shellQuote(branch)}`,
  ] : [];
  return { eligible, reasons: uniqueReasons, commands, proposal, proposalPath, patchPath };
}

export function renderProposeResult(result) {
  const lines = [`PR eligible: ${result.eligible ? "yes" : "no"}`];
  if (result.reasons.length > 0) {
    lines.push("Reasons:", ...result.reasons.map((reason) => `- ${reason}`));
  }
  if (result.commands.length > 0) {
    lines.push("Exact commands (not executed):", ...result.commands);
  } else {
    lines.push("Commands: none; this bundle may not become a PR.");
  }
  return `${lines.join("\n")}\n`;
}
