import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const REQUIRED_VERIFICATIONS = Object.freeze([
  "validate:engine-input-hashes",
  "validate:engine-catalog",
  "validate:engine-line-endings",
]);

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

function safeProposalPath(path, engineId, refreshKind) {
  if (refreshKind === "provenance") {
    return path === `engines/images/${engineId}/plan.json`
      || path === "engines/image-input-hash-policy.json";
  }
  return safeAdapterPath(path, engineId);
}

function providerPathClass(providerId) {
  if (providerId === "mechanical") return "formal_default";
  if (providerId === "cli") return "optional_ai";
  return "unknown";
}

function providerPathLabel(pathClass) {
  if (pathClass === "formal_default") return "default deterministic path";
  if (pathClass === "optional_ai") return "optional AI path";
  return "unclassified path";
}

export function evaluateBundleForPr({ bundlePath, decision = "undecided" }) {
  const absolute = resolve(bundlePath);
  const proposalPath = lstatSync(absolute).isDirectory() ? resolve(absolute, "proposal.json") : absolute;
  const directory = dirname(proposalPath);
  const proposalBytes = readFileSync(proposalPath);
  const proposal = JSON.parse(proposalBytes.toString("utf8"));
  const reasons = [];
  if (proposal?.policy?.status !== "eligible") reasons.push(`Policy status is ${proposal?.policy?.status ?? "missing"}.`);
  if (proposal?.changes?.produced !== true || !Array.isArray(proposal?.changes?.files) || proposal.changes.files.length === 0) {
    reasons.push("The bundle contains no proposed adapter change.");
  }
  const engineId = proposal?.engine?.id;
  const refreshKind = proposal?.refresh_kind ?? "revision";
  if (typeof engineId !== "string" || !proposal?.changes?.files?.every?.((path) => safeProposalPath(path, engineId, refreshKind))) {
    reasons.push("The proposed file list is missing or escapes the paths allowed for this refresh kind.");
  }
  if (refreshKind === "provenance" && proposal?.changes?.produced === true) {
    const expected = ["engines/image-input-hash-policy.json", `engines/images/${engineId}/plan.json`].sort();
    const actual = [...new Set(proposal?.changes?.files ?? [])].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      reasons.push("A provenance bundle must change exactly the selected engine plan and the shared input-hash policy.");
    }
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
  const localCommands = eligible ? [
    `git apply --check ${shellQuote(relativePatch)}`,
    `git switch -c ${shellQuote(branch)}`,
    `git apply ${shellQuote(relativePatch)}`,
    `git add -- ${files.map(shellQuote).join(" ")}`,
    `git commit -m ${shellQuote(`Refresh ${proposal.engine.id} upstream adapter`)}`,
  ] : [];
  const commands = eligible && decision === "open" ? [
    ...localCommands,
    `git push -u origin ${shellQuote(branch)}`,
    `gh pr create --fill --head ${shellQuote(branch)}`,
  ] : localCommands;
  const providerId = proposal?.provider?.selected ?? "unknown";
  const pathClass = providerPathClass(providerId);
  return {
    eligible,
    reasons: uniqueReasons,
    commands,
    decision,
    provider: { id: providerId, path_class: pathClass, label: providerPathLabel(pathClass) },
    proposal,
    proposalPath,
    proposalDigest: sha256(proposalBytes),
    patchPath,
    patchDigest: patchBytes ? sha256(patchBytes) : null,
    directory,
  };
}

export function renderProposeResult(result) {
  const lines = [
    `Provider: ${result.provider.id} (${result.provider.label})`,
    `PR decision: ${result.decision}`,
    `PR eligible: ${result.eligible ? "yes" : "no"}`,
  ];
  if (result.reasons.length > 0) {
    lines.push("Reasons:", ...result.reasons.map((reason) => `- ${reason}`));
  }
  if (result.commands.length > 0) {
    lines.push("Exact commands (not executed):", ...result.commands);
  } else {
    lines.push("Commands: none; this bundle may not become a PR.");
  }
  if (result.eligible && result.decision === "keep-local") {
    lines.push("No push or PR-creation command is printed because the client chose to keep the change local.");
  } else if (result.eligible && result.decision === "undecided") {
    lines.push(
      "PR choices:",
      "- Open a PR back to Main: re-run with --open-pr.",
      "- Keep the change local: re-run with --no-open-pr.",
    );
  }
  return `${lines.join("\n")}\n`;
}

export function recordPrDecision(result, now = new Date()) {
  if (result.decision === "undecided") return null;
  const record = {
    schema_version: 1,
    decided_at: new Date(now).toISOString(),
    decision: result.decision,
    engine: result.proposal?.engine?.id ?? null,
    refresh_kind: result.proposal?.refresh_kind ?? "revision",
    provider: {
      id: result.provider.id,
      path_class: result.provider.path_class,
    },
    pr_eligible: result.eligible,
    bundle: {
      proposal: { path: "proposal.json", sha256: result.proposalDigest },
      patch: { path: "changes.patch", sha256: result.patchDigest },
    },
    commands_printed: result.commands,
  };
  writeFileSync(resolve(result.directory, "pr-decision.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
  return resolve(result.directory, "pr-decision.json");
}
