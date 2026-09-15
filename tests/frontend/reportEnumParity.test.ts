import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The report's closed vocabularies are declared twice: once as a Rust enum the
// backend serializes, once as a TypeScript union the app narrows on. A variant
// added on one side and missed on the other compiles, passes every existing
// gate, and reaches the reader as an unhandled value -- a coverage row with no
// label, or a next step the page cannot name.
//
// Nothing else catches it. `tsconfig.app.json` includes only `src`, so a bad
// literal in a test is not even a type error, and the Rust side has no reason
// to know the union exists. This test reads both declarations.

const rust = (file: string) =>
  readFileSync(new URL(`../../src-tauri/src/${file}`, import.meta.url), "utf8");

const typescript = readFileSync(new URL("../../src/types.ts", import.meta.url), "utf8");

const beginnerReport = rust("beginner_report.rs");
const domain = rust("domain.rs");

/** Serde's `rename_all = "snake_case"`: lower-case, `_` before each capital. */
const serdeSnakeCase = (variant: string): string =>
  variant.replaceAll(/(?<!^)[A-Z]/gu, (capital) => `_${capital}`).toLowerCase();

/**
 * The variants of one `#[serde(rename_all = "snake_case")]` enum, as the wire
 * spells them, including any per-variant `serde(rename)` override.
 *
 * The attribute is required rather than assumed: an enum without it serializes
 * its variants verbatim, and comparing those against a snake_case union would
 * report drift that is not there -- or, worse, miss drift that is.
 */
const rustVariants = (source: string, name: string): string[] => {
  const declaration = source.indexOf(`pub enum ${name} {`);
  assert.ok(declaration > 0, `Rust enum ${name} was not found`);
  const attributes = source.slice(Math.max(0, declaration - 400), declaration);
  assert.ok(
    attributes.includes('#[serde(rename_all = "snake_case")]'),
    `${name} is compared as snake_case but does not declare it`,
  );
  const body = source.slice(declaration + `pub enum ${name} {`.length);
  const end = body.indexOf("\n}");
  assert.ok(end > 0, `Rust enum ${name} has no closing brace`);
  return [...body.slice(0, end).matchAll(
    /^(?:[ \t]*#\[serde\(rename = "([^"]+)"\)\][ \t]*\r?\n)?[ \t]*([A-Z][A-Za-z0-9]*),[ \t]*$/gmu,
  )].map((match) => match[1] ?? serdeSnakeCase(match[2]!));
};

/** Variants of an internally tagged Rust enum whose members carry fields. */
const rustTaggedVariants = (source: string, name: string): string[] => {
  const declaration = source.indexOf(`pub enum ${name} {`);
  assert.ok(declaration > 0, `Rust enum ${name} was not found`);
  const attributes = source.slice(Math.max(0, declaration - 400), declaration);
  assert.ok(
    attributes.includes('#[serde(tag = "kind", rename_all = "snake_case")]'),
    `${name} is compared as a kind-tagged snake_case enum but does not declare it`,
  );
  const body = source.slice(declaration + `pub enum ${name} {`.length);
  const end = body.indexOf("\n}");
  assert.ok(end > 0, `Rust enum ${name} has no closing brace`);
  return [...body.slice(0, end).matchAll(
    /^(?:[ \t]*#\[serde\(rename = "([^"]+)"\)\][ \t]*\r?\n)?[ \t]*([A-Z][A-Za-z0-9]*)[ \t]*(?:\{|,)[ \t]*$/gmu,
  )].map((match) => match[1] ?? serdeSnakeCase(match[2]!));
};

/** The string members of one exported TypeScript string-union type. */
const unionMembers = (name: string): string[] => {
  const declaration = typescript.indexOf(`export type ${name} =`);
  assert.ok(declaration > 0, `TypeScript type ${name} was not found`);
  const body = typescript.slice(declaration);
  const end = body.indexOf(";");
  assert.ok(end > 0, `TypeScript type ${name} is not terminated`);
  return [...body.slice(0, end).matchAll(/"([^"]+)"/gu)].map((match) => match[1]!);
};

/** `kind` literals from one exported TypeScript discriminated union. */
const discriminatedUnionMembers = (name: string): string[] => {
  const declaration = typescript.indexOf(`export type ${name} =`);
  assert.ok(declaration > 0, `TypeScript type ${name} was not found`);
  const body = typescript.slice(declaration);
  const nextDeclaration = body.slice(1).search(/\nexport (?:interface|type) /u);
  const definition = nextDeclaration < 0 ? body : body.slice(0, nextDeclaration + 1);
  return [...definition.matchAll(/\bkind:[ \t]*"([^"]+)"/gu)].map((match) => match[1]!);
};

// Every closed vocabulary the app has to narrow on. A new one belongs here the
// day it is added, which is cheaper than the day a reader sees a blank label.
const PAIRS: ReadonlyArray<readonly [source: string, rustName: string, typescriptName: string]> = [
  ["beginner_report.rs", "CoverageGapKind", "BeginnerCoverageGapKind"],
  ["beginner_report.rs", "NextActionCode", "BeginnerNextActionCode"],
  ["beginner_report.rs", "CoverageDimensionStatus", "BeginnerCoverageStatus"],
  ["beginner_report.rs", "BeginnerReportSummary", "BeginnerReportSummary"],
  ["beginner_report.rs", "ReportLifecycle", "BeginnerReportLifecycle"],
  ["beginner_report.rs", "FindingGroupPresentationScope", "BeginnerFindingGroupPresentationScope"],
  ["beginner_report.rs", "ReportScanStage", "BeginnerReportStage"],
  ["beginner_report.rs", "DataAvailability", "BeginnerReportDataAvailability"],
  ["beginner_report.rs", "CheckResultKind", "BeginnerCheckResultKind"],
  ["beginner_report.rs", "RequestedLimitSource", "BeginnerRequestedLimitSource"],
  ["beginner_report.rs", "FindingSnapshotSource", "BeginnerFindingSnapshotSource"],
  ["domain.rs", "AssessmentActivity", "AssessmentActivity"],
  ["domain.rs", "AssessmentIntent", "AssessmentIntent"],
  ["domain.rs", "AiGeneratedArtifactAnswer", "AiGeneratedArtifactAnswer"],
  ["domain.rs", "AssetKind", "AssetKind"],
  ["domain.rs", "AwsIamPolicySource", "AwsIamPolicySource"],
  ["domain.rs", "CaseStatus", "CaseStatusWire"],
  ["domain.rs", "Confidence", "Confidence"],
  ["domain.rs", "ConfidenceBasisCode", "ConfidenceBasisCode"],
  ["domain.rs", "ContextFactor", "ContextFactor"],
  ["domain.rs", "CoverageStatus", "CoverageStatusWire"],
  ["domain.rs", "EvidenceKind", "EvidenceKind"],
  ["domain.rs", "EngineCategory", "EngineCategory"],
  ["domain.rs", "EngineRunStatus", "EngineRunStatusWire"],
  ["domain.rs", "ManifestStatus", "EngineManifestStatusWire"],
  ["domain.rs", "DistributionMode", "DistributionMode"],
  ["domain.rs", "FindingDiffReasonCode", "FindingDiffReasonCode"],
  ["domain.rs", "FindingDiffStatus", "FindingDiffStatus"],
  ["domain.rs", "FindingFamily", "FindingFamily"],
  ["domain.rs", "FindingGroupAction", "FindingGroupAction"],
  ["domain.rs", "FindingStatus", "FindingStatusWire"],
  ["domain.rs", "LocalInputProfile", "LocalInputProfile"],
  ["domain.rs", "LocalhostTcpOutcome", "LocalhostTcpOutcome"],
  ["domain.rs", "KnowledgeInputKind", "KnowledgeInputKind"],
  ["domain.rs", "KnowledgePinState", "KnowledgePinState"],
  ["domain.rs", "ScanRequestOutcomeCode", "ScanRequestOutcomeCode"],
  ["domain.rs", "ScanPermission", "ScanPermissionWire"],
  ["domain.rs", "Severity", "SeverityWire"],
  ["domain.rs", "SeverityBasisCode", "SeverityBasisCode"],
  ["domain.rs", "SourceConnectionStatus", "SourceConnectionStatus"],
  ["domain.rs", "SourceKind", "SourceKind"],
];

const TAGGED_PAIRS: ReadonlyArray<readonly [source: string, rustName: string, typescriptName: string]> = [
  ["beginner_report.rs", "BeginnerInventoryItemKind", "BeginnerInventoryItem"],
  ["beginner_report.rs", "TechnicalExecution", "BeginnerTechnicalExecution"],
  ["domain.rs", "EngineTaskKind", "EngineTaskKind"],
];

for (const [file, rustName, typescriptName] of PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same set of values`, () => {
    const fromRust = rustVariants(file === "domain.rs" ? domain : beginnerReport, rustName);
    const fromTypescript = unionMembers(typescriptName);

    assert.ok(fromRust.length > 0, `${rustName} extracted no variants`);
    // Sets, not sequences: the two files are free to declare in different
    // orders, and neither order reaches the reader.
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

for (const [file, rustName, typescriptName] of TAGGED_PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same kind tags`, () => {
    const fromRust = rustTaggedVariants(file === "domain.rs" ? domain : beginnerReport, rustName);
    const fromTypescript = discriminatedUnionMembers(typescriptName);

    assert.ok(fromRust.length > 0, `${rustName} extracted no tagged variants`);
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

test("the extractor reads real variants, not whatever the regex allows", () => {
  // A silent extraction failure would make every assertion above pass by
  // comparing two empty sets, so the shapes it must find are named here.
  assert.deepEqual(rustVariants(beginnerReport, "CoverageGapKind"), [
    "not_tested",
    "failed",
    "timed_out",
    "cancelled",
    "excluded",
    "truncated",
    "unavailable",
    "unattributed",
    "manual_review",
  ]);
  // Digits stay attached to the word they belong to.
  assert.ok(rustVariants(domain, "FindingFamily").includes("microsoft365"));
  // Per-variant serde names win over the enum's rename_all convention.
  assert.deepEqual(rustVariants(domain, "ScanRequestOutcomeCode"), [
    "no_effective_scope_grants",
    "no_ownership_confirmed_targets",
    "no_applicable_checks",
  ]);
  assert.deepEqual(unionMembers("BeginnerReportLifecycle"), ["final"]);
  assert.deepEqual(rustTaggedVariants(beginnerReport, "TechnicalExecution"), [
    "catalog_engine",
    "built_in_localhost_tcp",
    "invalid_built_in_task",
  ]);
});
