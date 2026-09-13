# Agentic Radar upstream issue and pull request drafts

Normative status: this file is local submission preparation only. Neither draft has been submitted
to GitHub, and this file does not authorize a submission, a push, packaging, publication, credential
use, or a scan. The drafts were prepared against
[`splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53`](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53)
(version 0.14.1) and the local
[integration decision](agentic-radar-evaluation.md).

## Submission preflight

Do not submit either draft until the product owner explicitly authorizes the GitHub write. At that
time, the submitter must also:

1. search the live issue tracker for an equivalent request and leave the issue-template duplicate
   checkbox unchecked until that search is complete;
2. refresh upstream `main` and confirm that the behavior and contribution instructions have not
   changed since the pinned revision;
3. submit the issue first, then wait until maintainers mark it `help needed` and confirm that no one
   has claimed it, as required by upstream `CONTRIBUTING.md`;
4. replace `#ISSUE` in the PR draft with the accepted issue number; and
5. rebase and rerun the upstream-required checks before opening a PR.

The reviewed local implementation is retained as
[`agentic-radar-0.14.1-machine-json.patch`](patches/agentic-radar-0.14.1-machine-json.patch), with
SHA-256 `d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`. It is evidence for the
draft, not a branch that is authorized for publication.

## Issue draft

Use upstream's **Feature Request** template.

### Title

`[Feature] Version graph JSON and report incomplete analysis to machine consumers`

### Is there an existing issue for the same feature request?

Leave this unchecked until the live issue search in the submission preflight is complete.

### Describe the feature request

Agentic Radar 0.14.1 has a useful `--export-graph-json` path, but the emitted document contains only
the graph. A machine consumer cannot determine which framework or Agentic Radar version produced
it, distinguish an explicit “no supported workflow” result from execution failure, or know when an
analyzer returned only a partial graph.

This matters for integrations that need to fail closed. Today they must infer completeness from
process status and human-readable analyzer output. The OpenAI Agents path can also perform hosted
vulnerability assessment before the static graph is exported, even though a graph-only consumer
does not need that assessment.

Could the existing JSON export become a documented, versioned envelope with:

- `schema_version` and `scanner_version`;
- the selected `framework`;
- a structural `status`, initially `workflow_found` or `no_supported_workflow`;
- a `complete` boolean and structured `warnings`; and
- the same sanitized, parser-produced graph already emitted today?

For JSON export only, an analyzed graph containing no supported workflow should produce the
explicit empty state and exit successfully. Analyzer diagnostics should remain visible as
structured warnings and force `complete: false`, while preserving the partial graph. Execution
errors should continue to fail normally. Static OpenAI Agents graph export should avoid hosted
vulnerability assessment; existing HTML report and explicit runtime-test behavior should remain
unchanged.

The contract would let consumers distinguish complete inventory, partial inventory, an explicit
empty result, and execution failure without interpreting prose or weakening error handling.

Reference behavior in 0.14.1:

- the
  [`--export-graph-json` option](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L79-L105)
  and its
  [graph-only serialization](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L136-L163);
- the
  [no-workflow exit](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L144-L159); and
- current CLI tests, which cover
  [HTML output for all five framework selectors](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/tests/cli_test.py#L30-L100)
  but not the graph JSON contract.

### Do you have any ideas for the technical implementation?

Keep the change in output and CLI orchestration code rather than creating another graph builder:

1. Add typed models for a schema-versioned graph-export envelope and warning records.
2. Serialize the existing sanitized `GraphDefinition` inside that envelope.
3. Capture non-empty analyzer diagnostics for JSON export as warnings and derive `complete` from
   whether warnings are present.
4. Emit `no_supported_workflow` only after analysis has completed and only on the JSON path; do not
   turn exceptions or invalid input into a successful empty result.
5. Make hosted vulnerability assessment optional in `OpenAIAgentsAnalyzer`, preserving its current
   default and disabling it only for static JSON export.
6. Add focused tests for all five framework values, the explicit empty state, partial completeness,
   unchanged HTML behavior, and the no-hosted-assessment JSON branch.

The implementation should not change framework parsers, graph detection, vulnerability matching,
severity, evidence, remediation, or the default HTML flow.

## Pull request draft

This draft is conditional on the submission preflight and an accepted upstream issue.

### Title

`feat: make graph JSON safe for machine consumers`

### Body

Closes #ISSUE.

#### Summary

- wrap the existing sanitized graph JSON in schema version `1`, including scanner version,
  framework, structural status, completeness, and structured warnings;
- emit an explicit `no_supported_workflow` document for a completed JSON analysis with no supported
  workflow, without changing the existing HTML exit behavior;
- preserve partial graphs while analyzer diagnostics set `complete` to false; and
- skip hosted OpenAI Agents vulnerability assessment only for static graph JSON export, while
  preserving its existing default everywhere else.

#### Output contract

```json
{
  "schema_version": "1",
  "scanner_version": "0.14.1",
  "framework": "crewai",
  "status": "workflow_found",
  "complete": false,
  "warnings": [
    {
      "code": "analyzer_diagnostic",
      "message": "Analyzer diagnostic text"
    }
  ],
  "graph": {
    "name": "workflow",
    "nodes": [],
    "edges": [],
    "agents": [],
    "tools": []
  }
}
```

`status` describes graph structure, not security posture. `complete: false` means the graph may be
partial; it does not discard the graph. Exceptions and invalid input still fail instead of becoming
an empty result.

#### Scope and compatibility

The patch serializes the same parser-produced `GraphDefinition`; it does not add or replace any
detection logic. Framework parsers, vulnerability mapping, severity, evidence, remediation, prompt
hardening, and runtime testing are unchanged. The existing HTML flow still maps vulnerabilities
and keeps its current no-workflow exit behavior.

The OpenAI Agents constructor retains hosted assessment as its default. The CLI opts out only when
`--export-graph-json` requests static inventory, so graph export does not unexpectedly require a
hosted provider.

#### Tests

The focused test file covers:

- the exact envelope and each of the five framework selectors;
- reuse of the analyzer-produced graph without generic vulnerability mapping;
- explicit `no_supported_workflow` output;
- analyzer diagnostics, structured warnings, and fail-closed completeness;
- unchanged HTML no-workflow failure behavior; and
- the OpenAI Agents graph-export path without hosted assessment.

Local validation against
`65a7e4bd01e2034c7cb52e9620eeed287688cc53` produced:

- 9 focused tests passed;
- Ruff lint and focused formatting checks passed; and
- mypy reported no issues in 90 source files.

Before submission, rerun the repository's full `pre-commit run --all-files` and CI-equivalent test
matrix after rebasing onto current upstream `main`.

## Deliberately omitted from both drafts

The drafts do not mention this product's catalog, adapter, packaging plan, report layer, or release
schedule because none is necessary to justify the upstream contract. They do not request new
detectors, reinterpret Agentic Radar's vulnerability claims, or propose credentials or hosted
provider access.
