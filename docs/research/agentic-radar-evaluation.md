# Agentic Radar integration decision

Normative status: this is a pinned research decision, subordinate to the
[canonical product specification](../product-spec.md). It records the admissible output and safety
boundary for one audited Agentic Radar revision. It does not admit an engine, authorize packaging
or publication, or make this inventory-only analysis a completed security check.

Decision: when Agentic Radar is integrated, consume its static workflow graph as typed inventory
observations. Do not turn its tool-category warnings or agent-mitigation assessments into findings.
The pinned revision already has a JSON graph exporter, so a product-maintained output-emitter patch
is not needed.

This static review is pinned to
[`splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53`](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53)
(version 0.14.1). Its checked-in license is Apache-2.0
([package metadata](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/pyproject.toml#L1-L18),
[license text](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/LICENSE#L1-L3)).
It remains `RESEARCH / NOT_DISTRIBUTED`: it is not an `ai-security-scanner` engine, installer
component, container image, or transitive release dependency.

## Audited machine-readable path

The earlier assumption that this revision can emit only HTML is incorrect. Agentic Radar added
graph JSON in version 0.12.0
([changelog](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/CHANGELOG.md#L37-L43)).
At the pinned revision:

- `scan` accepts LangGraph, CrewAI, n8n, OpenAI Agents, and AutoGen as explicit framework values
  ([CLI enum](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L42-L47),
  [analyzer selection](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L107-L133)).
- `--export-graph-json` is an upstream CLI option. After analysis, the CLI sanitizes the graph,
  writes `graph.model_dump_json(indent=2)`, and exits before applying the generic vulnerability
  mapper
  ([option](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L79-L105),
  [control flow](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L136-L163)).
- The exported in-memory model contains `name`, `nodes`, `edges`, `agents`, and `tools`. Nodes carry
  a node type, name, optional description and label, optional tool category, and a vulnerability
  list; edges carry start, end, and an optional condition; agent metadata carries name, model,
  system prompt, guardrail status, and optional mitigation assessments
  ([model](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/graph.py#L7-L74)).
  There is no schema version, scanner version, or framework field in this JSON. The future launcher
  must preserve the selected framework as trusted invocation metadata rather than infer it from
  target-controlled output.
- The framework analyzers all converge on that model: LangGraph collects graph nodes, inferred
  agents, tools, and MCP servers
  ([LangGraph](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/langgraph/analyze.py#L27-L133));
  CrewAI collects agents, tasks, tools, MCP servers, and inferred connections
  ([CrewAI](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/crewai/analyze.py#L22-L72));
  n8n reads workflow JSON and converts nodes and connections
  ([n8n](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/n8n/analyze.py#L16-L52));
  OpenAI Agents collects agents, tools, guardrails, and MCP servers
  ([OpenAI Agents](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/analyze.py#L23-L41));
  and AutoGen collects models, function tools, MCP adapters, agents, and teams
  ([AutoGen](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/autogen/agentchat/analyze.py#L27-L56)).
- The HTML path constructs a separate `ReportData` object containing project and framework names,
  timestamp, a rendered graph string, aggregate counts, agents, tools, MCP servers, hardened prompts,
  scanner version, and a local JavaScript dependency path. It passes that object plus the generic
  vulnerability definitions into Jinja
  ([report assembly](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/report/report.py#L19-L104)).
  That presentation object is not the adapter input: parsing it would couple the product to HTML and
  would reintroduce the generic warnings deliberately excluded by the upstream graph JSON path.

No Agentic Radar code was executed for this decision, and no scan target was contacted.

## Normalization decision

The future adapter may derive only inventory observations from the exported graph:

- one component observation for each distinct agent, tool, custom tool, basic workflow node, or MCP
  server in the union of `nodes` and `tools`;
- one relationship observation for each edge, retaining its start, end, and condition; and
- optional component attributes that the graph states directly, such as tool category, model name,
  and guardrail status.

The duplicate `tools` collection must enrich or confirm a component, not create a second copy. The
adapter must not put system prompts, free-form descriptions, MCP parameters, vulnerability text, or
mitigation explanations into the typed observation. The exact JSON remains a sensitive raw artifact
with a bounded pointer for each derived observation; normal export redaction continues to govern
whether that artifact is shared.

This uses the existing [adapter contract](../../src-tauri/src/adapter.rs#L111-L133), which keeps
scanner-authored inventory separate because inventory alone is not evidence of a vulnerability.
Agentic Radar observations therefore cannot create a finding, a priority item, a “no problems”
asset state, or first meaningful value by themselves. They may supplement the independent source
security checks already selected for an AI application.

## Why the reported vulnerabilities are not findings

The checked-in vulnerability map has 11 entries: four match a tool category and seven match a tool
name. Every entry is a tool rule. Its vulnerability objects contain only `name`, `description`,
`security_framework_mapping`, and `remediation`; they have no stable rule identifier, severity, or
per-occurrence source evidence
([mapping data](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/mapper/vulnerabilities.json#L1)).
The mapper attaches those warnings whenever a node or tool has the matching name or category
([matching logic](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/mapper/mapper.py#L25-L54)).
That is useful design guidance, but the presence of an LLM, web-search tool, code interpreter,
document loader, or named retriever is not evidence that an exploitable weakness exists.

The JSON path already exits before that mapper runs, so these tool warnings should not appear in a
captured graph. The adapter must still ignore a future graph that places them in a `vulnerabilities`
array rather than silently promoting them to findings.

OpenAI Agents has a separate concern: its analyzer calls an LLM-based mitigation assessment before
returning the graph
([call site](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/analyze.py#L23-L41)).
That path constructs an OpenAI client and can send guardrail code and system prompts to a hosted
model when credentials are available
([hosted analysis](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/analysis/openai_agents/parsing/vulnerabilities.py#L142-L210)).
Its generated mitigation levels and explanations are also excluded from findings and typed
observations.

## Required execution boundary before integration

Only the static `scan ... --export-graph-json` path is in scope. The future launcher must:

- never invoke `test` or `--harden-prompts`; both are active or hosted-AI paths, not source inventory
  ([commands](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L197-L254),
  [hardening path](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L164-L175));
- run without credential variables, outside the selected snapshot as its working directory, and
  without network access. This matters because the CLI loads `.env` at import time
  ([initialization](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L37-L39));
- accept only the explicitly selected framework and bounded read-only snapshot; and
- treat malformed, missing, or structurally inconsistent JSON as incomplete coverage, never as a
  clean result.

The pinned CLI exits with code 1 when it sees no more than two graph nodes instead of emitting an
explicit machine-readable empty result
([no-workflow branch](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/agentic_radar/cli.py#L144-L159)).
That cannot be translated into a successful clean scan. A future integration must retain the
product's non-zero-exit boundary and show this case as incomplete until the upstream output contract
can distinguish “no supported workflow found” from execution failure.

## Intended upstream issue and pull request

The issue should ask upstream to document and version the existing JSON contract rather than add a
second emitter. It should record three machine-consumer gaps: the output omits framework and scanner
version, the no-workflow case has no JSON state, and OpenAI Agents may perform hosted analysis before
static JSON export. The existing CLI tests exercise HTML output for the five frameworks but do not
cover `--export-graph-json`
([tests](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/tests/cli_test.py#L30-L100)).

A narrow pull request should stay in output and orchestration code: add a versioned JSON envelope
with framework and scanner version, emit an explicit empty-workflow state with a successful process
exit, ensure JSON export does not initialize hosted-model analysis, and add fixture-backed CLI tests
for all five framework values. It must serialize the same parser-produced graph and must not change
parsers, vulnerability matching, severity, evidence, or remediation logic. Until that contract is
available and pinned, this repository may evaluate a minimal equivalent patch in the ignored
research checkout, but it must not add the catalog entry, adapter, or packaged artifact.
