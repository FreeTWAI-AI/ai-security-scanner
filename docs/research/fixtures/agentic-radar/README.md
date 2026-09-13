# Agentic Radar research fixtures

Normative status: these are raw research fixtures for the pinned
[Agentic Radar integration decision](../../agentic-radar-evaluation.md). They are not product
findings, an admitted engine contract, a packaged artifact, or proof that a security check
completed.

## Provenance

The fixtures were generated on 2026-09-13 from upstream
`splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53` with the exact reviewed
[`agentic-radar-0.14.1-machine-json.patch`](../../patches/agentic-radar-0.14.1-machine-json.patch)
applied. The patch has SHA-256
`d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`. The patched checkout was at
local research commit
`1a3e4d81e3b122a69a529f1553a0b7239b64750d`.

Every invocation ran with an empty inherited environment except for fixed `PATH`, `PYTHONPATH`, and
`PYTHONHASHSEED` values. A bubblewrap network namespace exposed only loopback, the upstream checkout
and Python environment were read-only, and the report destination was a fresh temporary directory.
No hosted assessment ran and no external target was contacted.

| Fixture | Framework and controlled input | Nodes / edges / agents / tools | SHA-256 |
| --- | --- | --- | --- |
| [`langgraph.json`](langgraph.json) | LangGraph `examples/langgraph/MCP` | 3 / 0 / 0 / 1 | `62e9fb05cd4d6896359f2c1fc8179358ba74a31c98ec5506f3caaebd568fe046` |
| [`crewai.json`](crewai.json) | CrewAI `examples/crewai/mcp_1` | 4 / 3 / 0 / 0 | `f8c7db002564e9968ac39cad5bd8a48b945190428a14acfa4d1446c1a02a47a8` |
| [`n8n.json`](n8n.json) | n8n `examples/n8n/mcp` | 20 / 13 / 0 / 9 | `303b48d29c05c8b5020e77964c3c43080f201abac2d5cb7697f6c29800e2c275` |
| [`openai-agents.json`](openai-agents.json) | OpenAI Agents `examples/openai-agents/mcp/filesystem_example` | 4 / 3 / 1 / 0 | `f344d79b24d604a2ea24a216e273da766d6d309fe857fcf2d3a2812e57611127` |
| [`autogen.json`](autogen.json) | AutoGen `examples/autogen/agentchat/autogen_mcp_1` | 4 / 3 / 1 / 0 | `640bc21afd1f7d3f588d68c38c188be922ee2be626e73fc2530207c25fd1b34e` |
| [`no-supported-workflow.json`](no-supported-workflow.json) | LangGraph empty temporary directory | 0 / 0 / 0 / 0 | `5c243e84dbb28ec1142a1335cea56519a0f415c43c45de8fb710d6098d103618` |

## Output audit

All six files parse as JSON and carry schema version `1`, scanner version `0.14.1`, an explicit
framework, one of the two reviewed status values, a `complete` boolean, a structured `warnings`
array, and a graph object. `complete` is true exactly when `warnings` is empty. Every node, tool,
and agent vulnerability array is empty, confirming that the static path did not run the generic
mapper or hosted agent assessment.

The successful outputs also prove why the raw graph must be treated as sensitive and normalized
through an allowlist:

- OpenAI Agents and AutoGen include complete system prompts in `agents`.
- MCP node descriptions include commands, arguments, URLs, and headers. The AutoGen example contains
  the upstream placeholder `Authorization: Bearer your-api-key`; it is not a real credential, but it
  demonstrates that the same field can carry credential material in a real project.
- n8n repeats nine tool records in both `nodes` and `tools`, so a union without stable deduplication
  would double-count them.
- The LangGraph input yields three disconnected MCP-server nodes and no agents or edges while still
  receiving `workflow_found`, because the pinned upstream decision is based only on node count.
  That status means the analyzer returned structure; it is not a security result.
- The CrewAI run produced five analyzer diagnostics, including absent `crewai_tools`, an unsupported
  tool-list shape, and absent CrewAI agent metadata. The JSON retains them as
  `analyzer_diagnostic` warnings and sets `complete` to false while preserving the partial graph.
  Runtime memory addresses in Python object representations are removed from diagnostic messages;
  all other text is retained.
- CrewAI stores nodes and edges in sets. Two isolated runs of the same controlled input varied their
  array order, so array position is not a stable component or relationship identity.

An adapter may use these fixtures to verify parsing, deduplication, sensitive-field exclusion,
empty-state handling, and incomplete coverage. It must clear `AdapterOutput::complete` whenever the
upstream envelope says `complete: false`, retain the warnings as coverage diagnostics, and never
discard the partial graph. It must not copy `description`, `system_prompt`, vulnerability, or
mitigation content into typed inventory observations, and it must not interpret `workflow_found` as
a finding, clean result, or completed security check.
