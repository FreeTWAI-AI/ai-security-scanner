# Agentic Radar research fixtures

Normative status: these are raw research fixtures for the pinned
[Agentic Radar integration decision](../../agentic-radar-evaluation.md). They are not product
findings, an admitted engine contract, a packaged artifact, or proof that a security check
completed.

## Provenance

The fixtures were generated on 2026-09-13 from upstream
`splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53` with the exact reviewed
[`agentic-radar-0.14.1-machine-json.patch`](../../patches/agentic-radar-0.14.1-machine-json.patch)
applied. The patched checkout was at local research commit
`a622b9d62ea9fbab3c25f1ee7dd7ea59de8c1714`.

Every invocation ran with an empty inherited environment except for fixed `PATH` and `PYTHONPATH`
values. A bubblewrap network namespace exposed only loopback, the upstream checkout and Python
environment were read-only, and the report destination was a fresh temporary directory. No hosted
assessment ran and no external target was contacted.

| Fixture | Framework and controlled input | Nodes / edges / agents / tools | SHA-256 |
| --- | --- | --- | --- |
| [`langgraph.json`](langgraph.json) | LangGraph `examples/langgraph/MCP` | 3 / 0 / 0 / 1 | `7c56fbc7662b068fcf9d194bf5234c902af1c74c8a25d9a00dcccab6a478a6d3` |
| [`crewai.json`](crewai.json) | CrewAI `examples/crewai/mcp_1` | 4 / 3 / 0 / 0 | `e85bc1db3b40306a6a628fa66b4707e553933fead7cf8ef5981fae41f020e1c4` |
| [`n8n.json`](n8n.json) | n8n `examples/n8n/mcp` | 20 / 13 / 0 / 9 | `f266b59815482a675f951ecd6425785612862a1ae8810831f774f97023217584` |
| [`openai-agents.json`](openai-agents.json) | OpenAI Agents `examples/openai-agents/mcp/filesystem_example` | 4 / 3 / 1 / 0 | `050501da928effaf5b0e55013a1d87adc0b5a3ec63e86b7d3bf0558a9e1e646b` |
| [`autogen.json`](autogen.json) | AutoGen `examples/autogen/agentchat/autogen_mcp_1` | 4 / 3 / 1 / 0 | `c3f66da0493ffaa2dcf85680fad1f4c104cf766429c7048bb24c239861d45411` |
| [`no-supported-workflow.json`](no-supported-workflow.json) | LangGraph empty temporary directory | 0 / 0 / 0 / 0 | `3b11f0e3eea835961bdd83ea810e9e74df703ad1e1aabcc08254a8d55b3572fa` |

## Output audit

All six files parse as JSON and carry schema version `1`, scanner version `0.14.1`, an explicit
framework, one of the two reviewed status values, and a graph object. Every node, tool, and agent
vulnerability array is empty, confirming that the static path did not run the generic mapper or
hosted agent assessment.

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
- The CrewAI run reported on standard output that `crewai_tools` and CrewAI were not installed, then
  emitted `workflow_found` while omitting agent metadata. That output is retained as a coverage
  shortfall fixture, not as the canonical complete CrewAI result. The current envelope has no
  structured warning or completeness field for this condition.

An adapter may use these fixtures to verify parsing, deduplication, sensitive-field exclusion, and
empty-state handling. It must not copy `description`, `system_prompt`, vulnerability, or mitigation
content into typed inventory observations, and it must not interpret `workflow_found` as a finding,
clean result, or completed security check.
