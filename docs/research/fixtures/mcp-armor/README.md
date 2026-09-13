# MCP Armor configuration-only research fixtures

Normative status: these are raw research outputs from the pinned
[MCP Armor integration decision](../../mcp-armor-evaluation.md). They are not product findings, a
packaged artifact, authorization to contact an MCP server, or proof that model-backed checks ran.

## Provenance

The fixtures were generated from
`aira-security/mcp-armor@6af4cee4665ab6242f02a88952f9127b6a04922a` plus the exact
[`mcp-armor-1.0.2-config-only.patch`](../../patches/mcp-armor-1.0.2-config-only.patch), whose
SHA-256 is `ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122`.
The patched ignored checkout was at local research commit
`d5fbb944d35c98495a64f97a4270112c48fcdcda`.

Each CLI invocation inherited only fixed `PATH`, `PYTHONPATH`, `PYTHONHASHSEED`, and `PYTHONUTF8`
values. The system Python had PyYAML and Rich but did not have FastMCP, Transformers, or PyTorch.
The successful executions therefore prove that the configuration-only path did not import its live
MCP connector or model stack. No configured command was executed, no endpoint or OAuth flow was
contacted, and no model or credential was loaded.

The upstream test inputs are embedded in the retained patch. Their command and permission values
are inert text. The findings fixture includes one visibly synthetic OpenAI-shaped token solely to
exercise MCP Armor's existing secret pattern; it is not a credential and does not appear
unredacted in output.

| Fixture | Result | SHA-256 |
| --- | --- | --- |
| [`config-findings.json`](config-findings.json) | Two upstream findings; both checks completed | `8a94b0b7aa717b106896bf3e86c5da063ab5f8023fcff2b97cac85990a72cffa` |
| [`config-clean.json`](config-clean.json) | Zero findings; both checks completed | `7df09184de483652621090124e0b5aa593ad08552a3fe4527865b0712f78742f` |
| [`config-partial.json`](config-partial.json) | Zero findings retained with one structured warning and `complete: false` | `804519c14a8e265ef82010c5836a7354aa23732273bf9a3a2e3e487957258669` |
| [`config-disabled.json`](config-disabled.json) | One upstream low-severity excessive-permission result for a disabled server; both checks completed | `1932bd98c099da927f00f4e6c94f2dbbe9a8eb3d87c5039d0b60a0561f0c5550` |

## Contract audit

All four files contain schema version `1`, scanner version `1.0.2`, mode
`configuration_only`, exact input counts, `complete`, structured warnings, and an ordered ledger
for `hardcoded_secrets` and `excessive_tool_permissions`. A complete result requires at least one
readable input, no warnings, and `completed` status for both checks. A failed check or partially
invalid input keeps completed findings but clears completeness.

The product adapter may normalize only these two check IDs. It must preserve upstream finding type,
severity, configuration location, affected server, and allowlisted evidence. It must not expose the
redacted token excerpt in beginner-facing text, reinterpret the configuration scan as live MCP
coverage, or report a clean result unless both ledger entries and the top-level completeness field
agree.

The excessive-permission detector deliberately reports a disabled but still risky server as `low`
and an enabled risky server as `critical`. Both values are upstream behavior. The adapter preserves
that distinction and requires the low result's structured `disabled: true` evidence rather than
deriving status from a title or server name.
