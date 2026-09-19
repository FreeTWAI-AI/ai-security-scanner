# Development status

_Updated 2026-09-19._

This page summarizes current engineering status for contributors. It is not a product specification
or release declaration. [The product specification](product-spec.md) remains the source of truth for
product behavior, and the [current product review](product-audit.md) tracks the broader user journey.

## At a glance

- The engine catalog contains 24 records: 22 integrated, runnable engines and 2 experimental AI
  integrations that remain non-runnable.
- Repository, website/API, infrastructure, cloud, Microsoft 365, and Kubernetes paths use bounded
  upstream checks and feed one product-owned report.
- Report presentation distinguishes measured zero findings from an asset that was not measured, and
  keeps compact document identity in printed headers and footers.
- The offline adapter refresh pipeline produces reviewable proposals; deterministic generation is the
  default, AI edits require explicit opt-in and digest attribution, and the person running it chooses
  whether to open a pull request while the pipeline executes no commands.
- Native report, case, coverage, route, permission, and engine-task vocabularies are bound to their Rust
  wire contracts; unknown permissions and tasks cannot claim authorization, execution, or coverage.
- No model endpoint or hosted provider was contacted while developing the experimental AI paths.

## AI integration work

| Integration | Implemented | Current fail-closed boundary |
| --- | --- | --- |
| Garak | A thin adapter preserves probe identifiers and failure counts without inventing severity. | No managed image, exact model-endpoint scope grant, or product-owned credential path exists. |
| Agentic Radar | Its workflow graph is normalized as observations rather than unsupported vulnerability findings; incomplete machine output fails closed. | No managed image or typed framework-selection path exists; the machine-output contract is absent from an accepted upstream release. |
| MCP Armor | One exact MCP configuration file can be selected from an immutable repository snapshot and checked by a restricted, model-free configuration launcher. The local image produced a complete two-check report and an excessive-permission finding from a synthetic fixture with networking disabled. | The image is published, digest-pinned, and dispatchable, but not default-enabled. It runs with networking disabled over one approved MCP configuration snapshot; it does not start or contact an MCP server or load a model. |
| Augustus | Research-only, pure-data 14-rule preflight contracts and rejection fixtures define the required endpoint, cost, request, deadline, sandbox, and output boundaries. | No production catalog entry, adapter, launcher, provider connection, credential path, or dispatch path exists yet. |

The two experimental entries, Garak and Agentic Radar, remain `runnable: false`. Research artifacts
and local image identifiers are not substitutes for a published digest or an authorized runtime path.

## Current verification baseline

The latest recorded local baseline for these lanes completed successfully:

- Rust core and CLI: 1,700 tests.
- Frontend unit tests: 688 tests.
- Component rendering: 315 tests across 18 files.
- CI document and contract tests: 76 tests.
- Engine catalog validation: 8 tests.
- TypeScript type checking, Rust formatting, and Clippy: passed.

After removing credential-shaped text from an upstream test fixture, the MCP Armor image was rebuilt,
published, and pinned. Its offline synthetic smoke test produced one finding, two completed checks, no
warning, and `complete: true` under `network=none`.

## Current blockers

- Garak and Agentic Radar remain non-runnable while their catalog blockers exist.

These blockers describe fail-closed admission state; they do not authorize a publication or release
plan. Publication, packaging, signing, versioning, and compliance posture remain product-owner
decisions.
Real endpoint scans require explicit scope and must never infer authorization or accept credentials
through chat or command arguments.

## Supporting records

- [Engine catalog](engine-catalog.md)
- [MCP Armor research decision](research/mcp-armor-evaluation.md)
- [Agentic Radar research decision](research/agentic-radar-evaluation.md)
- [Augustus research decision](research/augustus-evaluation.md)
- [Product doctrine](PRODUCT-DOCTRINE.md)
