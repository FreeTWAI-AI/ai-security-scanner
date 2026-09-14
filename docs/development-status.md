# Development status

_Updated 2026-09-14._

This page summarizes current engineering status for contributors. It is not a product specification
or release declaration. [The product specification](product-spec.md) remains the source of truth for
product behavior, and the [current product review](product-audit.md) tracks the broader user journey.

## At a glance

- The engine catalog contains 24 records: 21 integrated, runnable engines and 3 experimental AI
  integrations that remain non-runnable.
- Repository, website/API, infrastructure, cloud, Microsoft 365, and Kubernetes paths use bounded
  upstream checks and feed one product-owned report.
- Report presentation distinguishes measured zero findings from an asset that was not measured, and
  keeps compact document identity in printed headers and footers.
- No model endpoint or hosted provider was contacted while developing the experimental AI paths.

## AI integration work

| Integration | Implemented | Remaining before it can run |
| --- | --- | --- |
| Garak | A thin adapter preserves probe identifiers and failure counts without inventing severity. | A managed image, an exact model-endpoint scope grant, and a product-owned credential path where a selected endpoint requires one. |
| Agentic Radar | Its workflow graph is normalized as observations rather than unsupported vulnerability findings; incomplete machine output fails closed. | A managed image, typed framework selection, and an accepted upstream machine-output contract. |
| MCP Armor | One exact MCP configuration file can be selected from an immutable repository snapshot and checked by a restricted, model-free configuration launcher. The local image produced a complete two-check report and an excessive-permission finding from a synthetic fixture with networking disabled. | Run and verify the approved immutable-image publication workflow, then record its published digest before enabling dispatch. |
| Augustus | Research-only, pure-data 14-rule preflight contracts and rejection fixtures define the required endpoint, cost, request, deadline, sandbox, and output boundaries. | No production catalog entry, adapter, launcher, provider connection, credential path, or dispatch path exists yet. |

Experimental entries remain `runnable: false`. Research artifacts and local image identifiers are not
substitutes for a published digest or an authorized runtime path.

## Current verification baseline

The latest recorded local baseline for these lanes completed successfully:

- Rust core and CLI: 1,690 tests.
- Frontend unit tests: 601 tests.
- Component rendering: 262 tests across 18 files.
- CI document and contract tests: 45 tests.
- Engine catalog validation: 8 tests.
- TypeScript type checking, Rust formatting, and Clippy: passed.

After removing credential-shaped text from an upstream test fixture, the MCP Armor image was rebuilt
and its offline synthetic smoke test again produced one finding, two completed checks, no warning, and
`complete: true` under `network=none`.

## Open work

1. Complete MCP Armor publication evidence and digest writeback before changing its runnable status.
2. Keep the other experimental AI integrations fail closed until their catalog blockers are resolved.

Publication, packaging, signing, versioning, and compliance posture remain product-owner decisions.
Real endpoint scans require explicit scope and must never infer authorization or accept credentials
through chat or command arguments.

## Supporting records

- [Engine catalog](engine-catalog.md)
- [MCP Armor research decision](research/mcp-armor-evaluation.md)
- [Agentic Radar research decision](research/agentic-radar-evaluation.md)
- [Augustus research decision](research/augustus-evaluation.md)
- [Product doctrine](PRODUCT-DOCTRINE.md)
