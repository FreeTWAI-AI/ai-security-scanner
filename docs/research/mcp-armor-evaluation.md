# MCP Armor integration decision

Normative status: this is a pinned research decision, subordinate to the
[canonical product specification](../product-spec.md). It evaluates one MCP Armor source revision
and one referenced model snapshot. It does not admit an engine, define a production adapter,
authorize MCP server contact, approve model terms, or start packaging or publication work.

Decision: do not add MCP Armor to the engine catalog at this revision. Re-evaluate a static,
configuration-only slice after upstream exposes it as an explicit machine-readable mode that never
starts or contacts an MCP server and does not require the prompt-injection model. Do not integrate
the model-backed checks until their artifact, license, dependency, provenance, and incomplete-check
boundaries are separately resolved.

## Audited revisions

The source review is pinned to tag `v1.0.2` at
[`aira-security/mcp-armor@6af4cee4665ab6242f02a88952f9127b6a04922a`](https://github.com/aira-security/mcp-armor/tree/6af4cee4665ab6242f02a88952f9127b6a04922a),
committed on 2026-03-27. The Python package and source repository declare Apache-2.0
([package metadata](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/pyproject.toml#L5-L14),
[license text](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/LICENSE#L1-L3)).
It is recorded here as `RESEARCH / NOT_DISTRIBUTED`.

MCP Armor names `Aira-security/FT-Llama-Prompt-Guard-2` without a revision. For this review only,
the public model metadata observed on 2026-09-13 is pinned to
[`01a2a0b80460f68757fc71c682d412dcddde2faa`](https://huggingface.co/Aira-security/FT-Llama-Prompt-Guard-2/tree/01a2a0b80460f68757fc71c682d412dcddde2faa).
That observation does not change what MCP Armor will resolve at runtime, and no model weight was
downloaded or executed.

## The current scan is not a selectable static mode

The README calls the open-source product “static MCP configuration scanning,” but its documented
inventory connects to MCP servers, and the CLI has no configuration-only option
([feature description](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/README.md#L19-L26),
[scan options](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/cli.py#L1438-L1458)).
The implementation does contain two genuine configuration-file checks:

- `Hardcoded Secret`, which scans the selected configuration text with upstream regexes and emits
  a redacted high-severity result
  ([implementation](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/hardcoded_secrets.py#L378-L458)); and
- `Excessive Tool Permissions`, which evaluates configured commands, arguments, and declared
  permissions using upstream-owned rules
  ([rules](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/excessive_tool_permissions.py#L20-L119),
  [scan path](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/excessive_tool_permissions.py#L122-L168)).

Those checks run concurrently with server discovery. The same `scan` invocation constructs a
configuration-only task and a discovery task, then waits for both
([orchestration](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/cli.py#L778-L785)).
Discovery attempts every enabled server
([fan-out](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scanner.py#L239-L279)).
For stdio configuration it passes the configured command, arguments, and environment to FastMCP;
for HTTP or SSE it uses the configured endpoint and may enter OAuth
([transport construction](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/connector.py#L77-L126),
[connection](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/connector.py#L28-L66)).

If every connection fails, MCP Armor retains the two configuration checks and says that only those
checks ran
([fallback result](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/cli.py#L818-L851)).
That is useful failure recovery, not a safe mode a caller can select before execution. A product
wrapper must not deliberately cause connection failure, rewrite every server as disabled, call
private internals, or rely on isolation failure to obtain this slice. Doing so would replace a
documented upstream execution contract with product-owned behavior.

The candidate future integration is therefore narrow: accept only an exact approved MCP
configuration snapshot and run the two upstream configuration checks through an explicit upstream
CLI mode. It would be a meaningful static security check, not MCP server inventory, live tool
analysis, prompt-injection coverage, or rug-pull coverage. Automatic searches of home-directory
locations are also outside that boundary; the CLI must receive the one selected snapshot rather
than use its built-in discovery list
([configuration discovery](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scanner.py#L31-L89)).

## Model acquisition is mandatory for the current full scan

The full runner unconditionally includes prompt-injection checks for discovered tools, resources,
prompts, and resource templates
([check registration](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/run_checks.py#L55-L105)).
Those checks call Transformers with the mutable repository name
`Aira-security/FT-Llama-Prompt-Guard-2`; no model revision, local-files-only setting, or artifact
digest is supplied
([model loader](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/prompt_injection.py#L24-L70)).
The CLI tells users that the first scan automatically downloads about 290 MB from Hugging Face
([CLI help](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/cli.py#L1430-L1447)),
and the README confirms that runtime download path
([FAQ](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/README.md#L144-L153)).

The model is not optional at the package boundary either. `transformers~=4.57.1` and
`torch~=2.9.0` are unconditional dependencies, and the repository contains no dependency lock file
([dependency declarations](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/pyproject.toml#L25-L32)).
An eventual static-only mode must move model support behind an optional dependency and a lazy
import, as well as guarantee that the static invocation neither resolves nor initializes a model.
Merely skipping prompt checks after importing the full runner would not give the product a bounded
model-free artifact.

## Scanner and model licenses are separate

The source repository's Apache-2.0 license does not by itself establish terms for separately
downloaded weights. At the observed model revision:

- the fine-tuned model card declares `license: llama2` and identifies
  `meta-llama/Llama-Prompt-Guard-2-22M` as its base
  ([model card](https://huggingface.co/Aira-security/FT-Llama-Prompt-Guard-2/blob/01a2a0b80460f68757fc71c682d412dcddde2faa/README.md));
- the fine-tuned repository has no separate `LICENSE` file
  ([pinned file tree](https://huggingface.co/Aira-security/FT-Llama-Prompt-Guard-2/tree/01a2a0b80460f68757fc71c682d412dcddde2faa)); and
- the identified base model is access-gated and declares `license_name: llama4`, with the Llama 4
  Community License and acceptable-use terms rather than Apache-2.0
  ([base-model record](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M/tree/11614a155199674a0a95e6602d6ab0417b790ed0)).

The fine-tune's `llama2` label and its named Llama 4 base do not provide a coherent, self-contained
redistribution record. This document makes no legal determination about permitted use. It records
that the evidence is insufficient for this project's `license_spdx`, notice, and publication
decisions. Any future distribution of the model requires a separate product-owner review of the
exact weight revision and all applicable upstream terms. Avoiding the model entirely removes this
blocker from the proposed configuration-only slice.

## Reproducibility and completeness are not yet bounded

At the observed fine-tuned model revision, `model.safetensors` is 283,347,432 bytes with SHA-256
`4e18e9500a456d7acbd80031036b5e9a4b0429df0474bf5eb6fa2150f02ba8ee`
([weight record](https://huggingface.co/Aira-security/FT-Llama-Prompt-Guard-2/blob/01a2a0b80460f68757fc71c682d412dcddde2faa/model.safetensors)).
MCP Armor does not pin that revision or digest. Its compatible-release dependency ranges can also
select different Transformers, PyTorch, FastMCP, and supporting versions on later installations.
The JSON report contains findings and human-readable `status` and `errors`, but no schema version,
scanner source revision, model revision, dependency identity, or per-check evaluated/skipped/failed
ledger
([JSON construction](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/cli.py#L865-L943)).

More importantly, failure can look clean:

- a model-load or inference failure becomes a benign classification
  ([classification fallback](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/prompt_injection.py#L142-L161));
- a missing classifier skips the prompt-injection check and returns an empty issue list
  ([tool-check path](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/scan_checks/prompt_injection.py#L230-L255)); and
- the common runner logs a check exception and continues without adding an incomplete-check record
  ([runner behavior](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/src/mcp_armor/run_checks.py#L164-L185)).

An adapter cannot reconstruct which checks really ran from zero findings. Until upstream emits
structured completeness, model/check failures must not be normalized as completed clean coverage.
Pinning only the weight would not fix this evidence boundary.

## Conditions for a new evaluation

A future revision or narrow upstream patch can be reconsidered when all conditions for its selected
slice are demonstrable:

1. A documented `--config-only` or equivalent mode accepts exact configuration paths and never
   creates a connector, starts a configured command, contacts an endpoint, enters OAuth, uses
   configuration credentials for authentication, or auto-discovers other files.
2. That mode calls the existing upstream configuration checks without copying their patterns,
   severities, or detection logic into a product wrapper.
3. Model dependencies are optional and are not imported, resolved, downloaded, or initialized by
   the static mode.
4. Machine output has a versioned schema, stable finding identity, scanner provenance, and a
   structured ledger for every selected check; errors and skipped checks make coverage incomplete.
5. Representative upstream-produced fixtures cover findings, zero findings, malformed input, a
   failed check, and proof that no server or model path was reached.
6. If model-backed checks are considered later, the exact model revision, every fetched file
   digest, dependency lock, offline loading behavior, inference parameters, output provenance, and
   applicable redistribution record are reviewed together. Model failure must fail closed.

The smallest follow-up consistent with this decision is to prepare and locally evaluate an
upstream-oriented patch for items 1–5 only. That patch would expose existing configuration checks;
it would not rebuild detection, add model behavior, connect to MCP servers, or admit an engine.

## Research actions performed

The source repository was shallow-cloned read-only into the ignored `.upstreams/` research area.
Public Hugging Face repository metadata, model cards, file names, and the weight pointer were read
to establish the model revision, size, digest, and stated terms. MCP Armor was not installed or
executed. No model weight, dependency, container image, or credential was downloaded; no MCP
server, scan target, OAuth flow, or hosted inference service was contacted.
