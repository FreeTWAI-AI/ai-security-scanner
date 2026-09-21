# MCP Armor integration decision

Normative status: this is a pinned research and integration decision, subordinate to the
[canonical product specification](../product-spec.md). It evaluates one MCP Armor source revision,
one retained configuration-only patch, and one referenced model snapshot. The live catalog now
records the configuration-only image as `integrated` and `runnable: true`. This document keeps the
original admission conditions and the current dispatch state. It does not authorize MCP server
contact, model terms, or live MCP checks.

Decision: integrate the patched static configuration-only slice as a fail-closed engine contract.
It reads one exact MCP configuration snapshot and runs only upstream's existing
`hardcoded_secrets` and `excessive_tool_permissions` checks. The adapter normalizes those results as
findings, accepts a zero-finding result only when both checks completed, and preserves completed
findings while any warning, failed check, malformed ledger, or unevaluated input marks coverage
partial. A typed product path binds exactly one approved configuration file. Do not integrate
model-backed or live MCP checks until their separate artifact, license, dependency, provenance,
authorization, and incomplete-check boundaries are resolved.

## Audited revisions

The source review is pinned to tag `v1.0.2` at
[`aira-security/mcp-armor@6af4cee4665ab6242f02a88952f9127b6a04922a`](https://github.com/aira-security/mcp-armor/tree/6af4cee4665ab6242f02a88952f9127b6a04922a),
committed on 2026-03-27. The Python package and source repository declare Apache-2.0
([package metadata](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/pyproject.toml#L5-L14),
[license text](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/LICENSE#L1-L3)).
The source review recorded this revision as `RESEARCH / NOT_DISTRIBUTED`. The published configuration-only image is `ALLOW` in [`THIRD_PARTY.md`](../../THIRD_PARTY.md); model files remain excluded.

MCP Armor names `Aira-security/FT-Llama-Prompt-Guard-2` without a revision. For this review only,
the public model metadata observed on 2026-09-13 is pinned to
[`01a2a0b80460f68757fc71c682d412dcddde2faa`](https://huggingface.co/Aira-security/FT-Llama-Prompt-Guard-2/tree/01a2a0b80460f68757fc71c682d412dcddde2faa).
That observation does not change what MCP Armor will resolve at runtime, and no model weight was
downloaded or executed.

## The unmodified scan is not a selectable static mode

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

## The unmodified full scan does not bound reproducibility or completeness

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

## Evaluated configuration-only patch

The locally evaluated upstream-oriented commit is
`d5fbb944d35c98495a64f97a4270112c48fcdcda`, directly based on the audited upstream revision. Its
mailbox patch is retained at
[`patches/mcp-armor-1.0.2-config-only.patch`](patches/mcp-armor-1.0.2-config-only.patch), SHA-256
`ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122`. It has not been submitted to
GitHub.

The patch makes these bounded changes without changing either detector's patterns, severity, or
decision logic:

1. `mcp-armor scan --config-only --config <exact-json-path>` is mutually exclusive with baseline
   mode and never runs automatic configuration discovery.
2. The static runner imports neither FastMCP nor the prompt-injection classifier, creates no
   connector, starts no configured command, and performs no OAuth or network operation.
3. `transformers` and `torch` move behind a `prompt-injection` optional dependency. A full scan
   fails before server contact if that extra is absent; the static slice does not need it.
4. Both existing configuration detectors accept `fail_on_error=True`, allowing the orchestration
   layer to record a check failure rather than turn it into a clean empty list. Detection behavior
   is otherwise unchanged.
5. The JSON envelope carries schema and scanner versions, mode, input/evaluated counts, a
   `complete` boolean, structured warnings, an exact two-check ledger, and findings tagged with
   their stable check identifier. Any warning or failed/not-run check clears `complete` while
   findings from completed checks remain available.

The patch's 11 configuration-only tests pass under the system Python without FastMCP,
Transformers, PyTorch, or TheFuzz installed, and `compileall` passes. Those tests cover findings,
clean zero findings, malformed configuration, failed-check retention, no-valid-input exit failure,
CLI argument boundaries, lazy imports, and absence of file/stderr logging. The checked-in outputs
were emitted by that patch with a minimal deterministic environment; their provenance and hashes
are frozen in the [fixture record](fixtures/mcp-armor/README.md):

- [`config-findings.json`](fixtures/mcp-armor/config-findings.json) contains one high hardcoded-secret
  result and one critical excessive-permission result with a complete two-check ledger;
- [`config-clean.json`](fixtures/mcp-armor/config-clean.json) proves that zero findings are clean only
  after both checks complete; and
- [`config-partial.json`](fixtures/mcp-armor/config-partial.json) proves that a structured
  server-configuration warning clears completeness even though both selected checks ran; and
- [`config-disabled.json`](fixtures/mcp-armor/config-disabled.json) preserves the detector's
  low-severity result for a disabled server, distinct from its critical enabled-server result.

The product adapter validates the exact envelope, versions, mode, one-input boundary, check set,
status/count agreement, stable finding types and severities (including upstream's low rating for a
disabled risky server), and bounded evidence shapes. It keeps
the upstream check id as `source_rule`. A hardcoded credential becomes an MCP-secret finding; an
over-privileged tool or command becomes an MCP-configuration finding. The upstream redacted token
excerpt remains only in the raw artifact and never enters a finding. Control references are selected
only from the two exact check ids, never from configuration-controlled names, commands, permissions,
titles, or severities.

## Current dispatch state

The configuration-only slice is in the live catalog as `integrated` and `runnable: true`, with a
published digest-pinned image. The original admission conditions for that slice are met:

1. The pinned image `1.0.2-config-only.1` (`sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc`) is published and dispatchable.
2. A typed product path selects exactly one relative MCP configuration file inside the approved
   immutable repository snapshot; no launcher may search default home-directory locations.
3. The machine-output patch is part of the reviewed image build recipe.

The image is not default-enabled. The model-backed and live MCP surface remains outside this slice.
Considering it later still requires an exact model revision, every fetched-file digest, dependency
lock, offline loading behavior, inference parameters, output provenance, applicable redistribution
record, explicit target authorization, and fail-closed model/check errors.

## Research actions performed

The source repository was shallow-cloned into the ignored `.upstreams/` research area. Public
Hugging Face repository metadata, model cards, file names, and the weight pointer were read to
establish the model revision, size, digest, and stated terms. The local configuration-only patch and
its tests were executed only against checked-in synthetic JSON fixtures. No package dependency,
model weight, container image, or credential was downloaded; no MCP server, external scan target,
OAuth flow, or hosted inference service was contacted. Nothing was packaged, published, pushed to
the product remote, or submitted upstream.
