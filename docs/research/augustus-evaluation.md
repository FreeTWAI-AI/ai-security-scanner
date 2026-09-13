# Augustus hosted-endpoint integration decision

Normative status: this is a pinned research decision, subordinate to the
[canonical product specification](../product-spec.md). It records the authorization, credential,
execution, and machine-output boundary for one audited Augustus revision. It does not authorize a
model-endpoint scan, admit an engine, or initiate packaging or publication.

Decision: Augustus is a viable upstream for future active testing of a hosted model endpoint, but
the audited output cannot yet support a fail-closed thin adapter. Do not add Augustus to the engine
catalog or adapter registry until a bounded machine-output patch and synthetic fixtures prove the
contract below. A catalog entry and adapter must then land together as one experimental,
non-runnable integration.

This static review is pinned to
[`praetorian-inc/augustus@f032fc6373aaa9983868282b31dc9c59503c78a2`](https://github.com/praetorian-inc/augustus/tree/f032fc6373aaa9983868282b31dc9c59503c78a2),
tagged `v0.14.29`. Its checked-in license is Apache-2.0
([license text](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/LICENSE#L1-L3));
the build injects the version from the Git tag rather than relying on the source fallback
([Makefile](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/Makefile#L7-L13)).
It remains `RESEARCH / NOT_DISTRIBUTED`: it is not an `ai-security-scanner` engine, installer
component, container image, or transitive release dependency.

## Why Augustus is useful

Augustus is an actual model-behavior scanner, not an inventory utility. The pinned revision states
that it provides more than 210 adversarial probes, more than 90 detectors, and integrations for 28
provider categories, with JSON, JSONL, and HTML output
([capabilities](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/README.md#L50-L60),
[providers](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/README.md#L126-L161)).
Its probe families include prompt injection, jailbreak, data extraction, multi-turn attacks, RAG,
agent and tool abuse, and exploitation payloads
([attack categories](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/README.md#L63-L77)).
That makes it a plausible second model-endpoint engine after garak, provided the product narrows it
to one reviewable and authorized profile instead of exposing the full upstream CLI.

This is active offensive testing. Upstream itself requires explicit authorization and warns that
the target can return harmful or sensitive content
([threat model](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/docs/01%20-%20Overview/Threat%20Model%20%26%20Authorized%20Use.md#L8-L41)).
Selecting an AI-application journey or possessing a provider key is not authorization to send these
prompts.

## Authorization and credential boundary

A future run must bind all of the following before dispatch:

- one exact provider, provider-owned API origin, and model identifier represented by an approved
  `ai_model_endpoint` asset;
- an `active_external_testing` scope grant for that same immutable coordinate and the chosen probe
  profile; and
- a product-owned, short-lived credential handle whose value is never stored in a case, report,
  command line, YAML/JSON configuration, log, or finding.

The current product has no scope-grant or credential path that binds a provider and model endpoint
this way. The audited Augustus CLI accepts inline JSON, YAML configuration, and provider environment
variables for API keys
([provider configuration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/docs/08%20-%20CLI%20%26%20Usage/Provider%20Configuration.md#L29-L67),
[key lookup](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/registry/config_helpers.go#L121-L131)).
Those are upstream interfaces, not permission to route a secret through this product. Integration
stays blocked until the product can deliver a credential ephemerally to an isolated process and
guarantee cleanup without exposing the value in argv, persisted configuration, or inherited ambient
environment.

The first profile must use exactly one native provider implementation and its official fixed API
origin. Even the native OpenAI generator accepts a custom `base_url`
([configuration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/generators/openai/config.go#L9-L59),
[client construction](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/generators/openai/openai.go#L59-L93));
the launcher must omit and reject that override. The generic `rest.Rest` generator is out of scope:
it accepts an arbitrary URI, HTTP method including `DELETE`, headers, body template, proxy, and
disabled TLS verification
([REST configuration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/generators/rest/rest.go#L139-L171),
[network overrides](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/generators/rest/rest.go#L232-L292)).

## The upstream CLI is wider than the product boundary

The CLI exposes individual names, globs, `--all`, reconnaissance, arbitrary detector and buff
selection, YAML profiles, and three runtime shell hooks
([CLI shape](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/cmd/augustus/cli.go#L52-L98)).
The hooks are executable commands, and the per-probe hook receives the preceding raw target
response
([execution path](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/cmd/augustus/scan.go#L645-L705)).
None of those controls may cross the adapter boundary.

The product-owned launcher must provide a fixed, source-audited allowlist of single-turn probes and
their intended local detectors. It must reject `--all`, globs, reconnaissance, buffs, config files,
profiles, custom detectors, and setup/prepare/cleanup hooks. `--all` is not a safe profile: it starts
from every registered probe and only filters a short list of unconfigured multi-turn probes
([selection logic](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/cmd/augustus/scan.go#L732-L767)).

The first profile must also exclude any path that creates a second network target or credential:

- TAP constructs separate attacker and judge generators
  ([TAP setup](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/probes/tap/tap.go#L41-L88));
- the judge detector creates another model generator
  ([judge setup](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/judge/judge.go#L41-L69));
- the Perspective detector calls a separately keyed Google endpoint
  ([Perspective setup](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/perspective/perspective.go#L28-L60),
  [detection path](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/perspective/perspective.go#L96-L109)); and
- package-hallucination detectors query public package registries such as PyPI
  ([default destination](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/packagehallucination/pythonpypi.go#L20-L38),
  [checker construction](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/packagehallucination/pythonpypi.go#L124-L149)).

Multi-turn, attacker/judge, package-registry, Perspective, browsing, tool/MCP, RAG, out-of-band, and
exploitation paths therefore remain excluded until each destination, side effect, and authorization
requirement has been separately audited. The launcher must also set finite concurrency, request
count, retry, token/output, per-probe, and whole-run limits; upstream defaults to concurrency 10 and
no overall or per-probe timeout
([defaults](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/scanner/options.go#L31-L39)).

## Source-audited first profile

The first profile is now frozen as the research-only
[`augustus-openai-promptinject-v1`](augustus-single-destination-profile.json) contract, SHA-256
`2dacb19545726fa0a18b8fa412633dca5df6cf2289c6a5db6ea95bec08a9a798`. It remains blocked from
dispatch. The allowlist contains exactly one native generator, one probe, and one detector:

- generator `openai.OpenAI`, bound at dispatch to the exact model in the scope grant and only the
  fixed `https://api.openai.com:443/v1` API base;
- probe `promptinject.HijackLongPrompt`; and
- detector `promptinject.AttackRogueString`, with its upstream default case-insensitive match.

`HijackLongPrompt` uses the non-full variant and an inert 116-byte sentinel rather than the sibling
hate or kill strings
([registration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/probes/promptinject/hijack.go#L23-L48)).
Its source combines three ordinary questions with five static injection forms and stops the
non-full variant at exactly 15 prompts
([prompt construction](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/probes/promptinject/hijack.go#L81-L128)).
Each prompt creates a new conversation and calls the target generator once with `n = 1`; it supplies
no tools and retains the sentinel as attempt metadata
([execution](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/probes/promptinject/hijack.go#L130-L159)).
The detector performs only a local case-insensitive substring comparison against that metadata and
returns upstream scores of `1.0` for a match and `0.0` otherwise
([detector registration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/promptinject/promptinject.go#L13-L35),
[matching](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/detectors/base/trigger_match_detector.go#L56-L108)).
It opens no file, process, model, or network connection. The only permitted network operation is the
target generator call to the granted provider/model coordinate.

The ordered prompt corpus is pinned by SHA-256
`8c8c6136d30d94639587e20101d4716589c282ce4e8941d7766758de421c0278`, calculated over its compact
UTF-8 JSON array in source order. It contains 3,212 prompt bytes total and no prompt exceeds 233
bytes. All other generator, probe, and detector IDs are denied rather than treated as optional
profile expansion.

The same machine-readable contract fixes these ceilings:

| Boundary | Ceiling |
| --- | --- |
| Target work | 15 provider requests; one turn, one generation, and no tools per attempt |
| Token/cost work | 512 input tokens and 128 output tokens per request; 7,680 input, 1,920 output, and 9,600 total tokens per run |
| Monetary preflight | USD 0.25 worst-case estimate; unknown model pricing or a higher estimate rejects dispatch |
| Rate and retry | One request per second, one concurrent connection, zero scanner retries, and zero redirects |
| Time | 20 seconds per request, 300 seconds for the probe and scanner, 330 seconds for the process including terminal output |
| Process | 1,000 CPU millis, 512 MiB memory, 128 PIDs, and 16 MiB writable temporary storage |
| I/O | 256 KiB per provider response; 1 MiB each for stdout and stderr |

These are launcher and isolation requirements, not claims about current Augustus enforcement.
Augustus exposes scanner/probe timeouts and concurrency, and its scanner can disable its own probe
retry
([scanner options](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/scanner/options.go#L9-L39),
[execution](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/scanner/scanner.go#L87-L163)).
The native generator accepts `max_tokens`, but also accepts a custom `base_url`
([typed configuration](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/generators/openai/config.go#L9-L59));
the future typed launcher must set the former and reject the latter. A product-owned outer deadline
and exact-destination egress gate must enforce the request rate, redirect, body-size, and monetary
ceilings that Augustus does not provide. Missing enforcement rejects dispatch.

The audit also found one fail-closed integration gap. `HijackLongPrompt` is a custom prober rather
than `SimpleProbe` and does not implement the retained machine patch's `ExpectedAttemptCounter`.
The current patched output would therefore mark its expected-attempt plan unknown and
`complete: false`. Before any integration test, a narrow upstream patch must report the existing
15-prompt count without changing prompt or detector behavior, and a synthetic test must prove that
the machine plan says exactly 15. This audit approves only the frozen profile and limits; it does
not authorize or make the profile runnable.

## Why the current machine output is not admissible

The documented JSONL record carries an upstream `probe`, `detector`, score array, four-way verdict,
status, error, timestamp, and the complete prompt and target response
([output contract](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/docs/08%20-%20CLI%20%26%20Usage/Output%20%26%20Reports.md#L41-L62),
[record type](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/results/results.go#L35-L87)).
This is useful per-attempt evidence, but it has no schema version, source revision, trusted provider
and model coordinate, declared probe/detector plan, expected count, run-level `complete` flag, or
structured warning ledger. A consumer cannot prove that missing rows mean a clean run.

Two audited paths make that ambiguity concrete:

- the probewise harness deliberately invokes detectors with `SkipOnError`
  ([harness](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/internal/harnesses/probewise/probewise.go#L158-L225));
  `ApplyDetectors` logs a detector failure, continues, and later marks the attempt complete when the
  attempt itself is not already in an error state
  ([detector handling](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/harnesses/detection.go#L71-L100),
  [skip and completion](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/harnesses/detection.go#L131-L199)); and
- the incremental JSONL writer returns no error from `Append`; an encoding failure is printed to
  stderr and the line is lost
  ([stream writer](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/results/stream.go#L37-L53)).

At run level, probe failures are counted internally and successful siblings continue, but attempts
from a failed probe are not included in the returned list
([scanner aggregation](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/pkg/scanner/scanner.go#L194-L226)).
Augustus does return exit code 3 when output attempts themselves are errored
([exit contract](https://github.com/praetorian-inc/augustus/blob/f032fc6373aaa9983868282b31dc9c59503c78a2/cmd/augustus/main.go#L14-L54)).
That is a useful fail-closed signal, and the product must retain its existing rule that a non-zero
engine exit produces no findings. It does not repair detector skips or silently missing JSONL rows
that can occur without an errored attempt.

For those reasons, adapting the current JSONL would require the product to infer whether the
declared scan completed. That would invent scanner meaning and could report a false clean result.

## Required machine-output patch

The next research step is a narrow upstream-oriented patch, exercised only with Augustus's local
`test.Repeat` generator and synthetic fixtures. It may change output and orchestration plumbing, but
must not change probe prompts, detector scores, thresholds, verdicts, evidence, or remediation.

The machine envelope must include:

- a schema version, Augustus version, audited source revision, and a stable run identifier;
- the trusted native generator name, official endpoint identity, model identifier, and exact ordered
  probe/detector plan supplied by the launcher;
- expected, started, completed, not-tested, errored, and emitted attempt/probe counts;
- the exact upstream attempt verdicts and scores, plus structured detector and probe failure records;
- structured, bounded warnings and an explicit `complete` boolean; and
- a terminal output record that is written only after all rows are durably encoded.

Any skipped or failed detector, missing expected attempt, probe shortfall, count mismatch, or
unwritten row must make `complete: false`; it must never become `safe`. A fully encoded assessment
shortfall may exit 0 with `complete: false` so the product can preserve genuine sibling findings as
a partially completed scan. A target transport/authentication failure, process failure, malformed
envelope, or output-write failure remains non-zero and therefore remains the end of evidence.

The raw machine artifact is sensitive. It may retain upstream prompts and responses for audit under
the product's existing export redaction rules, but the adapter must never copy a target response,
arbitrary metadata, credential, or unbounded error text into a normal finding.

## Future normalization decision

Once the contract above is fixture-proven, the thin adapter may normalize only what Augustus states:

- only an upstream `vuln` verdict becomes a finding;
- the exact upstream probe and detector identifiers, scores, bounded evidence pointer, and remedy are
  preserved;
- severity remains `Unknown`, because Augustus publishes a detector score and verdict rather than a
  severity. A new basis code must describe an unrated upstream adversarial verdict; the garak-specific
  `AdversarialProbeFailureRate` basis must not be reused for a single-attempt score;
- `review` is not a vulnerability and is not clean; it becomes an explicit manual-review outcome or
  coverage warning once the shared result model can represent it without promotion;
- `safe` contributes to a clean result only when the declared plan is complete and every detector,
  attempt, and output row is accounted for; and
- `error`, `not_tested`, skipped detectors, and warnings clear completeness rather than becoming
  findings or disappearing.

No control-framework mapping is approved by this decision. A mapping can be reviewed only after the
fixed probe profile exists, using upstream identifiers and evidence rather than names or target
content.

## Local machine-output patch evaluation

On 2026-09-13, the narrow output patch was evaluated against the pinned source in the ignored
research checkout. The exact
[`augustus-0.14.29-machine-json.patch`](patches/augustus-0.14.29-machine-json.patch) has SHA-256
`963f7654cc043d097bf714169dae7ac445e7cdf79a3178652f4efc43309a10e2`. It was generated from local
research commit `4195d19e2223690ca565d8ca8469b74e1069fca0`, whose parent is the audited upstream
commit.

The patch stays within output and orchestration plumbing:

- adds `machine-json` as a terminal schema-versioned document with trusted run, endpoint, generator,
  model, version, source, and exact ordered probe/detector plan metadata;
- records expected, started, completed, successful, failed, produced, processed, emitted,
  not-tested, and errored counts instead of inferring coverage from surviving rows;
- adds an explicit expected-attempt interface to static one-prompt-per-attempt probes, while an
  unsupported probe makes the plan incomplete rather than guessing;
- turns a detector skipped under the existing `SkipOnError` behavior into a bounded
  `detector_failed` warning and `complete: false`, without changing the detector score or upstream
  attempt verdict;
- emits `count_mismatch`, provenance, plan, not-tested, and errored warnings fail-closed; and
- propagates terminal JSON encoding failures plus incremental JSONL append, sync, and close failures
  to the process boundary.

The machine CLI path requires a trusted run ID and endpoint identity, explicit probe names, and the
probewise harness. It rejects `--all`, globs, recon, buffs, runtime hooks, config files, inline
configuration, secondary output files, and runtime detector tuning. This prevents the research path
from becoming an alternate credential or target-expansion channel; the future product launcher
still owns authorization and secure credential delivery.

The three reviewed [`test.Repeat` fixtures](fixtures/augustus/README.md) cover a complete run, a
detector warning, and a count mismatch. Six dependency-free focused Go test commands passed,
including the real checked-in `test.Repeat` generator and a failing writer; the affected core
packages also built offline. The full upstream suite could not run with `GOPROXY=off` because
`testify` and `x/text` were absent from the local module cache. They were not downloaded or
installed. This local evidence proves the machine contract's shape, but it is not release
qualification or engine admission.

## Remaining blockers

Augustus remains outside the catalog until all of these are independently resolved:

1. an exact provider/model endpoint scope-grant path for active external testing;
2. a product-owned ephemeral credential-delivery and cleanup path;
3. upstream review plus a dependency-complete gate for the pinned machine-output patch;
4. a typed launcher and exact-destination egress gate that enforce the frozen profile, plus an
   explicit 15-attempt contract and dependency-complete synthetic proof; and
5. a separately authorized packaging decision by the product owner.

Packaging is deliberately not started by this research decision. Clearing the first four blockers
does not authorize the fifth.

## Research actions performed

The exact upstream revision was shallow-cloned into the ignored `.upstreams/` research area and
reviewed as source. The patched output components and checked-in `test.Repeat` generator were run
locally against inert synthetic data with network-backed module lookup disabled. No Augustus probe,
hosted-provider generator, target, or provider API was contacted; no dependency was installed, and
no credential or model weight was accessed. No image was built or published, and no repository
branch was pushed. The later profile audit only read the pinned source and calculated deterministic
prompt counts, byte lengths, and hashes; it did not execute Augustus code or open a network
connection.
