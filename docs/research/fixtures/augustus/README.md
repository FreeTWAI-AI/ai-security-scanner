# Augustus machine-output and pre-contact research fixtures

Normative status: these are synthetic research fixtures for the pinned
[Augustus hosted-endpoint integration decision](../../augustus-evaluation.md). They are not product
findings, an admitted engine contract, authorization to contact a model endpoint, or proof that a
hosted model security check ran.

## Provenance

The machine-output fixtures exercise
`praetorian-inc/augustus@f032fc6373aaa9983868282b31dc9c59503c78a2` plus the exact
[`augustus-0.14.29-machine-json.patch`](../../patches/augustus-0.14.29-machine-json.patch), whose
SHA-256 is `4f6c1e0d16014ac2a638ec50ebbab053b7a3c6a7320911fbff14b8541f45b59a`.
The patched ignored checkout is at local research commit
`13c96bc6a36f880e7f016e02da63eadd64b73674`, whose parent is the pinned upstream revision.

`TestRepeatMachineOutputFixtures` invokes the checked-in `test.Repeat` generator directly. Its only
input is the inert string `SYNTHETIC AUGUSTUS REPEAT INPUT`, which it echoes locally. Fixed synthetic
detectors then produce either a score or an error; no probe payload or hosted-provider generator is
used.

Every focused Go command ran with an empty inherited environment and explicit local Go paths,
`GOTOOLCHAIN=local`, `GOPROXY=off`, and `GOSUMDB=off`. That made dependency download impossible.
The full upstream suite was not run because two test-only modules were absent from the local cache;
no dependency was installed to bypass that boundary. Six dependency-free focused file-list
commands and the affected package build completed. A seventh focused command created the real
`promptinject.HijackLongPrompt` probe and used the checked-in `test.Repeat` generator to prove its
machine plan contains exactly 15 attempts; a temporary overlay excluded only the unrelated
`lipsum.go` file whose uncached `x/text` import otherwise prevented compilation.

| Fixture | Contract result | SHA-256 |
| --- | --- | --- |
| [`machine-complete.json`](machine-complete.json) | One planned, started, completed, processed, and emitted attempt; `complete: true` | `8482446756cdcd079d8349aa5ac4c828092e7ec4236dae3b43ea5d7f0921f52b` |
| [`machine-detector-warning.json`](machine-detector-warning.json) | Detector error retained as a bounded warning; `complete: false` | `1fc37120cb27660f1958f30f6ccdbd03aa5d64ff446e637aff671d81342dd2f7` |
| [`machine-count-mismatch.json`](machine-count-mismatch.json) | Two attempts expected but only one started and emitted; `complete: false` | `d94b8616c134194f7c8a0ce11e2d2167fd611a4b1117c067347cd4d006eade19` |

## Pre-contact rejection vectors

[`precontact-rejections.json`](precontact-rejections.json), SHA-256
`3376e1757f658acbb13863584e105acc043192997ce3c02e71a73c174bedbab7`, is a pure-data companion to
the frozen launcher/egress enforcement matrix. It assigns all 14 rules a unique order and stable
lowercase error code. Its 35 synthetic vectors cover every matrix rejection condition exactly once.
Evaluation stops at the lowest failing order and returns only that rule's code; every vector expects
zero provider requests, no egress lease, no target contact, and no findings.

The vectors are not executable launcher inputs and do not claim that later rules can make the
current profile runnable. The actual frozen profile stops at order 1 with
`augustus_profile_not_admitted` because its normative status remains `research_only_blocked`.

The reject-only [`augustus-preflight.schema.json`](../../augustus-preflight.schema.json), SHA-256
`eba52bc18c2954df58c127084a6408a76666083e7fa65df32a9908ff9f35cd04`, defines the typed input and
output that carry this contract. Input contains only fixed artifact references plus 14 ordered
`verified`, `rejected`, or `unverified` evidence states. Output can carry only the first stable
rejection triplet, the input SHA-256, exact artifact references, and the same zero-contact
invariants; there is no accepted or dispatchable output shape.

### Schema-valid pairs

Each pair below independently validates against the schema. Its input has exactly one `rejected`
rule and 13 `verified` rules; its output returns the matching first rejection and binds the exact
input file bytes by SHA-256. CI pins every input and output digest. These are isolated schema
examples, not caller authority: the product evaluator mechanically replaces rules 1 and 2 with
evidence from the embedded profile, retained machine-patch digest, frozen source revision, and
profile blocker ledger. It also replaces Rule 3 with the frozen destination plus an explicit absent
scope-grant and bound-model state. Rule 4 retains the profile's custom-base-URL and redirect denials
as intent, while separately recording that neither launcher nor HTTP-gate enforcement exists. Rule
5 likewise retains the exact ordered 16-entry denied-capability ledger only as intent; closed
launcher and destination-gate enforcement remain absent. Rule 6 retains the exact one-entry
probe/detector allowlist, case-insensitive setting, and 15-attempt metadata, but the machine plan
remains absent. Rule 7 separately retains the 15-attempt, one-turn, one-generation, no-tools shape,
while terminal reconciliation evidence remains absent. Rule 8 retains the reviewed ordered corpus
digest, source revision, count, and byte bounds, but has no launcher evidence binding the executed
prompt source to that attestation. With the current profile, every schema-valid pair therefore stops
at rule 1 when evaluated by the product.

| Order | Pair | Stable error code |
| --- | --- | --- |
| 1 | [input](preflight/01-profile-identity.input.json) / [output](preflight/01-profile-identity.output.json) | `augustus_profile_not_admitted` |
| 2 | [input](preflight/02-dispatch-blockers.input.json) / [output](preflight/02-dispatch-blockers.output.json) | `augustus_dispatch_blocked` |
| 3 | [input](preflight/03-scope-binding.input.json) / [output](preflight/03-scope-binding.output.json) | `augustus_scope_binding_rejected` |
| 4 | [input](preflight/04-destination-policy.input.json) / [output](preflight/04-destination-policy.output.json) | `augustus_destination_policy_rejected` |
| 5 | [input](preflight/05-denied-capabilities.input.json) / [output](preflight/05-denied-capabilities.output.json) | `augustus_capability_rejected` |
| 6 | [input](preflight/06-plan-allowlist.input.json) / [output](preflight/06-plan-allowlist.output.json) | `augustus_plan_allowlist_rejected` |
| 7 | [input](preflight/07-attempt-shape.input.json) / [output](preflight/07-attempt-shape.output.json) | `augustus_attempt_shape_rejected` |
| 8 | [input](preflight/08-prompt-corpus.input.json) / [output](preflight/08-prompt-corpus.output.json) | `augustus_prompt_corpus_rejected` |
| 9 | [input](preflight/09-cost-budget.input.json) / [output](preflight/09-cost-budget.output.json) | `augustus_cost_budget_rejected` |
| 10 | [input](preflight/10-concurrency.input.json) / [output](preflight/10-concurrency.output.json) | `augustus_concurrency_policy_rejected` |
| 11 | [input](preflight/11-request-policy.input.json) / [output](preflight/11-request-policy.output.json) | `augustus_request_policy_rejected` |
| 12 | [input](preflight/12-deadlines.input.json) / [output](preflight/12-deadlines.output.json) | `augustus_deadline_policy_rejected` |
| 13 | [input](preflight/13-sandbox.input.json) / [output](preflight/13-sandbox.output.json) | `augustus_sandbox_policy_rejected` |
| 14 | [input](preflight/14-output-bounds.input.json) / [output](preflight/14-output-bounds.output.json) | `augustus_output_bound_rejected` |

### Schema-negative fixtures

These four documents are deliberately invalid. Each starts from the order-1 valid pair and changes
only the named contract dimension; schema rejection is the expected result.

| Fixture | Required rejection | SHA-256 |
| --- | --- | --- |
| [`accepted-output.json`](preflight-negative/accepted-output.json) | Output uses unsupported `decision: accepted` | `ca1e8fb881e826e12f910c74a3b9644a23ca3968edc1ae50e7faebac0fb1ffc1` |
| [`all-verified-input.json`](preflight-negative/all-verified-input.json) | Input has no `rejected` or `unverified` rule | `a0043709139d4632259972f585e8a0fee407471062a161cf1cf6482d66512cd4` |
| [`mismatched-error-code.json`](preflight-negative/mismatched-error-code.json) | Order-1 rule carries the order-2 error code | `b0c78605017b4513359c32a42a0a24c5d74fefe1d9957fa678032ad7c991ee2a` |
| [`extra-argv-input.json`](preflight-negative/extra-argv-input.json) | Input adds the forbidden `argv` property | `e7507226a66766524e5ea6539caaf8823881cff24c19b54c5c60388574666961` |

## Contract audit

All three machine-output files contain schema version `1`, scanner version `v0.14.29`, the exact
upstream source revision, a stable run ID, `test.Repeat` plus the inert `local://test-repeat`
endpoint identity, an ordered probe/detector plan, explicit probe and attempt counts, `complete`,
structured warnings, and the unmodified upstream attempt records.

The warning fixture deliberately retains the attempt's upstream `safe` verdict while the failed
detector makes the run incomplete. This proves the adapter must require top-level completeness
before a safe attempt contributes to a clean result; it must not reconstruct completeness from
attempt verdicts. Detector warnings contain only the stable code, probe, attempt ID, and detector.
The synthetic detector's error message is not copied into machine output.

The count-mismatch fixture proves that a structurally valid attempt cannot hide a missing planned
attempt. `WriteMachineJSON` is separately tested with a writer that always fails, and the patched
incremental JSONL writer now propagates both append and durable-close failures. Any such error keeps
the process non-zero, so a partial byte sequence cannot become evidence.

The product's pure Rust
[`augustus_terminal`](../../../../src-tauri/src/augustus_terminal.rs) verifier consumes these three
fixtures without invoking Augustus. They pin a complete result, an incomplete detector-warning
result, and an incomplete count shortfall. A synthetic document derived from the complete fixture
also exercises the frozen 15-prompt corpus and proves that 14 reconciled rows cannot carry a clean
terminal result.

The prompt and response in these fixtures are identical synthetic text because `test.Repeat` echoes
locally. Real target responses remain sensitive raw artifacts and must never be copied into normal
finding text.

No hosted provider, model endpoint, secondary detector service, package registry, or other scan
target was contacted. No credential or model weight was accessed, no image was built or published,
and no branch was pushed.
