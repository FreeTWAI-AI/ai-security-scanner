# Augustus machine-output research fixtures

Normative status: these are synthetic machine-output fixtures for the pinned
[Augustus hosted-endpoint integration decision](../../augustus-evaluation.md). They are not product
findings, an admitted engine contract, authorization to contact a model endpoint, or proof that a
hosted model security check ran.

## Provenance

The fixtures exercise
`praetorian-inc/augustus@f032fc6373aaa9983868282b31dc9c59503c78a2` plus the exact
[`augustus-0.14.29-machine-json.patch`](../../patches/augustus-0.14.29-machine-json.patch), whose
SHA-256 is `963f7654cc043d097bf714169dae7ac445e7cdf79a3178652f4efc43309a10e2`.
The patched ignored checkout is at local research commit
`4195d19e2223690ca565d8ca8469b74e1069fca0`, whose parent is the pinned upstream revision.

`TestRepeatMachineOutputFixtures` invokes the checked-in `test.Repeat` generator directly. Its only
input is the inert string `SYNTHETIC AUGUSTUS REPEAT INPUT`, which it echoes locally. Fixed synthetic
detectors then produce either a score or an error; no probe payload or hosted-provider generator is
used.

Every focused Go command ran with an empty inherited environment and explicit local Go paths,
`GOTOOLCHAIN=local`, `GOPROXY=off`, and `GOSUMDB=off`. That made dependency download impossible.
The full upstream suite was not run because two test-only modules were absent from the local cache;
no dependency was installed to bypass that boundary. Six focused file-list test commands and the
affected dependency-free package build completed instead.

| Fixture | Contract result | SHA-256 |
| --- | --- | --- |
| [`machine-complete.json`](machine-complete.json) | One planned, started, completed, processed, and emitted attempt; `complete: true` | `8482446756cdcd079d8349aa5ac4c828092e7ec4236dae3b43ea5d7f0921f52b` |
| [`machine-detector-warning.json`](machine-detector-warning.json) | Detector error retained as a bounded warning; `complete: false` | `1fc37120cb27660f1958f30f6ccdbd03aa5d64ff446e637aff671d81342dd2f7` |
| [`machine-count-mismatch.json`](machine-count-mismatch.json) | Two attempts expected but only one started and emitted; `complete: false` | `d94b8616c134194f7c8a0ce11e2d2167fd611a4b1117c067347cd4d006eade19` |

## Contract audit

All three files contain schema version `1`, scanner version `v0.14.29`, the exact upstream source
revision, a stable run ID, `test.Repeat` plus the inert `local://test-repeat` endpoint identity, an
ordered probe/detector plan, explicit probe and attempt counts, `complete`, structured warnings, and
the unmodified upstream attempt records.

The warning fixture deliberately retains the attempt's upstream `safe` verdict while the failed
detector makes the run incomplete. This proves the adapter must require top-level completeness
before a safe attempt contributes to a clean result; it must not reconstruct completeness from
attempt verdicts. Detector warnings contain only the stable code, probe, attempt ID, and detector.
The synthetic detector's error message is not copied into machine output.

The count-mismatch fixture proves that a structurally valid attempt cannot hide a missing planned
attempt. `WriteMachineJSON` is separately tested with a writer that always fails, and the patched
incremental JSONL writer now propagates both append and durable-close failures. Any such error keeps
the process non-zero, so a partial byte sequence cannot become evidence.

The prompt and response in these fixtures are identical synthetic text because `test.Repeat` echoes
locally. Real target responses remain sensitive raw artifacts and must never be copied into normal
finding text.

No hosted provider, model endpoint, secondary detector service, package registry, or other scan
target was contacted. No credential or model weight was accessed, no image was built or published,
and no branch was pushed.
