# Contributing

Contributions should make the product faster to understand, easier to start, and more useful after the first scan. Read the [product specification](docs/product-spec.md) before changing user-visible behavior.

## Product priorities

Use these priorities when choosing and reviewing work:

1. A beginner can quickly start a meaningful scan and understand the result.
2. Scanner integrations stay close to upstream behavior and data.
3. The product combines engine output into one clear, professional report.
4. Versioning, release timing, publication, and compliance positioning are product-owner decisions. Do not expand work into those areas unless the owner explicitly requests it.
5. Primary choices, progress, and reports stay concise and action-led; detail is available on demand.

A connectivity check, process launch, or empty report is not meaningful scan value. Product-facing work should help the user discover a real exposure, vulnerability, secret, risky configuration, or other actionable security signal—or clearly explain why a requested check could not run.

## Product changes

Prefer the shortest complete beginner journey:

- let one environment project contain multiple repositories, internal devices or endpoints, and websites, while retaining single-target shortcuts;
- ask only for information needed to start checks for the selected assets;
- provide useful defaults and keep advanced controls out of the primary path;
- route each upstream engine to only its applicable approved asset IDs;
- show which assets were scanned, the most important results, their impact, and the next action in one report;
- distinguish no findings from checks that did not run; and
- preserve saved work and allow unaffected checks to continue when one scanner fails.

Active scans remain in Progress. Results and Export open only for a terminal run. Do not add live/interim reports, defensive caveat walls, implementation-defect or test-harness explanations, or prose that transfers product responsibility to the user. Put required formal terms at the end or footer of the final report and keep technical evidence in collapsed detail.

Inventory, service discovery, port reachability, and connectivity may prepare an internal target, but they cannot satisfy vulnerability-scan value by themselves.

Test rendered behavior and a real user path where practical. Source-text assertions and schema checks can support that evidence, but they do not replace exercising the interaction they describe.

## Scanner integrations

Keep adapters thin. Let the upstream scanner own detection, rule behavior, severities, and scanner-specific evidence. Product code should concentrate on:

- converting the user's approved target and options into typed scanner input;
- launching without shell interpolation and with bounded resources;
- preserving upstream identifiers, versions, evidence, and raw output references;
- translating execution outcomes into consistent task and coverage states; and
- normalizing results for the shared report without inventing findings.

Avoid duplicating upstream detection logic or maintaining product-specific rewrites of titles, severity, and remediation when the upstream scanner already supplies them.

An engine contribution should include its official source and license, a supported version or digest, input and permission requirements, a typed launcher, redacted fixtures, parser tests, and honest completed/partial/failed/timed-out/cancelled behavior. An unavailable scanner should leave sibling checks usable and its coverage visibly untested.

## Professional reporting

All scanners feed one report model. A report contribution should improve the shared presentation of:

- scope and checks actually run, grouped by affected repository, internal device or endpoint, and website;
- prioritized findings with evidence and impact;
- recommended next actions;
- coverage gaps, failures, and exclusions; and
- technical details available when needed;
- cross-engine correlation or deduplication without losing any source finding or evidence.

Framework mappings may enrich a report, but they do not replace findings and should not control whether a scan can run.

## Reviewing user-facing claims

User-facing copy must not claim behavior that a different layer does not implement. A beginner cannot detect that mismatch, so a precise false claim is worse than a plainly disclosed limit. Trace every important promise to the data and execution that make it true, then confirm the rendered user state as Product changes already requires.

Look for these defect families:

- Failed or missing runs presented with completed-looking language.
- Report identity and history that borrow current-case values instead of the selected run's saved facts.
- Export copy that overstates redaction, source attachment, signatures, relationships, or format availability.
- Setup and authorization copy that offers actions or outcomes the backend cannot provide.
- Scanner output that is dropped, flattened, or assigned product-authored severity while appearing upstream-authored.
- English technical prose leaking into the Traditional Chinese first layer.
- Coverage gaps that collapse different causes into one misleading sentence.

When reviewing a user-facing claim:

1. Identify the decision the user will make from a sentence or status.
2. Trace the underlying target, task, scanner output, report record, and export path.
3. Fix the product behavior or replace the claim directly.
4. Render the affected state and assert the decision-relevant outcome.
5. When the change concerns a scan, exercise the real upstream path when practical.

## Verification

Run checks proportional to the changed boundary. Common commands include:

```bash
npm run test:frontend
npm run test:component
npm run typecheck
npm run build
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
```

For a small copy or documentation change, focused tests and link checks are enough. For a changed scan path, exercise the affected input, execution, saved result, and report flow. Release packaging, signing, publication, and compliance work are outside ordinary contribution scope unless explicitly requested by the product owner.

## Data and scope safety

- Never commit credentials, tokens, customer findings, personal data, internal addresses, or real scan reports.
- Use synthetic, redacted fixtures and reserved example domains or address ranges.
- Never contact a target without the user's explicit scope authorization.
- Do not execute remediation commands.
- Explain new network, process, filesystem, credential, or data-retention behavior in the pull request.

Keep each change focused and rewrite obsolete guidance where it lives instead of adding contradictory correction sections.

<!-- freedom-repository-guide:start -->
## 自由工坊：從一個成果到一個 PR

資安公會的授權範圍檢查與報告工具來源。 工坊保留上游桌面／CLI、scanner adapters 與報告程式，可用於有權測試的自有環境練習。

先看[本倉 Issues](https://github.com/FreeTWAI-AI/ai-security-scanner/issues)與[現有 PR](https://github.com/FreeTWAI-AI/ai-security-scanner/pulls)。提出問題、這一輪範圍、完成條件與可投入時間，在 Issue 認領並協調重疊工作；維護者已直接派工時不必重複等待，將約定連回交接即可。使用自己的 fork／分支，PR 送到 **FreeTWAI-AI/ai-security-scanner:main**。

交給 Agent 前先讓它讀 [AGENTS.md](AGENTS.md)。PR 寫明變更用途、使用者可見結果、驗證命令、限制與原 Issue；附上可公開的合成案例或重現方式。Issue／PR 是程式協作的記錄，平台名片與公會身分不取代 repo 維護者的審查。

偵測維持上游 engine 行為與證據；探測連通性不等於安全檢查。不得因公會身分掃描他人資產，真報告、憑證與內部地址不進公開 PR，也不自動送中央資料庫。

### 這個模組怎麼驗證

選擇與修改範圍相符的既有入口：

```sh
npm run test:frontend
npm run test:component
npm run typecheck
```

命令列在這裡不表示本輪已執行。先核對依賴與環境，再記錄實際結果；缺工具、桌面、媒體或授權時寫 `not_run` 與原因，不能補造成功。純文件修改以連結／路徑核對與 `git diff --check` 為主。

### 署名與上游

工坊 Fork：上游產品／授權來源為 [teddashh/ai-security-scanner](https://github.com/teddashh/ai-security-scanner)；本次協作的 Issue／PR 送到 **FreeTWAI-AI/ai-security-scanner**，不是自動送往上游。 保留原作者與授權檔，另列真正完成文件、測試、設計、程式或協作的人。使用 AI 時如實交代協作範圍；只有實際 GitHub PR／review／合併紀錄可以作為對應貢獻證據，不能靠自填帳號推定。

自願貢獻不保證案源、XP、收益或雇用。若產生付費合作，由當事人另定條款與 Seller 外部收款；平台不代收。秘密、客戶資料、真實交易單據與未授權素材不進公開 Issue／PR。
<!-- freedom-repository-guide:end -->
