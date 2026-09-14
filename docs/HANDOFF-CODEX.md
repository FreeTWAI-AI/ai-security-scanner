# 交接紀錄：給下一位 Codex Agent

交接日期：2026-09-13（America/New_York）
交接基準 commit：`9032d96`（`main`，**未 push**）
最新續接紀錄：`7a07d65`（Agentic Radar Step 2 收斂稽核，`main`，**未 push**）
交接者：Claude Code session `284f7d7a-b6c3-4a29-b652-c31fa7be49dd`，工作區間 2026-09-09 01:07 → 2026-09-13 01:16（America/New_York），該區間共 183 個 commit

> 這份文件是**開發交接**，不是產品規格、發布核准、合規聲明或安全保證。
> 產品行為的唯一依據是 [產品規格](product-spec.md)。本文與規格衝突時以規格為準，並把衝突當成待修缺陷。
> 專案全景與歷史請讀 [完整開發交接筆記](project-handover.zh-TW.md)（978 行，基線 `9f1f570`，**部分章節已被本文取代**，見 §7）。
> 你的行為約束在 [AGENTS.md](../AGENTS.md)（與 `CLAUDE.md` 逐字相同，由 `tests/ci/skill-parity.test.mjs` 綁定）。

## 0. Product doctrine (locked 2026-09-13 Ted)

See [`PRODUCT-DOCTRINE.md`](PRODUCT-DOCTRINE.md). Short form: optimize **time-to-first-scan**; finish Augustus **Rules 8→14** as pure-data fail-closed evidence only (no launcher/network/credentials/push unless Ted says); **never** invent an advanced Augustus 14-knob UI — one simple starter path + short human reject one-liners; refuse incomplete exports / do not loosen contracts for green builds.


---

## 1. 目前目標與剛完成的里程碑

### 當前軸

**AI 引擎研究／experimental integration 軸已在不可派送邊界收斂。** garak、Agentic Radar、MCP Armor 與 Augustus 的既定研究或純資料證據均已保留；這不代表它們已建立可派送能力。不要自行處理 image、typed framework-selection、上游 PR／release、launcher、網路、provider 或憑證 blocker。

下一條可開軸線只在 §3 命名，尚未開始。

### 剛完成：Agentic Radar Step 2 收尾

| commit | 內容 |
| --- | --- |
| `d6d7666` | pinned 研究決定：workflow graph 收成 observations，不把 11 條通用警語當 findings |
| `546104c` | Step 2b：experimental、不可派送 catalog entry 與 fixture-bound thin adapter |
| `ed24d1d` | Step 2c：本機上游 issue／PR 草稿；沒有送出 GitHub |
| `488698b` | 重新核對 shallow checkout、pin、license 與文件時態 |
| `7a07d65` | Step 2b／2c 收斂稽核：pin、patch、fixtures、catalog、adapter 與草稿一致 |

**未 push。`7a07d65` 時 `main` 有 50 個未推送 commit。** Ted 的指示是 `main 未推送先不要 push`；要 push 需要他明確點頭。

### 交接時的測試數字（全綠）

| lane | 指令 | 結果 |
| --- | --- | --- |
| cargo（12 targets） | `cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli` | **1622** pass / 0 fail |
| frontend | `npm run test:frontend` | **601** pass / 0 fail |
| component | `npm run test:component` | **262** pass（18 files） |
| ci | `node --test tests/ci/*.test.mjs` | **35** pass |
| engines | `npm run validate:engines` | **8** pass |
| typecheck | `npm run typecheck` | 綠 |
| clippy | `cargo clippy … --all-targets -- -D warnings` | 綠 |
| fmt | `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` | 綠 |

cargo 1622 的分佈：lib 1032、cli 35、`adapter_fixtures` 95、`all_engine_report_audit` 4、`connector_fixtures` 15、`discovery_coverage` 11、`engine_execution` 362、`job_manager` 21、`local_case_lifecycle` 4、`source_authorization` 14、`workspace_snapshot` 26、doc-tests 3。

報告頁數（穩定基準，改報告版面後要對）：mixed **EN 19 / ZH 16**、every-detector **EN 22 / ZH 18**、standard-redacted **EN 24 / ZH 23**。

---

## 2. 進行中／未完成，以及關鍵檔案路徑

### 2.1 garak：已落地的部分（Step 1 完成）

引擎目錄現在有 **24** 筆：21 個 `integrated` + `runnable: true`，加上 garak、Agentic Radar、MCP Armor 三筆 `experimental` + `runnable: false`。

**garak 是刻意不可派送的**，而且是型別強制、不是紀律強制：`ScanRun`/`EngineManifest::release_blocker()`（`src-tauri/src/domain.rs:625` 附近）在 `!runnable`、`status != Integrated`、或 runnable 卻仍宣告 blocker 時回傳 `Some`，dispatch 直接被拒。

| 檔案 | 內容 |
| --- | --- |
| `engines/catalog.json` | garak 一筆。`category: ai_model_endpoint`、`distribution_mode: build_from_pinned_source`、`image: null`、`engine_version: 0.17.0`、`source_revision: 93aa9cdec309ec4170559676f1826ea2a679920c`、`adapter_version: 0.1.4`（**必須等於 `adapters/mod.rs` 的 `ADAPTER_VERSION` 常數**）、`license_spdx: Apache-2.0`、`status: experimental`、`default_enabled: false`、`required_permissions: ["active_external_testing"]`、`supported_asset_kinds: ["ai_model_endpoint"]` |
| `engines/images/garak/plan.json` | 一份「**沒有打包**」的紀錄：`publish_state: managed_artifact_not_published`、`final_artifact.tag/digest = null`、`dockerfile.emitted: false`、三條 `blockers` |
| `engines/upstreams.lock.json` | 63 筆；garak 手工插在 `DefectDojo/django-DefectDojo` 與 `OpenSCAP/openscap` 之間 |
| `engines/compatibility.schema.json` | `supported_asset_kinds.items.enum` 與 `category.enum` 各加 `ai_model_endpoint` |
| `src-tauri/src/domain.rs` | `AssetKind::AiModelEndpoint`、`EngineCategory::AiModelEndpoint`、`FindingFamily::ModelBehavior`、`SeverityBasisCode::AdversarialProbeFailureRate` |
| `src-tauri/src/registry.rs` | `KNOWN_ENGINE_IDS: [&str; 24]`，包含 `"garak"`、`"agentic-radar"`、`"mcp-armor"` |
| `src-tauri/src/adapters/mod.rs` | `Profile::Garak` + `extract_garak()` 與五個輔助函式；`ADAPTER_VERSION = "0.1.4"`（第 28 行） |
| `src-tauri/src/finding_narrative.rs` | `ModelBehavior` 的四句話、`AdversarialProbeFailureRate` 的中英 basis、`ALL_SEVERITY_BASIS_CODES: [_; 10]`、`"AI security engineer" => "AI 安全工程師"` |
| `src/types.ts` / `src/findingNarrative.ts` | 上面兩者的 TypeScript 孿生（parity 測試綁定） |
| `src/engineWarningPresentation.ts` | 四條 garak 警告的繁中呈現 |
| `mappings/control-mappings.json` | garak 11 筆 entry、3 個新控制項；`mapping_version: 2026-09-13.1`、`reviewed_at: 2026-09-13`、`canonical_sha256: 12dd26a5fc4a627c85ca30f1c78184dfd51ed5e5f925eea961b97447b3628906` |
| `mappings/README.md` | 新增第四個 reviewed prefix family（garak probe namespace）的說明與理由 |
| `src-tauri/tests/fixtures/adapters/garak.jsonl` | 14 列，key 集合照抄上游 `tests/_assets/report/report_test.report.jsonl` @ `93aa9cd` |
| `src-tauri/tests/adapter_fixtures.rs` | 105 tests，含三個 garak 專屬測試 |

### 2.2 garak：**還沒做**的部分（catalog 自己列出的三條 blocker）

`engines/catalog.json` 的 `compatibility.blocked_by` 就是待辦清單，逐字如下：

1. `no packaged image: the pinned source has never been built, tested, or published for this product`
2. `no scope-grant path exists for an AI model endpoint, so no run could be authorized against one`
3. `no credential path exists for a model endpoint that requires a key`

其中 **(1) 屬於 packaging／publication，依 owner authority 規則不可自行開始**（見 §4）。(2)(3) 是產品內部的授權與憑證路徑，那是真正的下一大塊，但不是「下一小步」。

### 2.3 其他掛著的事

| 項目 | 狀態 | 位置 |
| --- | --- | --- |
| Step 2 Agentic Radar | **已完成**（`7a07d65` 收斂）；experimental、不可派送，三項 blocker 不動 | `docs/research/agentic-radar-evaluation.md` |
| Step 3 MCP Armor | 已在 `5e01895` 收斂；experimental、不可派送 | `docs/research/mcp-armor-evaluation.md` |
| Step 4 Augustus | 14-rule 純資料 preflight ladder 已在 `89091fa` 完成收斂稽核；沒有派送路徑 | `docs/research/augustus-evaluation.md` |
| 報告 header／footer 美化 | Ted 排隊中的需求（原話：「header footer 還可以做得更漂亮一點」） | `src-tauri/src/case_service.rs` 的 HTML 報告產生器 |
| 資產看板 Severity mix 空白格 | **下一條可開軸線；尚未開始** | `html_asset_severity_strip`（`case_service.rs:15172`）在 `counts.is_empty()` 時回 `String::new()`，於是「確實是 0」和「根本沒量到」印出同一個空白 |
| `npm run validate:aidefend` 紅燈 | **HEAD 上就是紅的**，不是這輪改壞的 | 見 §4.4 |

---

## 3. 下一條可開軸線（尚未開始）

**資產看板 Severity mix 的空白狀態誠實性。** `html_asset_severity_strip` 在
`counts.is_empty()` 時回傳空字串，讓「已量測且問題數為 0」與「沒有足夠資料可量測」都
呈現空白。這會直接影響新手理解結果，且獨立於 Agentic Radar 的三項 blocker。

下一個任務若由 Ted 開始，最小範圍是先釘死這兩種資料狀態的呈現契約與報告 fixture，
再修正該 helper；不要順手做 header／footer 重設計。**本次交接更新沒有開始這條軸線。**

Agentic Radar 的 packaged image、typed framework-selection path、上游 PR／release 仍是明確
排除項目，不是下一步。

---

## 4. 已知坑、不要重做的事、站立約束

### 4.1 站立約束（Ted 的原話，一律遵守）

- **`main 未推送先不要 push`。** 目前 13 個未推送 commit。
- **`不要對外掃描、不要要憑證、不要擅自推 image`。** 整條 garak 線沒有跑過任何真實掃描、沒有接觸任何外部端點；唯一的網路動作是 GitHub 唯讀存取（`git ls-remote` 查 tag、`curl` 上游已 checked-in 的 fixture、`--depth 1` clone 到 gitignore 的 `.upstreams/`）。
- **`不要擅自遠端破壞性操作`** / `勿擅自對遠端做破壞性操作`。
- **`不要開 SSO／正式環境`**。
- **兩件事需要 Ted 明確點頭才可以動**：把 engine image 推到 `ghcr.io`（對外發佈），以及任何對真實 LLM endpoint 的實際掃描。
- **完成一小步就停**，跑完 gates、回報測試數字，用繁體中文簡述。
- **不要開大重構、不要開新大軸。**
- **不要為綠燈放寬契約。**
- gates 已綠就別重跑整包；但**改到報告輸出就值得跑完整包 cargo**。
- Ted 說過 `你可以自己研究沒關係 不用找 codex , codex 不太有額度了`——這句是對前一位 Claude 說的；你現在就是 Codex，直接自己做。

### 4.2 已經定案、**不要重新討論**的決定

| 決定 | 理由 |
| --- | --- |
| garak 的 finding **不發明 severity** | 一律 `Severity::Unknown` + 新的 `SeverityBasisCode::AdversarialProbeFailureRate`，沿用 `UnratedVulnerabilityTestAlarm` 的先例。garak 只發佈失敗次數，單一 probe 失敗本身不是一個有評級的弱點；排序交給產品層的 prioritization |
| garak 的 `source_rule` = `probe/detector`（garak 自己的階層 id） | 保留上游識別碼 |
| `fails == 0` 不收成 finding | 那是覆蓋率，不是問題。把「什麼都沒找到的 probe」和「每次都失敗的 probe」放同一個清單，正好抹掉讀者要看的那個差別 |
| evidence 帶完整計數（`fails` / `total_evaluated` / `nones` / `total_processed`） | 3/40 和 5/5 的失敗次數不同意義；只給分子是誤導的那一半 |
| **絕不讀 garak 的 `outputs`（目標的回覆）** | prompt 是 garak 自己的測試輸入，可以帶；回覆是目標的內容，`ScannerFindingDetails.description` 明確排除。fixture 每一列 attempt 都塞了 `FIXTURE MODEL REPLY:` 標記，有測試斷言它不出現在正規化輸出裡 |
| prompt 摘錄**不挑「失敗的那一次」** | 判定哪幾次算失敗是 garak 自己的 threshold scoring；在 wrapper 裡重推一遍就是產品在做偵測，違反 `do not rebuild detection logic in wrappers` |
| 新增 `FindingFamily::ModelBehavior` 而不是重用 `NetworkExposure` | 後者的 remedy 是「記錄為何這個服務必須可達，或移除／限制曝露」——對一個照著 jailbreak 回答的模型，那是把讀者送到錯的地方 |
| **不使用 garak 自己的 `owasp:llmXX` 標籤** | 那是 OWASP LLM Top 10 **v1（2023）** 編號（該版 LLM06 是敏感資訊外洩、LLM10 是模型竊取；上游 `FAQ.md:139` 明講 v1），目錄裡是 2025 版座標。把 v1 翻成 2025 就是產品在猜控制項。而且 `dan` 模組**根本沒有任何 owasp 標籤**，fixture 的兩個探測項目都在裡面 |
| garak 的 mapping 用 **probe namespace prefix**，不是 exact `probe/detector` | OWASP 類別屬於探測項目執行的攻擊，不屬於評分的偵測器；而且探測項目配哪個偵測器是 garak 執行期的外掛決定，列舉它就是在猜。整個模組寫 `dan.`，單一探測類別寫 `divergence.Repeat/`。**兩個結尾符號都是關鍵**：少了 `/`，`divergence.Repeat` 會吃掉 `divergence.RepeatedToken` |
| 模組層級的 mapping entry **只寫在上游 docstring 有規定收錄範圍的模組** | 例如 `dan` 的 "Only probes implementing a DAN attack or similar long-form instruction-based attack should be added here"。模組內含兩種以上攻擊的逐類別對應 |
| lmrc／realtoxicityprompts／topic 等內容安全探測**維持未對應** | `mappings/README.md`：unknown rules remain unmapped，產品不從標題、severity 或目標可控文字猜控制項 |
| agentic-radar 收成 **`observations`，不是 findings** | 它那 11 條「漏洞」是按 tool 類別掛上去的通用警語，沒有 rule ID、沒有 severity、沒有 per-finding 證據。`AdapterOutput::observations` 的註解本身就寫著「deliberately separate from findings because inventory alone is not evidence of a vulnerability」 |
| **TriShieldRAG 不納入** | 它是防禦不是掃描器（沒有 findings 可正規化）；GitHub 判定 `NOASSERTION`（README 說 MIT 但沒有可辨識的 LICENSE 檔，過不了 `license_spdx`）；7 個 commit、2 star、IIT Jodhpur CSL6010 課程作業。對客戶的 RAG index 重現 KB 投毒是對知識庫的破壞性寫入，正是本產品不做的 destructive check |
| **0din-ai/ai-scanner 不當 engine 收** | 它不是 scanner，是 Rails + Postgres + Docker Compose 的 web 應用，偵測引擎就是 garak。它的排程／目標管理／報告／SIEM 匯出正好是本產品自己擁有的那幾層。要收的 upstream 是 **garak 本身** |
| **不要「用 AI 做 tool calling」決定掃什麼** | 那會把 LLM 放進「掃什麼」的決策路徑上，牴觸產品邊界（LLM 不能發明授權或擴大目標）。真要做，它必須坐在 scope grant **之下**，永遠不在之上 |

### 4.3 **已經被撤回、不要重做**

**「AI 框架缺少 AI 偵測器」的免責句已被 Ted 否決並 `git reset` 移除。**

原本的 Step 0（commit `8fdcd3e`，2026-09-12 22:44 提交，22:52 `reset --hard HEAD~1` 移除，**現在不在任何 ref 上**）在 AIDEFEND 與 OWASP LLM 兩個框架區塊加了一句：

> No engine in this build tests a model endpoint, an agent framework, an MCP server, or a retrieval pipeline...

Ted 的判斷：「有沒有掃什麼幹嘛特別講？我覺得這是多餘的」。成立的理由有三條：

1. 照那個邏輯每個框架都要來一句。NIST CSF 這輪對到 8 個 subcategory，難道要寫「本版本沒有引擎會測實體安全、治理、供應鏈合約」？七個框架每個都有沒被觸及的部分，那是常態不是新聞。只給 AI 那兩個加註，反而是把它們當特例。
2. 區塊上面那段本來就講完了：座標是 **navigation aids**、**not a compliance result**，已對七個框架一次說清楚。
3. `AGENTS.md` 自己那條：`Do not ship … defensive caveat walls, implementation-defect or test-harness explanations`。把功能缺口寫進使用者的安全報告裡，正是那條在禁止的東西。

**「我們不掃模型」的正確解法是去掃模型，不是寫一句話說我們不掃。** 那就是 Step 1～4。

其他這輪查過、確認不是問題、**不要重開**的：ids／duplicate-ids／`<th scope>`／aria refs／captions；`lang` 屬性；redacted PDF 的水平溢出；中文報告裡的英文字串（那是上游偵測器輸出，`AGENTS.md` 規定要保留）。

### 4.4 已知的坑（踩過，會再踩）

| 坑 | 症狀與正解 |
| --- | --- |
| **`node scripts/lock-upstreams.mjs` 會污染 lock** | 它從本機 `.upstreams/` 重建整份 lock，會把未追蹤的研究 checkout（Armur-Ai/vibescan、edward-playground/aidefense-framework、約 60 個 qemu 子目錄）全部收進去，產生 504 行 diff。**手工插入 lock entry**，照 JS 預設排序（大寫在小寫前） |
| **不要用 `json.dumps` 重寫 `engines/catalog.json`** | 會把既有的 inline `input_contracts` 物件展開。用文字 splice 插入 entry。（`mappings/control-mappings.json` 相反，實測 `json.dumps(indent=2, ensure_ascii=False)+"\n"` **byte-identical** round-trip，可以放心程式化編輯） |
| **cargo 總數會被截斷** | 裸的 `cargo test \| grep \| paste \| bc` 曾經吐出 1189（實際 1619）。**一定要先 `tee` 到檔案再從檔案數** |
| **`adapter_version` 是模組級常數** | `BuiltinAdapter::adapter_version()` 回傳 `adapters/mod.rs` 的 `ADAPTER_VERSION`，不是 per-engine。catalog 的 `adapter_version` 與 `provenance.adapter.version` 必須跟著它 |
| **catalog 的 `category` 同時存在於 JSON schema 和 Rust enum** | 只加 JSON schema 會得到 `catalog_entry_invalid: unknown variant 'ai_model_endpoint'`。`EngineCategory` 也要加。診斷方式：寫一個丟棄式測試印 `registry.admission_issues()` |
| **加 catalog entry 就必須同時加 adapter** | 測試斷言 `adapter_ids == catalog_ids`，兩者分不開 |
| **`json_rows` 對單行檔案回傳 pointer `/`** | 單一 JSON 物件會被解析成 *document* 不是 JSONL。曾經寫了 `matches!(parsed, ParsedArtifact::JsonLines(_))` 守衛，結果把「每支探測都通過」的乾淨 garak 結果判成 malformed。nuclei／trufflehog 都沒有這種守衛；正解是內容檢查（零筆 `eval` 列 → 警告） |
| **英文警告呈現有 census 禁字** | 禁 `retained\|preserved\|adapter\|pinned\|reporter`。`directEngineWarningEnglish` 的收摺規則只認 `JSONL output` 或 `JSON reporter`，所以新警告要用 Nuclei 的既有措辭結尾（`the supported pinned JSONL output`）才會被收成 `; result excluded` |
| **`$AI_SCANNER_REPORT_DUMP_DIR` 必須是絕對路徑**，且先 `rm -rf` | 它會寫出 `report-{en,zh}.html`、`report-standard-redacted-{en,zh}.html`、`report.json`、`beginner-report.json`、`framework.json` 與 `every-detector/` |
| **Python heredoc 遇到 Rust `\u{...}`** | 用 `r'''...'''`，否則 `SyntaxError: (unicode error) 'unicodeescape' codec can't decode` |
| **`mappings/control-mappings.schema.json` 與目錄脫節（既有缺陷）** | schema 還要求 `aidefend_applicability`，目錄用的是 `applicability`；schema 也不認得 `cwe_derived_controls`。因此 **`npm run validate:aidefend`（CI `.github/workflows/ci.yml:141` 有跑）在 HEAD 上就是 exit 1**，已用 stash 對照確認訊息一模一樣。修它是欄位改名的獨立決定，需要 Ted 指示 |
| **`reportEnumParity` 的 PAIRS 不涵蓋全部 enum** | 只涵蓋 `CoverageGapKind`、`NextActionCode`、`CoverageDimensionStatus`、`BeginnerReportSummary`、`ReportScanStage`、`DataAvailability`、`FindingFamily`。**`AssetKind` 和 `SeverityBasisCode` 不在裡面**，改它們不會被這個測試擋 |
| **Bash 的工作目錄每次呼叫都會重設** | 用絕對路徑，或每個指令開頭先 `cd` |

### 4.5 產品偏好與硬邊界

以下每一條都在 [AGENTS.md](../AGENTS.md) 裡，這裡只挑最容易被違反的：

- **有意義的掃描 = 真正的安全／弱點／秘密／相依／設定／曝露檢查。** 程序結束、setup 檢查、單一 TCP 連線都不算。盤點與服務探索是「為內部目標準備一項適用的檢查」，本身不是弱點結果，也不是成功的掃描成果。
- **保留上游偵測器行為、識別碼、severity、證據與修補建議。** Adapter 只做：翻譯型別化輸入、強制範圍與資源邊界、呼叫上游、正規化輸出。**不得在 wrapper 裡重建偵測邏輯。**
- **產品自有的排序、去重、白話解釋、跨引擎關聯與報告呈現，放在共用報告層。**
- **主要路徑要精簡、以行動為導向。** 不出 live／interim 報告、不出防禦性免責牆、不出實作缺陷或測試框架的說明、不出把產品責任轉嫁給使用者的文字。進行中的工作留在 Progress；終態 Results 只帶精簡結果，正式術語放報告尾端或頁尾，技術證據放收摺細節。
- **不要自行發起或擴大** 版本分類、發布資格、打包、簽章、發佈或合規工作，除非 Ted 在當前任務中明確要求。既有的 release 紀錄是歷史脈絡，不是待辦清單。
- **絕不發明授權、擴大掃描目標、透過聊天或命令列參數處理憑證、執行破壞性檢查，或隱藏不完整的涵蓋範圍。**

#### 拒絕不完整的 export（這條特別容易踩）

兩個獨立但都是 fail-closed 的機制，**不要為了讓輸出「看起來完整」而放寬任何一個**：

1. **非零 exit 是證據的終點。** 引擎容器只要 `exit_code != Some(0)`，就**永遠**不會產生 findings，即使它已經寫出一份合法的結果文件（`orchestrator.rs:751` 呼叫 `report.fail(...)` 後直接 return，不走 `adapt_captured`；`ExecutionStage::Failed` 對應 `ResumeAction::Reexecute` 而不是 `AdaptCapturedArtifacts`，所以 resume 也拒絕）。**這是刻意的信任邊界，不是疏漏。** 不要把「非零 exit 但有 artifact」改道到 `CapturedAwaitingAdapter`——那會一次弱化 20+ 個引擎的邊界。
   正確的 wrapper 形狀是分清楚兩件事：*「我跑不起來、或我不信任自己的執行」*（exit 非零，正確地終結）與 *「我跑完了，但有 N 個控制項沒被評估」*（exit 0，把 shortfall 記在文件裡）。`unevaluated_controls`（`adapters/mod.rs`）會再把 shortfall 拆成「設計上略過」（只揭露）與「無法評估」（同時清掉 `AdapterOutput::complete`）。
   **`complete` 是關於涵蓋範圍，不是關於丟棄結果**——`orchestrator.rs:879` 在讀它之前就已指派 findings，所以清掉 `complete` 得到的是帶著真實 findings 的 `PartiallyCompleted`，而不是資料遺失。搞反了不是丟 findings 就是宣稱乾淨掃描。

2. **Export 的敏感資料述詞。** 整份 export 內容取決於 `src-tauri/src/export.rs` 的一行：

   ```rust
   let include = include_raw_artifacts
       && !(redaction == RedactionProfile::Standard && artifact.contains_sensitive_data);
   ```

   兩個分支都反直覺：桌面 App 擷取的**每一份** artifact 都是敏感的（`artifact_store.rs` 的 `finalize_capture` 寫死 `contains_sensitive_data: true`），所以在預設的 standard redaction 下**不會附上任何 artifact**；而關掉 redaction 則會**逐字附上全部**（gitleaks／trufflehog 的原始輸出裡就有真的密鑰——adapter 特地把密鑰值擋在衍生 finding 之外，正因為原始檔裡還在）。任何動到 redaction、artifact 擷取或 export 開關的改動，都要重新對照這個述詞與 `tests/component/exportSharingConsequence.test.tsx`（它釘死了兩個開關產生的三種狀態）。

   Redacted export 的呈現原則是**扣住、不是抹除**：讀者仍要知道「有結果存在、但識別碼被扣住」（`export.rs:5397` 的註解），而「未提供」與「已扣住」是兩件不同的事（`export.rs:5128`）。

---

## 5. 常用指令

### 一次跑完所有 gate

```sh
cd /home/ted-h/projects/ai-security-scanner
export PATH="$HOME/.cargo/bin:$PATH"

# Rust（一定要 tee 到檔案再數，直接 pipe 會被截斷）
cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli 2>&1 | tee /tmp/c.log
grep -oP '^test result: ok\. \K\d+' /tmp/c.log | paste -sd+ | bc      # 應為 1622

cargo clippy --manifest-path src-tauri/Cargo.toml --no-default-features --features cli --all-targets -- -D warnings
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check

# 前端
npm run typecheck            # tsc -b
npm run test:frontend        # 601
npm run test:component       # 262（18 files）
node --test tests/ci/*.test.mjs   # 35
npm run validate:engines     # 8
```

**沒有 `npm run lint`。** Rust gate 一律用 `--no-default-features --features cli`（CI 的 "Rust core and CLI" lane）；預設的 `desktop` feature 需要這台機器沒有的 GTK／webkit 開發函式庫。

### 只跑單一目標／單一測試

```sh
cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli --test adapter_fixtures
cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli --lib control_mapping
cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli --test adapter_fixtures garak_maps
```

### 產生報告並量頁數（改到報告版面時必做）

```sh
rm -rf /tmp/reportdump && mkdir -p /tmp/reportdump
AI_SCANNER_REPORT_DUMP_DIR=/tmp/reportdump \
  cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --features cli --test all_engine_report_audit

CHROME=/home/ted-h/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
for f in report-en report-zh report-standard-redacted-en report-standard-redacted-zh; do
  $CHROME --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
    --print-to-pdf=/tmp/reportdump/$f.pdf /tmp/reportdump/$f.html 2>/dev/null
  echo "$f: $(pdfinfo /tmp/reportdump/$f.pdf | awk '/^Pages/{print $2}') pages"
done
```

可用工具：`pdfinfo`、`pdftotext`、`pdftotext -bbox`、`pdftoppm`。A4 寬 595.28pt、邊界 15mm（42.52pt）→ 內容框右緣 552.76pt。

### 重算 mapping catalog 的 canonical digest

改過 `mappings/control-mappings.json` 之後必做（已驗證與 Rust 的 `canonical_catalog_sha256` 一致）：

```sh
python3 - <<'PY'
import json, hashlib, collections
p='mappings/control-mappings.json'
raw=open(p,encoding='utf-8').read()
o=json.loads(raw, object_pairs_hook=collections.OrderedDict)
tmp=json.loads(raw); del tmp['provenance']['canonical_sha256']
d=hashlib.sha256(json.dumps(tmp, sort_keys=True, separators=(',',':'),
                            ensure_ascii=False).encode('utf-8')).hexdigest()
o['provenance']['canonical_sha256']=d
open(p,'w',encoding='utf-8').write(json.dumps(o, indent=2, ensure_ascii=False)+"\n")
print(d)
PY
```

改完還要同步硬編碼的版本與 digest：`src-tauri/src/adapters/control_mapping.rs`（`ENGINES` 常數、`embedded_catalog_is_bounded…`、`exact_and_standardized_prefix_rules…`）、`src-tauri/tests/adapter_fixtures.rs`、`src-tauri/tests/local_case_lifecycle.rs`、`tests/frontend/controlMappingRationalePresentation.test.ts`（那支釘死了完整的 coordinate 清單），以及中文對照 `src-tauri/src/finding_narrative.rs` ↔ `src/findingNarrative.ts`（parity 測試綁定）。

`mappings/README.md` 的 6 步變更程序是規範，逐條照做。

### 沙箱注意事項（如果你在 `workspace-write` 下跑）

- **沙箱沒有網路**：每個 cargo 指令都要 `--offline`，而且要先在外面暖 cache：
  ```sh
  PATH="$HOME/.cargo/bin:$PATH" cargo test --locked --offline --workspace \
    --no-default-features --features cli --no-run
  ```
- **Docker 在沙箱裡連不到**：Go launcher 測試要在沙箱外用釘死的 `golang` 容器跑。
- 若有子代理：共用同一個工作樹，不要重疊編輯，**只有協調者跑 cargo／npm**（平行 cargo 會搶 `target/`）。

---

## 6. 上游 repo 座標

### 已釘住並落地的（本輪）

| repo | pin | license | 本機 checkout |
| --- | --- | --- | --- |
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | `93aa9cdec309ec4170559676f1826ea2a679920c`（v0.17.0） | Apache-2.0 | `.upstreams/NVIDIA/garak`（shallow，gitignore） |

探測項目在 `garak/probes/`：189 個 class、122 個 active、49 個自帶 owasp 標籤（**v1 編號，不可直接當 2025 座標用**）。

### AI 引擎擴充 program 的五個候選（上一輪實測數字）

| repo | license | 最後 commit | Star | 機器可讀輸出 | 判定 |
| --- | --- | --- | --- | --- | --- |
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | Apache-2.0 | 2026-09-09 | 9218 | JSONL report + hitlog ✅ | **Step 1 已完成** |
| [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar) | Apache-2.0 | 2025-11-27 | 1051 | 上游 graph JSON + 本機 versioned envelope fixture | **Step 2 已完成（`7a07d65`）** |
| [aira-security/mcp-armor](https://github.com/aira-security/mcp-armor) | Apache-2.0 | 2026-03-27 | 123 | JSON ✅（`--report-type {json,md}`） | **Step 3 已收斂（`5e01895`）** |
| [praetorian-inc/augustus](https://github.com/praetorian-inc/augustus) | Apache-2.0 | 2026-09-08 | 288 | JSON / JSONL ✅ | **Step 4 純資料 ladder 已收斂（`89091fa`）** |
| [SPriTLab-iitj/TriShieldRAG](https://github.com/SPriTLab-iitj/TriShieldRAG) | **NOASSERTION** | 2026-08-31 | 2（7 commits） | 無 findings | **不納入**（§4.2） |
| [0din-ai/ai-scanner](https://github.com/0din-ai/ai-scanner) | — | — | — | 是 web app 不是 scanner | **不當 engine 收**（§4.2） |

**為什麼 garak 排在 Augustus 前面**（順序在中途改過，理由要留著）：garak 有免金鑰的 generator（`ollama.py`、`huggingface.py`、`ggml.py`、`rest.py`、`function.py`、`langchain.py`）。使用者本機已經在跑 Ollama，就把 garak 指過去——**零憑證、零外部 egress、零費用**，完全符合 local-first 的姿態。Augustus 是繞著 28 家 hosted provider 設計的，這條路弱很多。

**mcp-armor 的已知摩擦**：它會從 Hugging Face 下載並執行一個 fine-tuned Llama（`Aira-security/FT-Llama-Prompt-Guard-2`）做注入偵測。代表模型要烘進 pinned image、image 變好幾 GB，而且**模型權重不是 `rule_version`**——它的行為不像規則集那樣可複現，跟本專案的 provenance 模型有真實摩擦。等它有 model-optional 的靜態模式再說。

### 從 0din 的 garak wrapper 學到、已經吸收的四件事

1. **garak 開箱即用會過度回報。** 上游 `StringDetector` 不做正規化，模型用彎引號拒絕（"I can't"）會被判成越獄成功；judge 型偵測器出錯時往「攻擊成功」倒。0din 是用 monkey-patch 修的——**那踩到本專案的紅線**（`do not rebuild detection logic in wrappers`）。本專案的出路是**根本不把單一 probe 失敗宣告成弱點**：帶著 `fails/total_evaluated` 當證據，讓產品層排序，把上游的誤判稀釋成比率誤差而不是假警報。
2. **憑證走檔案 + 保證刪除，絕不進 argv。** 若日後要餵 LLM endpoint 憑證，直接照抄這個形狀。
3. **一份 blocklist 由產品端提供、連線層 fail-closed 強制**，避免產生會漂移的第二份副本——跟本專案用 parity test 守 `findingNarrative.rs` ↔ `.ts` 是同一個原則。這對 `external_scope.rs` 是正面驗證，不是新工作。
4. **部分失敗絕不悄悄縮小覆蓋目錄。** 0din 的原話：抽取有錯就「skip disabling outdated probes to avoid removing valid probes」。

### 其他

`.upstreams/` 的研究 checkout 全部 gitignore、**未追蹤**；`engines/upstreams.lock.json` 有 63 筆被追蹤的研究 pin。兩者刻意不同步，**這就是 `lock-upstreams.mjs` 不能跑的原因**（§4.4）。

---

## 7. 本文與既有交接文件的關係

[`docs/project-handover.zh-TW.md`](project-handover.zh-TW.md)（978 行）仍然是專案全景與歷史的主文件，**但它的基線是 `9f1f570`（2026-09-10 23:35）**，因此以下內容已被本文取代：

- §1「21 個已整合上游工具」→ 現在是 **24 筆目錄、21 個可派送 + 3 個 experimental 不可派送**
- §1「`adapter_fixtures` 共 92 項測試」→ 現在 **105**
- §7「21 個整合工具的真實狀態」→ 需補 garak、Agentic Radar、MCP Armor
- 整條報告設計線（2026-09-11 ～ 09-12 約 60 個 commit）在那份文件裡沒有紀錄，只有 §8.4／§12.3／§16 P1-1 對照過 `d7d2652`

其餘章節（狀態用語、產品方針、系統與資料流、程式碼地圖、runtime 與資料安全、踩過的坑、工作方法、測試與 CI、不要做的事）仍然有效，值得完整讀過一次。

`docs/research/vibescan-evaluation.md` 是 pinned 研究決定的格式範本；Agentic Radar 的已完成決定在 `docs/research/agentic-radar-evaluation.md`。
