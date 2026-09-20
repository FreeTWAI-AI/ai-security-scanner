# 開始使用

[English](getting-started.md) · [文件](README.zh-TW.md)

## 安裝

目前公開安裝檔**僅提供 Linux**（2026 年 9 月 20 日確認），請從 [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases) 下載。

| 平台 | 建議套件 |
| --- | --- |
| Linux x86-64 | Debian `.deb` |
| Windows | 目前未提供 |
| macOS | 目前未提供 |

安裝完成後啟動 **ai-security-scanner**。選定的檢查需要本機掃描環境時，應用程式會直接準備。

## 透過 Agent Skill 使用

若要使用目前 `main` 的實作，包含 Grype 專案掃描，請從原始碼建置。公開安裝檔仍是較早的版本；從原始碼建置到掃描的路徑已在 Linux 實測。

在 **Claude Code** 或 **Codex** 開啟本儲存庫，使用其中的 `ai-security-scanner` skill：[Claude Code 指引](../.claude/skills/ai-security-scanner/SKILL.md) · [Codex 指引](../.codex/skills/ai-security-scanner/SKILL.md)。兩份內容相同，都透過產品介面提供建置與操作入口。

可以這樣要求 Agent：

> 使用 ai-security-scanner skill 建置這份原始碼，協助我選擇本機專案資料夾、執行適用的安全檢查，並保存最終 HTML 報告。

安裝 Node.js 24 或更新版本、Rust 1.98，以及 Tauri 的 Linux 開發相依套件後，可使用以下建置指令：

```sh
npm ci
cargo build --locked --no-default-features --features cli --bin ai-security-scanner-cli
./target/debug/ai-security-scanner-cli doctor
npm run tauri dev
```

Agent 可檢查執行環境、引導選擇目標、透過產品執行適用檢查，再解讀與匯出最終報告。本機資料夾由你選定，網路目標授權也由你確認，Skill 不會代為授權。掃描中的工作顯示於進度頁面，結果與匯出使用已達終態的掃描。

目前 Grype 映像固定為 `0.117.0-4`（`sha256:56b0d675…`），已有本機專案弱點掃描結果。詳見[完整釘選與實測紀錄](engine-catalog.md#grype-repository-support)。

## 選擇第一次掃描

### IT 環境

需要把程式碼專案、網站與內部系統放進同一次評估時，使用這條路徑。

1. 加入一個或多個專案資料夾。
2. 加入完整的 `http://` 或 `https://` 網站網址。
3. 以精確主機名稱或 IP 位址加入每個已獲准的內部系統。預設檢查 22、23、25、80、443、445、3389、5900、8080 與 8443；進階設定可改為最多 64 個精確連接埠。
4. 確認每個資產與網路界線。
5. 確認畫面列出的網路目標，選擇**開始掃描**。

每個掃描器只會收到分配給它的資產；所有已完成結果會集中在同一份報告。

### 網站

1. 選擇**檢查網站**。
2. 輸入一個完整網址。
3. 確認精確 origin，選擇**開始掃描**。

這個設定涵蓋畫面列出的 `scheme://host:port` origin。請在[掃描範圍](scanning-scope.zh-TW.md#網站或-api)查看請求行為。

### 專案資料夾

1. 選擇**檢查專案資料夾**。
2. 選取本機資料夾。
3. 確認副本界線，選擇**開始掃描**。

應用程式會掃描有界的唯讀副本，不會改動原始資料夾。

## 查看進度

進度頁面會顯示目前資產與檢查、已確認問題數、完成項目、剩餘項目、經過時間與可用控制。工具準備也在同一頁面進行，完成後會接續已確認的掃描。

掃描進入終態時，**查看結果**會直接開啟報告。

## 處理結果

先看**發現問題**與最高優先項目。每個項目包含受影響資產、影響、下一步與驗證方式。接著查看資產摘要中的未完成或未測試項目，最後從匯出頁面保存好讀的 HTML 報告。

完整報告模型請參閱[結果與匯出](results-and-exports.zh-TW.md)。

## 繼續評估

從**我的掃描**重新開啟專案、查看過去終態結果、增減資產、重試未完成檢查，或把後續掃描與已完成基準比較。
