# Getting started

[繁體中文](getting-started.zh-TW.md) · [Documentation](README.md)

## From New scan to an HTML report

For the current source build, follow this path:

**New scan → Scan setup → Start scan → Scan progress → Results → Share results → HTML report**

1. Select **New scan** in the sidebar. Choose **Scan my environment**, **Check a website**, or **Check code or an AI project** for the targets you want to check.
2. Add the targets in the form, then use its review or create button to reach **Scan setup**. For a local project, select **Choose the source-code folder**, choose your folder, then **Create scan with this code**. You can leave the project name blank.
3. In **Scan setup**, review the selected targets, checks and displayed permissions, then select **Start scan**. A first project review uses **Confirm and start scan**; select it after confirming the displayed scope.
4. Follow the work in **Scan progress**. Tool preparation appears here too. Wait until the run finishes or stops; completed checks remain available even when another check could not finish.
5. Select **Results** in the sidebar. If there is more than one saved run, choose the intended scan in **Report run**. Read the affected assets, the highest-priority problems and next actions, and what was not tested.
6. Select **Save or share report** at the top of Results. The breadcrumb changes to **Share results**.
7. Select **HTML report (recommended)**, keep **Hide sensitive identifiers (recommended)** selected, then select **Save HTML report (recommended)**. Choose a filename and location in the save dialog and save the file. Open the saved `.html` file in a browser to read or share the professional report.

**Scan setup**, **Scan progress**, and **Share results** open through these actions; they are not separate sidebar entries. Saving a report writes a local file.

### Return to a scan

Open **My scans** and select your project. For ongoing work, select **View scan progress**. For a finished or stopped run, select **Results** and check **Report run** before saving its report. If checks need another attempt, use **Review scanner status** from Results.

If Scan progress says the plan was saved but no checks started, choose **Continue the original scope** to resume it or **Start a new scan** for a fresh run. **Cancel this run** stops queued or active work when available.

See [Results and exports](results-and-exports.md) for more about the report.

## Install

Public installers are currently **Linux-only** (checked September 20, 2026). Download from [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases).

| Platform | Recommended package |
| --- | --- |
| Linux x86-64 | Debian `.deb` |
| Windows | Not currently offered |
| macOS | Not currently offered |

Launch **ai-security-scanner** after installation. The app prepares its local scanning runtime when the selected checks need it.

## Use with an Agent Skill

For the current `main` implementation, including Grype repository scanning, use a source checkout. The public installer is an earlier build. The source build-to-scan path has been exercised on Linux.

Open the checkout in **Claude Code** or **Codex** and use the repository's `ai-security-scanner` skill: [Claude Code instructions](../.claude/skills/ai-security-scanner/SKILL.md) · [Codex instructions](../.codex/skills/ai-security-scanner/SKILL.md). Both copies provide the same build-and-operate entry point through the product interfaces.

Ask the agent:

> Use the ai-security-scanner skill to build this checkout, help me select a local project folder, run its applicable security checks, and save the final HTML report.

With Node.js 24 or newer, Rust 1.98, and Tauri's Linux development dependencies installed, the source build commands are:

```sh
npm ci
cargo build --locked --no-default-features --features cli --bin ai-security-scanner-cli
./target/debug/ai-security-scanner-cli doctor
npm run tauri dev
```

The agent can inspect runtime readiness, guide target selection, run the applicable checks through the product, and explain/export the final report. You select the local folder and confirm any network targets; the skill does not supply authorization for you. Active work stays in **Scan progress**; **Results** and **Share results** use a finished or stopped run.

The current Grype image pin is `0.117.0-4` (`sha256:56b0d675…`), with local repository vulnerability results recorded. See [the exact pin and result](engine-catalog.md#grype-repository-support).

## Choose the first scan

### IT environment

On **New scan**, select **Scan my environment** when repositories, websites, and internal systems belong in one assessment.

1. Add one or more project folders.
2. Add complete `http://` or `https://` website URLs.
3. Add each approved internal system by exact hostname or IP address. The default profile checks ports 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced settings can replace this list with up to 64 exact ports.
4. Select **Review scan** to open **Scan setup**, then review every asset and network boundary.
5. Confirm the displayed network targets and select **Start scan**.

Each scanner receives only its assigned assets. All completed outcomes are combined in one report.

### Website

1. Select **Check a website**.
2. Enter one complete URL and select **Create scan project**.
3. In **Scan setup**, review the exact origin and select **Confirm and start scan**.

This profile covers the displayed `scheme://host:port` origin. See [Scanning scope](scanning-scope.md#website-or-api) for its request behavior.

### Project folder

1. On **New scan**, select **Check code or an AI project**.
2. Select **Choose the source-code folder** and choose the local folder.
3. Select **Create scan with this code**.
4. In **Scan setup**, review the snapshot boundary and select **Confirm and start scan**.

The app scans a bounded read-only snapshot. The original folder is not changed.

After starting, follow [the steps to an HTML report](#from-new-scan-to-an-html-report).
