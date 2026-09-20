# Getting started

[繁體中文](getting-started.zh-TW.md) · [Documentation](README.md)

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

The agent can inspect runtime readiness, guide target selection, run the applicable checks through the product, and explain/export the final report. You select the local folder and confirm any network targets; the skill does not supply authorization for you. Active work stays in Progress, and Results/Export use a terminal run.

The current Grype image pin is `0.117.0-4` (`sha256:56b0d675…`), with local repository vulnerability results recorded. See [the exact pin and result](engine-catalog.md#grype-repository-support).

## Choose the first scan

### IT environment

Use this path when repositories, websites, and internal systems belong in one assessment.

1. Add one or more project folders.
2. Add complete `http://` or `https://` website URLs.
3. Add each approved internal system by exact hostname or IP address. The default profile checks ports 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced settings can replace this list with up to 64 exact ports.
4. Review every asset and network boundary.
5. Confirm the displayed network targets and select **Start scan**.

Each scanner receives only its assigned assets. All completed outcomes are combined in one report.

### Website

1. Select **Check a website**.
2. Enter one complete URL.
3. Review the exact origin and select **Start scan**.

This profile covers the displayed `scheme://host:port` origin. See [Scanning scope](scanning-scope.md#website-or-api) for its request behavior.

### Project folder

1. Select **Check a project folder**.
2. Choose the local folder.
3. Review the snapshot boundary and select **Start scan**.

The app scans a bounded read-only snapshot. The original folder is not changed.

## Follow progress

Progress shows the current asset and check, confirmed problem count, completed work, remaining work, elapsed time, and available controls. Tool preparation appears in the same view and continues into the reviewed scan when ready.

**View results** opens when the run reaches a terminal outcome.

## Act on the result

Start with **Problems found** and the highest-priority item. Each priority includes the affected asset, impact, next action, and verification guidance. Check the asset summary for incomplete or untested work, then save the readable HTML report from Export.

The complete report model is described in [Results and exports](results-and-exports.md).

## Continue an assessment

Open **My scans** to reopen a project, review an earlier terminal run, add or remove assets, retry unfinished checks, or compare a later scan with a completed baseline.
