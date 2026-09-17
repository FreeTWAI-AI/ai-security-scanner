#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { evaluateBundleForPr, recordPrDecision, renderProposeResult } from "./upstream-propose-lib.mjs";

export const PROPOSE_USAGE = `Usage: npm run upstream:propose -- --bundle <path> [--open-pr | --no-open-pr]

Options:
  --bundle <path>  Refresh bundle directory or proposal.json path.
  --open-pr        Print local, push, and PR-creation commands.
  --no-open-pr     Print only local commands and record that the change stays local.
  -h, --help       Show this help and exit.

Without a decision flag, the PR decision remains undecided and only local commands are printed.
No command is executed.
`;

export function parseProposeArguments(argv) {
  const options = { bundlePath: null, decision: "undecided", help: false };
  let openPr = false;
  let noOpenPr = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") options.help = true;
    else if (argument === "--bundle") options.bundlePath = argv[++index];
    else if (argument === "--open-pr") openPr = true;
    else if (argument === "--no-open-pr") noOpenPr = true;
    else throw new Error(`Unknown argument: ${argument}`);
  }
  if (openPr && noOpenPr) throw new Error("Choose either --open-pr or --no-open-pr, not both.");
  if (!options.help && !options.bundlePath) throw new Error("Usage: npm run upstream:propose -- --bundle <path> [--open-pr | --no-open-pr]");
  options.decision = openPr ? "open" : noOpenPr ? "keep-local" : "undecided";
  return options;
}

export function main(argv = process.argv.slice(2), io = process.stdout) {
  const options = parseProposeArguments(argv);
  if (options.help) {
    io.write(PROPOSE_USAGE);
    return 0;
  }
  const result = evaluateBundleForPr(options);
  let output = renderProposeResult(result);
  if (options.decision !== "undecided") {
    try {
      output += `PR decision record: ${recordPrDecision(result)}\n`;
    } catch (error) {
      output += `PR decision record: not written — ${error.message}\n`;
    }
  }
  io.write(output);
  return result.eligible ? 0 : 1;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    process.exitCode = main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
