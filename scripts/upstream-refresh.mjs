#!/usr/bin/env node

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { refreshEngines } from "./upstream-refresh-lib.mjs";

export function parseRefreshArguments(argv) {
  const options = { engineIds: [], providerId: "mechanical", cliArgs: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--engine") options.engineIds.push(argv[++index]);
    else if (argument === "--provider") options.providerId = argv[++index];
    else if (argument === "--ai-cli") options.cliCommand = argv[++index];
    else if (argument === "--ai-cli-arg") options.cliArgs.push(argv[++index]);
    else throw new Error(`Unknown argument: ${argument}`);
  }
  if (options.engineIds.length === 0 || options.engineIds.some((id) => !id)) {
    throw new Error("At least one --engine <id> is required.");
  }
  return options;
}

export async function main(argv = process.argv.slice(2), io = console) {
  const options = parseRefreshArguments(argv);
  const root = resolve(import.meta.dirname, "..");
  const run = await refreshEngines({ root, ...options });
  for (const result of run.results) {
    if (result.error) {
      io.error(`Refresh failed for ${result.engineId}: ${result.error.message}`);
      continue;
    }
    io.log(`${result.proposal.engine.id}: ${result.proposal.outcome}`);
    io.log(`Bundle: ${result.bundlePath}`);
    io.log(`PR eligible: ${result.proposal.pr_eligible ? "yes" : "no"}`);
    for (const reason of result.proposal.pr_ineligibility_reasons) io.log(`- ${reason}`);
  }
  return run.exitCode;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    process.exitCode = await main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
