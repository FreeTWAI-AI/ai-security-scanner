#!/usr/bin/env node

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { formatRefreshOutcomeLine, refreshEngines } from "./upstream-refresh-lib.mjs";

export const REFRESH_USAGE = `Usage: npm run upstream:refresh -- --engine <id> [options]

Options:
  --engine <id>                    Engine to refresh; repeat for more than one engine.
  --kind {revision,provenance}     Refresh revision metadata or build-input provenance.
  --provider {mechanical,cli}      Provider path. mechanical is the default deterministic offline path.
  --ai-cli <executable>            With --provider cli, invoke this named AI executable.
  --ai-cli-arg <arg>               Pass an argument to the AI executable; repeat as needed.
  -h, --help                       Show this help and exit.

The cli provider is an optional AI path. It runs only when explicitly selected with
--provider cli and invokes the executable named by --ai-cli.
`;

export function parseRefreshArguments(argv) {
  const options = { engineIds: [], providerId: "mechanical", refreshKind: "revision", cliArgs: [], help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") options.help = true;
    else if (argument === "--engine") options.engineIds.push(argv[++index]);
    else if (argument === "--kind") options.refreshKind = argv[++index];
    else if (argument === "--provider") options.providerId = argv[++index];
    else if (argument === "--ai-cli") options.cliCommand = argv[++index];
    else if (argument === "--ai-cli-arg") options.cliArgs.push(argv[++index]);
    else throw new Error(`Unknown argument: ${argument}`);
  }
  if (!options.help && (options.engineIds.length === 0 || options.engineIds.some((id) => !id))) {
    throw new Error("At least one --engine <id> is required.");
  }
  return options;
}

export async function main(argv = process.argv.slice(2), io = console) {
  const options = parseRefreshArguments(argv);
  if (options.help) {
    io.log(REFRESH_USAGE.trimEnd());
    return 0;
  }
  const root = resolve(import.meta.dirname, "..");
  const run = await refreshEngines({ root, ...options });
  for (const result of run.results) {
    if (result.error) {
      io.error(`Refresh failed for ${result.engineId}: ${result.error.message}`);
      continue;
    }
    io.log(`${result.proposal.engine.id}: ${formatRefreshOutcomeLine(result.proposal)}`);
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
