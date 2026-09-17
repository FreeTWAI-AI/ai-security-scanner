#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { evaluateBundleForPr, renderProposeResult } from "./upstream-propose-lib.mjs";

export function parseProposeArguments(argv) {
  if (argv.length !== 2 || argv[0] !== "--bundle" || !argv[1]) {
    throw new Error("Usage: npm run upstream:propose -- --bundle <path>");
  }
  return { bundlePath: argv[1] };
}

export function main(argv = process.argv.slice(2), io = process.stdout) {
  const result = evaluateBundleForPr(parseProposeArguments(argv));
  io.write(renderProposeResult(result));
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
