#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const defaultRoot = resolve(import.meta.dirname, "..");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function nulFields(bytes) {
  const fields = bytes.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  return fields;
}

function chunks(values, size = 100) {
  const result = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}

export function validateEngineLineEndings({
  root = defaultRoot,
  gitRunner = (args, options = {}) => {
    const result = spawnSync("git", ["-C", root, ...args], {
      encoding: null,
      maxBuffer: 32 * 1024 * 1024,
      timeout: 180_000,
      ...options,
    });
    if (result.status !== 0) {
      throw new Error(result.error?.message ?? (result.stderr?.toString("utf8").trim() || `git exited ${result.status}`));
    }
    return result.stdout;
  },
} = {}) {
  const git = (args, options = {}) => gitRunner(args, options);
  const temporaryRoot = mkdtempSync(join(tmpdir(), "ai-security-scanner-engine-eol-"));
  let trackedPathCount = 0;
  try {
    const checkoutRoot = join(temporaryRoot, "checkout");
    const canonicalRoot = join(temporaryRoot, "canonical");
    const temporaryIndex = join(temporaryRoot, "index");
    const temporaryObjects = join(temporaryRoot, "objects");
    mkdirSync(checkoutRoot);
    mkdirSync(canonicalRoot);
    mkdirSync(temporaryObjects);
    const repositoryObjects = git(["rev-parse", "--git-path", "objects"]).toString("utf8").trim();
    const indexEnvironment = {
      ...process.env,
      GIT_INDEX_FILE: temporaryIndex,
      GIT_OBJECT_DIRECTORY: temporaryObjects,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: resolve(root, repositoryObjects),
    };

  // Snapshot the current worktree into a private index. This makes local
  // validation cover modified, staged, and newly added engine inputs without
  // changing the user's real index. Reading only HEAD here would falsely pass
  // precisely the launcher/Dockerfile edits the check is meant to qualify.
    git(["read-tree", "HEAD"], { env: indexEnvironment });
    git(["add", "--all", "--", "engines"], { env: indexEnvironment });
    const trackedPaths = nulFields(git(
      ["ls-files", "-z", "--", "engines"],
      { env: indexEnvironment },
    ));
    trackedPathCount = trackedPaths.length;
    if (trackedPaths.length === 0) {
      throw new Error("engine line-ending validation found no tracked engine inputs");
    }
    if (trackedPaths.some((path) => !path.startsWith("engines/") || path.includes("\0"))) {
      throw new Error("engine line-ending validation received an unsafe tracked path");
    }

    const pathChunks = chunks(trackedPaths);
    const attributeFields = nulFields(Buffer.concat(pathChunks.map((paths) => git(
      ["check-attr", "-z", "text", "eol", "--", ...paths],
    ))));
    const attributeErrors = [];
    for (let index = 0; index < attributeFields.length; index += 3) {
      const path = attributeFields[index];
      const attribute = attributeFields[index + 1];
      const value = attributeFields[index + 2];
      if (attribute === "text" && value !== "auto") {
        attributeErrors.push(`${path}: text must be auto, observed ${value}`);
      }
      if (attribute === "eol" && value !== "lf") {
        attributeErrors.push(`${path}: eol must be lf, observed ${value}`);
      }
    }
    if (attributeFields.length !== trackedPaths.length * 6) {
      attributeErrors.push("git check-attr did not return both text and eol for every tracked engine input");
    }
    if (attributeErrors.length > 0) {
      throw new Error(`engine line-ending attributes are incomplete:\n${attributeErrors.join("\n")}`);
    }

    const checkoutPrefix = `${checkoutRoot.split(sep).join("/")}/`;
    for (const paths of pathChunks) {
      git(
        [
          "-c",
          "core.autocrlf=true",
          "checkout-index",
          `--prefix=${checkoutPrefix}`,
          "--",
          ...paths,
        ],
        { env: indexEnvironment },
      );
    }

    const canonicalPrefix = `${canonicalRoot.split(sep).join("/")}/`;
    for (const paths of pathChunks) {
      git(
        [
          "-c",
          "core.autocrlf=false",
          "checkout-index",
          `--prefix=${canonicalPrefix}`,
          "--",
          ...paths,
        ],
        { env: indexEnvironment },
      );
    }

    const mismatches = [];
    for (const path of trackedPaths) {
      const canonicalBlob = readFileSync(join(canonicalRoot, ...path.split("/")));
      const checkedOut = readFileSync(join(checkoutRoot, ...path.split("/")));
      if (!canonicalBlob.equals(checkedOut)) {
        mismatches.push(
          `${path}: Git blob ${sha256(canonicalBlob)} != autocrlf checkout ${sha256(checkedOut)}`,
        );
      }
    }
    if (mismatches.length > 0) {
      throw new Error(
        `engine inputs are not byte-stable under core.autocrlf=true:\n${mismatches.join("\n")}`,
      );
    }
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
  return { trackedPathCount };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const { trackedPathCount } = validateEngineLineEndings();
  console.log(
    `Verified ${trackedPathCount} current engine inputs are byte-stable in a core.autocrlf=true checkout.`,
  );
}
