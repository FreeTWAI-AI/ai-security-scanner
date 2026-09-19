import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const load = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("the Rust execution classifier stays bound to the local launcher rejection", async () => {
  const [launcherSource, runtimeSource] = await Promise.all([
    load("engines/images/local-launcher/main.go"),
    load("src-tauri/src/container_runtime.rs"),
  ]);

  const launcherMatch = launcherSource.match(
    /fmt\.Errorf\("([^"]*cannot consume local input profile[^"]*)"/u,
  );
  assert.ok(
    launcherMatch,
    "local launcher must retain a cannot-consume-local-input-profile format string",
  );

  const rustMatch = runtimeSource.match(
    /pub const LOCAL_INPUT_PROFILE_REJECTION_MARKER:\s*&str\s*=\s*"([^"]+)";/u,
  );
  assert.ok(
    rustMatch,
    "Rust must declare LOCAL_INPUT_PROFILE_REJECTION_MARKER as a string constant",
  );

  assert.ok(
    launcherMatch[1].includes(rustMatch[1]),
    `local launcher rejection ${JSON.stringify(launcherMatch[1])} must contain Rust marker ${JSON.stringify(rustMatch[1])}`,
  );
});
