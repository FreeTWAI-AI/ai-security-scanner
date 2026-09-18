import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const load = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("catalog adapter versions match the shared normalization contract", async () => {
  const [adapterSource, catalogText] = await Promise.all([
    load("src-tauri/src/adapters/mod.rs"),
    load("engines/catalog.json"),
  ]);
  const declarations = [
    ...adapterSource.matchAll(
      /pub const ADAPTER_VERSION:\s*&str\s*=\s*"([^"]+)";/gu,
    ),
  ];
  assert.equal(
    declarations.length,
    1,
    "src-tauri/src/adapters/mod.rs must declare exactly one string ADAPTER_VERSION",
  );

  const adapterVersion = declarations[0][1];
  const catalog = JSON.parse(catalogText);
  for (const engine of catalog) {
    assert.equal(
      engine.adapter_version,
      adapterVersion,
      `engine ${engine.id}: adapter_version must equal ADAPTER_VERSION ${adapterVersion}`,
    );
    assert.equal(
      engine.provenance?.adapter?.version,
      adapterVersion,
      `engine ${engine.id}: provenance.adapter.version must equal ADAPTER_VERSION ${adapterVersion}`,
    );
  }
});
