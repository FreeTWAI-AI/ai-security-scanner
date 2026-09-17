import assert from "node:assert/strict";
import test from "node:test";

import { promotePublication, publicationPreflight } from "../../scripts/engine-image-evidence.mjs";

const IMAGE = "ghcr.io/teddashh/ai-security-scanner-engine-scubagear";
const TAG = "1.8.0-6";
const REPOSITORY = "teddashh/ai-security-scanner";
const WORKFLOW_REF = `${REPOSITORY}/.github/workflows/engine-images-m365.yml@refs/heads/main`;
const CURRENT_REVISION = "cc".repeat(20);
const PUBLISHED_REVISION = "aa".repeat(20);
const INDEX_DIGEST = `sha256:${"11".repeat(32)}`;

function args() {
  return new Map([
    ["image", IMAGE],
    ["tag", TAG],
    ["source-revision", CURRENT_REVISION],
    ["repository", REPOSITORY],
    ["workflow-ref", WORKFLOW_REF],
    ["username", "fixture-user"],
  ]);
}

function recordedPlan() {
  return {
    schema_version: "1.0.0",
    engine_id: "scubagear",
    final_artifact: {
      repository: IMAGE,
      tag: TAG,
      digest: INDEX_DIGEST,
    },
    build_recipe: {
      source_archive: { sha256: `sha256:${"22".repeat(32)}` },
      base_images: [{
        repository: "mcr.microsoft.com/powershell",
        tag: "7.5.2-ubuntu-24.04",
        digest: `sha256:${"33".repeat(32)}`,
      }],
    },
    dockerfile: {
      path: "engines/images/scubagear/Dockerfile",
      sha256: `sha256:${"44".repeat(32)}`,
    },
    wrapper: { launcher_sha256: `sha256:${"55".repeat(32)}` },
    publication: {
      source_revision: PUBLISHED_REVISION,
      managed_smoke_evidence_sha256: `sha256:${"66".repeat(32)}`,
    },
  };
}

function provenanceOutput() {
  return JSON.stringify([{
    verificationResult: {
      statement: {
        subject: [{ name: IMAGE, digest: { sha256: INDEX_DIGEST.slice("sha256:".length) } }],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {
          buildDefinition: {
            resolvedDependencies: [{
              uri: `git+https://github.com/${REPOSITORY}@refs/heads/main`,
              digest: { gitCommit: PUBLISHED_REVISION },
            }],
          },
        },
      },
      signature: {
        certificate: {
          sourceRepositoryURI: `https://github.com/${REPOSITORY}`,
          sourceRepositoryDigest: PUBLISHED_REVISION,
          githubWorkflowRepository: REPOSITORY,
          githubWorkflowSHA: PUBLISHED_REVISION,
          buildSignerURI: `https://github.com/${WORKFLOW_REF}`,
          buildSignerDigest: PUBLISHED_REVISION,
          runnerEnvironment: "github-hosted",
        },
      },
    },
  }]);
}

async function withPublicationEnvironment(callback) {
  const previous = new Map([
    ["GHCR_TOKEN", process.env.GHCR_TOKEN],
    ["GITHUB_SHA", process.env.GITHUB_SHA],
    ["GITHUB_RUN_ID", process.env.GITHUB_RUN_ID],
    ["GITHUB_RUN_ATTEMPT", process.env.GITHUB_RUN_ATTEMPT],
  ]);
  process.env.GHCR_TOKEN = "fixture-token";
  process.env.GITHUB_SHA = CURRENT_REVISION;
  process.env.GITHUB_RUN_ID = "12345";
  process.env.GITHUB_RUN_ATTEMPT = "2";
  try {
    return await callback();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test("publication guard reuses an existing tag when recorded engine inputs are unchanged", async () => {
  await withPublicationEnvironment(async () => {
    const currentPlan = recordedPlan();
    const publishedPlan = structuredClone(currentPlan);
    publishedPlan.publication.source_revision = PUBLISHED_REVISION;
    const outputs = [];
    const messages = [];
    let provenanceChecks = 0;

    await publicationPreflight(args(), {
      inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
      exec: () => {
        provenanceChecks += 1;
        return provenanceOutput();
      },
      readCurrentPlan: async () => currentPlan,
      readPublishedPlan: async () => publishedPlan,
      appendGithubOutputs: async (entries) => outputs.push(...entries),
      writeStdout: (message) => messages.push(message),
    });

    assert.equal(provenanceChecks, 1, "reuse must verify the existing digest provenance");
    assert.deepEqual(Object.fromEntries(outputs), {
      mode: "reuse",
      should_build: "false",
      digest: INDEX_DIGEST,
      candidate_tag: `candidate-${CURRENT_REVISION}-12345-2`,
    });
    assert.match(messages.join(""), /recorded build inputs are unchanged/u);

    const promotionArgs = args();
    promotionArgs.set("mode", "reuse");
    promotionArgs.set("digest", INDEX_DIGEST);
    const promotionOutputs = [];
    let inputChecks = 0;
    await promotePublication(promotionArgs, {
      inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
      verifyPublishedProvenance: () => PUBLISHED_REVISION,
      verifyRecordedInputsUnchanged: async () => {
        inputChecks += 1;
      },
      appendGithubOutputs: async (entries) => promotionOutputs.push(...entries),
      execFileSync: () => assert.fail("reuse must not invoke a registry mutation command"),
      writeStdout: (message) => messages.push(message),
    });
    assert.equal(inputChecks, 1, "final reuse verification must recheck recorded inputs");
    assert.deepEqual(Object.fromEntries(promotionOutputs), {
      digest: INDEX_DIGEST,
      promoted: "false",
    });
    assert.match(messages.join(""), /no registry mutation performed/u);
  });
});

test("publication guard rejects an existing tag when a recorded Dockerfile digest changed", async () => {
  await withPublicationEnvironment(async () => {
    const currentPlan = recordedPlan();
    const publishedPlan = structuredClone(currentPlan);
    publishedPlan.dockerfile.sha256 = `sha256:${"77".repeat(32)}`;
    const outputs = [];
    let provenanceChecks = 0;

    await assert.rejects(
      publicationPreflight(args(), {
        inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
        exec: () => {
          provenanceChecks += 1;
          return provenanceOutput();
        },
        readCurrentPlan: async () => currentPlan,
        readPublishedPlan: async () => publishedPlan,
        appendGithubOutputs: async (entries) => outputs.push(...entries),
        writeStdout: () => {},
      }),
      /version tag is already bound to different recorded build inputs/u,
    );

    assert.equal(provenanceChecks, 1, "the existing digest must be verified before input comparison");
    assert.deepEqual(outputs, [], "changed inputs must not produce reuse or build authorization outputs");
  });
});

test("publication guard fails closed when the published input record is unavailable", async () => {
  await withPublicationEnvironment(async () => {
    const outputs = [];

    await assert.rejects(
      publicationPreflight(args(), {
        inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
        exec: () => provenanceOutput(),
        readCurrentPlan: async () => recordedPlan(),
        readPublishedPlan: async () => {
          throw new Error("fixture history unavailable");
        },
        appendGithubOutputs: async (entries) => outputs.push(...entries),
        writeStdout: () => {},
      }),
      /published engine input plan is unavailable: fixture history unavailable/u,
    );

    assert.deepEqual(outputs, [], "unavailable input history must not produce reuse or build authorization outputs");
  });
});

test("publication guard authorizes a build when the version tag is absent", async () => {
  await withPublicationEnvironment(async () => {
    const outputs = [];
    const messages = [];
    const unexpected = () => {
      assert.fail("an absent tag must not require provenance or historical input records");
    };

    await publicationPreflight(args(), {
      inspectGhcrTag: async () => ({ state: "absent" }),
      exec: unexpected,
      readCurrentPlan: unexpected,
      readPublishedPlan: unexpected,
      appendGithubOutputs: async (entries) => outputs.push(...entries),
      writeStdout: (message) => messages.push(message),
    });

    assert.deepEqual(Object.fromEntries(outputs), {
      mode: "build",
      should_build: "true",
      digest: "",
      candidate_tag: `candidate-${CURRENT_REVISION}-12345-2`,
    });
    assert.match(messages.join(""), /is absent; a unique candidate may be built/u);
  });
});
