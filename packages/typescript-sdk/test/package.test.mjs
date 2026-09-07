import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repository = fileURLToPath(new URL("../../../", import.meta.url));
function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, CI: "true" },
  });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")}\n${result.stdout}\n${result.stderr}`,
  );
  return result.stdout;
}

test("isolated extracted SDK with nested file packages resolves through supported pnpm", async (t) => {
  const temporary = await mkdtemp(resolve(tmpdir(), "provenance-sdk-package-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const sdk = resolve(temporary, "archive/package");
  await mkdir(sdk, { recursive: true });
  const document = JSON.parse(
    await readFile(
      resolve(repository, "packages/typescript-sdk/package.json"),
      "utf8",
    ),
  );
  document.dependencies = {};
  for (const [directory, name] of [
    ["api-client", "api-client"],
    ["config-schema", "config-schema"],
    ["verification", "verification"],
  ]) {
    const source = resolve(repository, "packages", directory);
    const destination = resolve(sdk, "vendor", name);
    await mkdir(destination, { recursive: true });
    await cp(resolve(source, "dist"), resolve(destination, "dist"), {
      recursive: true,
    });
    await cp(
      resolve(source, "package.json"),
      resolve(destination, "package.json"),
    );
    await cp(resolve(repository, "LICENSE"), resolve(destination, "LICENSE"));
    document.dependencies[`@bwmp-dev/${name}`] = `file:./vendor/${name}`;
  }
  document.files = ["dist", "vendor", "LICENSE"];
  await cp(
    resolve(repository, "packages/typescript-sdk/dist"),
    resolve(sdk, "dist"),
    { recursive: true },
  );
  await cp(resolve(repository, "LICENSE"), resolve(sdk, "LICENSE"));
  await writeFile(resolve(sdk, "package.json"), JSON.stringify(document));
  const consumer = resolve(temporary, "consumer");
  await mkdir(consumer);
  assert.equal(run("pnpm", ["--version"], consumer).trim(), "11.20.0");
  await writeFile(
    resolve(consumer, "package.json"),
    JSON.stringify({
      name: "isolated-sdk-consumer",
      private: true,
      type: "module",
      dependencies: { "@bwmp-dev/typescript-sdk": "file:../archive/package" },
    }),
  );
  run("pnpm", ["install", "--offline", "--ignore-scripts"], consumer);
  await writeFile(
    resolve(consumer, "index.mjs"),
    `import assert from 'node:assert/strict';
import {createSDKClient,hashConfiguration,verifyAttestationSignature} from '@bwmp-dev/typescript-sdk';
assert.equal(typeof hashConfiguration,'function');assert.equal(typeof verifyAttestationSignature,'function');
const api=createSDKClient({origin:'https://example.invalid',transport:async()=>Response.json({status:'passed'}),timeoutMs:1000,maxResponseBytes:1000});
const result=await api.GET('/v1/release-candidates/{candidateId}',{params:{path:{candidateId:'00000000-0000-4000-8000-000000000001'}}});
assert.equal(result.data.status,'passed');console.log('PACKAGED_SDK_IMPORT_PASS');
`,
  );
  assert.match(
    run(process.execPath, ["index.mjs"], consumer),
    /PACKAGED_SDK_IMPORT_PASS/,
  );
  // Execute the documented example through the installed package, not a source import.
  await cp(
    resolve(repository, "examples/consumption/sdk-verify.mjs"),
    resolve(consumer, "sdk-verify.mjs"),
  );
  const fixture = JSON.parse(
    await readFile(
      resolve(
        repository,
        "schemas/fixtures/attestation/interop/small-artifact.json",
      ),
      "utf8",
    ),
  );
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(fixture.publicKeyHex, "hex"),
    ]),
    format: "der",
    type: "spki",
  }).export({ format: "pem", type: "spki" });
  await writeFile(
    resolve(consumer, "attestation.json"),
    JSON.stringify(fixture.document),
  );
  await writeFile(
    resolve(consumer, "artifact.jar"),
    Buffer.from(fixture.artifactHex, "hex"),
  );
  await writeFile(resolve(consumer, "trusted.pem"), publicKey);
  assert.equal(
    run(
      process.execPath,
      ["sdk-verify.mjs", "attestation.json", "artifact.jar", "trusted.pem"],
      consumer,
    ).trim(),
    "Artifact signature, size and SHA-256 verified",
  );
  await writeFile(resolve(consumer, "artifact.jar"), "PRIVATE-BYTES");
  const rejected = spawnSync(
    process.execPath,
    ["sdk-verify.mjs", "attestation.json", "artifact.jar", "trusted.pem"],
    { cwd: consumer, encoding: "utf8" },
  );
  assert.equal(rejected.status, 1);
  assert.equal(rejected.stdout, "");
  assert.equal(rejected.stderr, "Artifact verification failed\n");
});
