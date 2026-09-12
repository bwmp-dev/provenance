import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { basename, delimiter, join, resolve } from "node:path";
import test from "node:test";
import { parse } from "yaml";
import { generateProtobuf, plugins } from "./generate-protobuf.mjs";

const repository = resolve(import.meta.dirname, "..");
function success(command) {
  const plugin = plugins.find(
    (entry) => basename(command).replace(/\.exe$/, "") === entry.binary,
  );
  return { status: 0, stdout: plugin ? `${plugin.version}\n` : "" };
}

test("generation uses only local plugins with unchanged options and exact pins", () => {
  assert.deepEqual(
    plugins.map((entry) => entry.module),
    [
      "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12",
      "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2",
    ],
  );
  const template = parse(
    readFileSync(join(repository, "buf.gen.yaml"), "utf8"),
  );
  assert.deepEqual(template.plugins, [
    {
      local: "protoc-gen-go",
      out: "gen/proto/provenance/runner/v1",
      opt: ["paths=source_relative"],
    },
    {
      local: "protoc-gen-go-grpc",
      out: "gen/proto/provenance/runner/v1",
      opt: ["paths=source_relative"],
    },
    {
      local: "protoc-gen-es",
      out: "packages/runner-protocol/src/gen",
      opt: ["target=ts", "import_extension=js"],
    },
  ]);
  assert.equal(template.clean, true);
  assert.deepEqual(template.inputs, [
    { directory: "proto/provenance/runner/v1" },
  ]);
  const manifest = JSON.parse(
    readFileSync(join(repository, "package.json"), "utf8"),
  );
  assert.equal(
    manifest.scripts.generate,
    "node scripts/sync-execution-evidence-openapi.mjs && node scripts/generate-protobuf.mjs && pnpm --filter @bwmp-dev/api-client generate",
  );
});

test("bootstrap isolates executable paths, pins toolchain, and cleans each invocation", () => {
  const directories = [];
  for (let invocation = 0; invocation < 2; invocation += 1) {
    const calls = [];
    generateProtobuf({
      env: { PATH: "/untrusted", GOBIN: "/untrusted", GOTOOLCHAIN: "auto" },
      run(command, args, options) {
        calls.push({ command, args, options });
        assert.equal(options.cwd, repository);
        assert.equal(
          options.env.GOTOOLCHAIN,
          `go${readFileSync(join(repository, ".go-version"), "utf8").trim()}`,
        );
        assert.ok(existsSync(options.env.GOBIN));
        assert.deepEqual(options.env.PATH.split(delimiter), [
          options.env.GOBIN,
          join(repository, "node_modules/.bin"),
          "/untrusted",
        ]);
        return success(command);
      },
    });
    assert.equal(calls.length, 5);
    const directory = calls[0].options.env.GOBIN;
    directories.push(directory);
    assert.notEqual(directory, "/untrusted");
    for (const [index, plugin] of plugins.entries()) {
      assert.equal(calls[index * 2].command, "go");
      assert.deepEqual(calls[index * 2].args, ["install", plugin.module]);
      assert.equal(
        calls[index * 2 + 1].command,
        join(
          directory,
          plugin.binary + (process.platform === "win32" ? ".exe" : ""),
        ),
      );
      assert.deepEqual(calls[index * 2 + 1].args, ["--version"]);
    }
    assert.equal(calls[4].command, join(repository, "node_modules/.bin/buf"));
    assert.deepEqual(calls[4].args, ["generate", "--template", "buf.gen.yaml"]);
    assert.equal(existsSync(directory), false);
  }
  assert.notEqual(directories[0], directories[1]);
});

for (const failingCall of [0, 1, 2, 3, 4]) {
  test(`failure at bootstrap/generation call ${failingCall} propagates and stops`, () => {
    let count = 0;
    let directory;
    assert.throws(
      () =>
        generateProtobuf({
          run(command, args, options) {
            directory = options.env.GOBIN;
            return count++ === failingCall ? { status: 17 } : success(command);
          },
        }),
      (error) => error.exitCode === 17,
    );
    assert.equal(count, failingCall + 1);
    assert.equal(existsSync(directory), false);
  });
}

test("spawn errors, signals, and incorrect executable versions fail closed", () => {
  for (const failure of [
    { error: new Error("spawn failed") },
    { status: null, signal: "SIGTERM" },
    { status: 0, stdout: "wrong version" },
  ]) {
    let count = 0;
    let directory;
    assert.throws(() =>
      generateProtobuf({
        run(command, args, options) {
          directory = options.env.GOBIN;
          return count++ === 1 ? failure : success(command);
        },
      }),
    );
    assert.equal(count, 2);
    assert.equal(existsSync(directory), false);
  }
});
