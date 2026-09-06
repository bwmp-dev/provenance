import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repository = resolve(import.meta.dirname, "..");
export const plugins = Object.freeze([
  Object.freeze({
    module: "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12",
    binary: "protoc-gen-go",
    version: "protoc-gen-go v1.36.12",
  }),
  Object.freeze({
    module: "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2",
    binary: "protoc-gen-go-grpc",
    version: "protoc-gen-go-grpc 1.6.2",
  }),
]);

export function generateProtobuf({ run = spawnSync, env = process.env } = {}) {
  // Never share writable executables between concurrent jobs, or trust a
  // pre-existing protoc plugin on PATH. Go's normal module/build caches remain
  // available; a cold bootstrap needs the Go proxy/checksum service.
  const directory = mkdtempSync(join(tmpdir(), "provenance-protoc-"));
  try {
    const goVersion = readFileSync(
      join(repository, ".go-version"),
      "utf8",
    ).trim();
    if (!/^\d+\.\d+\.\d+$/.test(goVersion))
      throw new Error("Invalid pinned Go version");
    const executable = (name) =>
      join(directory, name + (process.platform === "win32" ? ".exe" : ""));
    const childEnv = {
      ...env,
      GOBIN: directory,
      GOTOOLCHAIN: `go${goVersion}`,
      PATH: [
        directory,
        join(repository, "node_modules/.bin"),
        env.PATH ?? "",
      ].join(delimiter),
    };
    const execute = (command, args, capture = false) => {
      const result = run(command, args, {
        cwd: repository,
        env: childEnv,
        stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
        encoding: "utf8",
      });
      if (result.error) throw result.error;
      if (result.status !== 0 || result.signal) {
        const error = new Error(
          `${command} failed (${result.signal ?? result.status})`,
        );
        error.exitCode = result.status || 1;
        throw error;
      }
      return result.stdout?.trim();
    };
    for (const plugin of plugins) {
      execute("go", ["install", plugin.module]);
      if (
        execute(executable(plugin.binary), ["--version"], true) !==
        plugin.version
      ) {
        throw new Error(
          `Installed ${plugin.binary} version differs from its pin`,
        );
      }
    }
    execute(join(repository, "node_modules/.bin/buf"), [
      "generate",
      "--template",
      "buf.gen.yaml",
    ]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    generateProtobuf();
  } catch (error) {
    console.error(error.message);
    process.exitCode = error.exitCode ?? 1;
  }
}
