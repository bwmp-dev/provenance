import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

// Same immutable Paper API bytes already audited by the toolkit probe build.
const expected =
  "1e2c006933df7f688133140f05dec5ae7d28e64d761d9aadcf92d616b849bda2";
const directory = process.argv[2];
if (!directory)
  throw new Error("Supply the verified Paper API staging directory");
const jars = (await readdir(directory)).filter((name) => name.endsWith(".jar"));
if (jars.length !== 1)
  throw new Error("Expected exactly one staged Paper API JAR");
const api = resolve(directory, jars[0]);
if (
  createHash("sha256")
    .update(await readFile(api))
    .digest("hex") !== expected
)
  throw new Error("Paper API identity differs");
const temporary = await mkdtemp(
  resolve(tmpdir(), "provenance-example-classes-"),
);
function run(command, args) {
  const binary = process.env.JAVA_HOME
    ? resolve(process.env.JAVA_HOME, "bin", command)
    : command;
  const result = spawnSync(binary, args, { stdio: "inherit" });
  if (result.error || result.status !== 0)
    throw new Error(`Example ${command} failed`);
}
try {
  const output = resolve(import.meta.dirname, "build");
  await mkdir(output, { recursive: true });
  run("javac", [
    "--release",
    "21",
    "-g:none",
    "-encoding",
    "UTF-8",
    "-classpath",
    api,
    "-d",
    temporary,
    resolve(import.meta.dirname, "src/HelloPlugin.java"),
  ]);
  run("jar", [
    "--create",
    "--file",
    resolve(output, "example-plugin.jar"),
    "--date=1980-01-01T00:00:02Z",
    "-C",
    temporary,
    ".",
    "-C",
    import.meta.dirname,
    "plugin.yml",
  ]);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
