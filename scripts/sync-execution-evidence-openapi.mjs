// Mechanical byte-identical mirrors give OpenAPI's external schemas stable,
// distinct filenames without renaming legacy generated client schema aliases.
import { readFile, writeFile } from "node:fs/promises";
for (const [version, folder] of [
  [1, "terminal-evidence"],
  [2, "terminal-evidence-v2"],
]) {
  const source = new URL(
    `../proto/provenance/runner/v1/${folder}/schema.json`,
    import.meta.url,
  );
  const target = new URL(
    `../openapi/execution-evidence-v${version}.json`,
    import.meta.url,
  );
  await writeFile(target, await readFile(source));
}
