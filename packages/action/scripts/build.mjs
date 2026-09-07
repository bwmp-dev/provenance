import { build } from "esbuild";
import { mkdir, writeFile, readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export async function compile() {
  return build({
    absWorkingDir: root,
    entryPoints: [resolve(root, "src/entry.mjs")],
    bundle: true,
    platform: "node",
    target: "node24",
    format: "cjs",
    write: false,
    metafile: true,
    legalComments: "inline",
    sourcemap: false,
    charset: "utf8",
    logLevel: "silent",
  });
}
export async function notices(result) {
  const found = new Map();
  for (const input of Object.keys(result.metafile.inputs)) {
    if (!input.includes("node_modules/")) continue;
    let dir = dirname(resolve(root, input));
    for (;;) {
      try {
        const pkg = JSON.parse(
          await readFile(resolve(dir, "package.json"), "utf8"),
        );
        if (pkg.name && pkg.version) {
          const files = (await readdir(dir))
            .filter((n) => /^(licen[sc]e|copying)(\.|$)/i.test(n))
            .sort();
          if (!files.length)
            throw new Error("Bundled dependency license unavailable");
          found.set(
            `${pkg.name}@${pkg.version}`,
            `${pkg.name}@${pkg.version} (${pkg.license})\n${(await Promise.all(files.map((n) => readFile(resolve(dir, n), "utf8")))).join("\n")}`,
          );
          break;
        }
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
      const parent = dirname(dir);
      if (parent === dir)
        throw new Error("Bundled dependency identity unavailable");
      dir = parent;
    }
  }
  return [...found]
    .sort(([a], [b]) => a.localeCompare(b, "en"))
    .map(([, v]) => v)
    .join("\n\n---\n\n");
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await compile();
  await mkdir(resolve(root, "dist"), { recursive: true });
  await writeFile(
    resolve(root, "dist/index.cjs"),
    result.outputFiles[0].contents,
  );
  await writeFile(
    resolve(root, "dist/THIRD_PARTY_NOTICES.txt"),
    await notices(result),
  );
}
