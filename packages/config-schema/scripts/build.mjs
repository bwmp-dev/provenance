import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDirectory = resolve(packageDirectory, "../..");
const outputDirectory = resolve(packageDirectory, "dist");

await rm(outputDirectory, { force: true, recursive: true });
await mkdir(outputDirectory, { recursive: true });
await cp(
  resolve(packageDirectory, "src/index.js"),
  resolve(outputDirectory, "index.js"),
);
await cp(
  resolve(repositoryDirectory, "schemas/config/v1/schema.json"),
  resolve(outputDirectory, "schema.json"),
);
