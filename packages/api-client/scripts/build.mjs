import { cp, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generatedDirectory = resolve(packageDirectory, "dist/gen");

await mkdir(generatedDirectory, { recursive: true });
await cp(
  resolve(packageDirectory, "src/gen/schema.d.ts"),
  resolve(generatedDirectory, "schema.d.ts"),
);
