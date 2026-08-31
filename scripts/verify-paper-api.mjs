import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const [directory, expected] = process.argv.slice(2);
if (!directory || !expected) {
  throw new Error("usage: verify-paper-api.mjs <directory> <expected-sha256>");
}

const jars = readdirSync(directory).filter((name) => name.endsWith(".jar"));
if (jars.length !== 1) {
  throw new Error(`expected one Paper API JAR, found ${jars.length}`);
}

const jar = resolve(directory, jars[0]);
const actual = createHash("sha256").update(readFileSync(jar)).digest("hex");
if (actual !== expected) {
  throw new Error(
    `Paper API artifact hash mismatch: expected ${expected}, got ${actual}`,
  );
}

process.stdout.write(`${actual}  ${jars[0]}\n`);
