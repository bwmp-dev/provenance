import fs from "node:fs";
import { parse } from "yaml";
const doc = parse(
  fs.readFileSync(
    new URL("../openapi/provenance.v1.yaml", import.meta.url),
    "utf8",
  ),
);
function dereference(value) {
  if (Array.isArray(value)) return value.map(dereference);
  if (!value || typeof value !== "object") return value;
  if (value.$ref) {
    if (!value.$ref.startsWith("#/"))
      throw new Error("Runtime projection requires local references");
    const source = value.$ref
      .slice(2)
      .split("/")
      .reduce((o, k) => o[k], doc);
    const { $ref, ...rest } = value;
    return { ...dereference(source), ...dereference(rest) };
  }
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [k, dereference(v)]),
  );
}
const paths = Object.fromEntries(
  [
    "/v1/paper-runtimes/{runtimeId}",
    "/v1/paper-runtime-assets/{sha256}/{filename}",
    "/v1/paper-versions",
    "/v1/paper-versions/{version}/builds",
  ].map((path) => [path, dereference(doc.paths[path])]),
);
if (!process.argv[2]) throw new Error("Output path is required");
fs.writeFileSync(process.argv[2], JSON.stringify({ paths }, null, 2) + "\n");
