import fs from "node:fs";
import { parse } from "yaml";
const doc = parse(
  fs.readFileSync(
    new URL("../openapi/provenance.v1.yaml", import.meta.url),
    "utf8",
  ),
);
function dereference(v) {
  if (Array.isArray(v)) return v.map(dereference);
  if (!v || typeof v !== "object") return v;
  if (v.$ref) {
    const source = v.$ref
      .slice(2)
      .split("/")
      .reduce((o, k) => o[k], doc);
    const { $ref, ...rest } = v;
    return { ...dereference(source), ...dereference(rest) };
  }
  return Object.fromEntries(
    Object.entries(v).map(([k, x]) => [k, dereference(x)]),
  );
}
const paths = Object.fromEntries(
  ["/v1/admin/runner-updates", "/v1/runner-updater/{runnerId}/poll"].map(
    (p) => [p, dereference(doc.paths[p])],
  ),
);
if (!process.argv[2]) throw new Error("Output path is required");
fs.writeFileSync(process.argv[2], JSON.stringify({ paths }, null, 2) + "\n");
