// Authoritative schemas are owned by schemas/config, never the embedded copy.
import { copyFile } from "node:fs/promises";
for (const [version, filename] of [
  ["v1", "schema.json"],
  ["v2", "schema-v2.json"],
]) {
  await copyFile(
    new URL(`../schemas/config/${version}/schema.json`, import.meta.url),
    new URL(`../packages/cli-go/internal/config/${filename}`, import.meta.url),
  );
}
