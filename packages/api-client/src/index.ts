import createClient, { type ClientOptions } from "openapi-fetch";

import type { components, operations, paths } from "./gen/schema.js";

export type { components, operations, paths };

export function createProvenanceClient(options: ClientOptions = {}) {
  return createClient<paths>(options);
}
