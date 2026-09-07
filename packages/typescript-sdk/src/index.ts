import { createProvenanceClient } from "@bwmp-dev/api-client";
import {
  parseConfiguration as parse,
  normalizeConfiguration as normalize,
  hashConfiguration as hash,
} from "@bwmp-dev/config-schema";
import {
  verifyAttestationSignature as verifySignature,
  verifyAttestedArtifact as verifyArtifact,
} from "@bwmp-dev/verification";

export type { components, operations, paths } from "@bwmp-dev/api-client";
export type SDKErrorCode =
  | "invalid_options"
  | "destination_denied"
  | "redirect_denied"
  | "request_failed"
  | "transport_failed"
  | "response_limit"
  | "invalid_response"
  | "cancelled"
  | "timeout"
  | "configuration_invalid"
  | "verification_failed";
export class SDKError extends Error {
  readonly code: SDKErrorCode;
  readonly status: number | undefined;
  constructor(code: SDKErrorCode, status?: number) {
    super(`Provenance SDK: ${code}`);
    this.name = "SDKError";
    this.code = code;
    this.status = status;
  }
}
export interface ClientOptions {
  /** Exact trusted HTTPS origin, no path, user information, query or fragment. */
  readonly origin: string;
  /** Caller-owned transport; no hidden global transport or credential resolution. */
  readonly transport: typeof fetch;
  /** Positive per-request bound, including reading the response body; maximum 120000. */
  readonly timeoutMs: number;
  /** Positive response byte budget, maximum 16777216. Not a private log streaming API. */
  readonly maxResponseBytes: number;
}
const methods = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
  "TRACE",
] as const;
export type SDKClient = Pick<
  ReturnType<typeof createProvenanceClient>,
  (typeof methods)[number]
>;

function bounded(value: number, max: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= max;
}
function closed(error: unknown): SDKError {
  return error instanceof SDKError ? error : new SDKError("transport_failed");
}
function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new SDKError("timeout"));
    if (signal.aborted) {
      pending.catch(() => {});
      abort();
      return;
    }
    signal.addEventListener("abort", abort, { once: true });
    pending
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}

/**
 * Construct generated typed HTTP methods with explicit network bounds. Supply
 * credential headers per call; no token acquisition, refresh, persistence or retry.
 * Non-success HTTP responses throw SDKError(status), never a raw private body.
 */
export function createSDKClient(options: ClientOptions): SDKClient {
  let origin: URL;
  try {
    origin = new URL(options.origin);
  } catch {
    throw new SDKError("invalid_options");
  }
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    typeof options.transport !== "function" ||
    !bounded(options.timeoutMs, 120000) ||
    !bounded(options.maxResponseBytes, 16777216)
  )
    throw new SDKError("invalid_options");
  const trustedOrigin = origin.origin;
  // Snapshot configuration: caller mutation cannot relax destination or bounds.
  const transport = options.transport,
    timeoutMs = options.timeoutMs,
    maxResponseBytes = options.maxResponseBytes;
  const client = createProvenanceClient({
    baseUrl: trustedOrigin,
    fetch: async (request: Request) => {
      let target: URL;
      try {
        target = new URL(request.url);
      } catch {
        throw new SDKError("destination_denied");
      }
      if (
        target.origin !== trustedOrigin ||
        target.username ||
        target.password ||
        target.hash
      )
        throw new SDKError("destination_denied");
      const timeout = AbortSignal.timeout(timeoutMs);
      const signal = AbortSignal.any([request.signal, timeout]);
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      try {
        if (request.signal.aborted) throw new SDKError("cancelled");
        const response = await abortable(
          transport(
            new Request(request, {
              redirect: "manual",
              credentials: "omit",
              signal,
            }),
          ),
          signal,
        );
        if (
          response.redirected ||
          (response.url && new URL(response.url).origin !== trustedOrigin) ||
          (response.status >= 300 && response.status < 400)
        ) {
          void response.body?.cancel().catch(() => {});
          throw new SDKError("redirect_denied", response.status);
        }
        // Do not parse, expose, or retain any failed response body/headers.
        if (!response.ok) {
          void response.body?.cancel().catch(() => {});
          throw new SDKError("request_failed", response.status);
        }
        reader = response.body?.getReader();
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (reader)
          for (;;) {
            const next = await abortable(reader.read(), signal);
            if (next.done) break;
            size += next.value.length;
            if (size > maxResponseBytes) throw new SDKError("response_limit");
            chunks.push(next.value);
          }
        if (signal.aborted)
          throw new SDKError(request.signal.aborted ? "cancelled" : "timeout");
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.length;
        }
        const headers = new Headers(response.headers);
        // A reconstructed response cannot carry ambient cookie authority.
        headers.delete("set-cookie");
        return new Response(size ? bytes : null, {
          status: response.status,
          statusText: "",
          headers,
        });
      } catch (error) {
        if (request.signal.aborted) throw new SDKError("cancelled");
        if (timeout.aborted) throw new SDKError("timeout");
        throw closed(error);
      } finally {
        void reader?.cancel().catch(() => {});
      }
    },
  });
  const facade = {} as SDKClient;
  for (const method of methods) {
    // Preserve the generated overloads; the wrapper only closes thrown failures.
    const invoke = client[method] as (...args: unknown[]) => Promise<unknown>;
    Object.defineProperty(facade, method, {
      enumerable: true,
      value: async (...args: unknown[]) => {
        try {
          return await invoke(...args);
        } catch (error) {
          throw closed(error);
        }
      },
    });
  }
  return Object.freeze(facade);
}

export type JSONValue =
  string | number | boolean | null | JSONObject | readonly JSONValue[];
export interface JSONObject {
  readonly [key: string]: JSONValue;
}
export function parseConfiguration(source: string): JSONObject {
  try {
    return parse(source) as JSONObject;
  } catch {
    throw new SDKError("configuration_invalid");
  }
}
export function normalizeConfiguration(value: unknown): string {
  try {
    return normalize(value);
  } catch {
    throw new SDKError("configuration_invalid");
  }
}
export function hashConfiguration(value: unknown): string {
  try {
    return hash(value);
  } catch {
    throw new SDKError("configuration_invalid");
  }
}
/** Caller supplies trusted public PEM text or exact raw Ed25519 public bytes. */
export type TrustedPublicKey = string | Uint8Array;
export interface VerifiedArtifactIdentity {
  readonly sizeBytes: number;
  readonly digest: { readonly algorithm: "sha256"; readonly value: string };
}
export function verifyAttestationSignature(
  document: unknown,
  trustedPublicKey: TrustedPublicKey,
): boolean {
  try {
    return verifySignature(document, trustedPublicKey);
  } catch {
    throw new SDKError("verification_failed");
  }
}
export async function verifyAttestedArtifact(
  document: unknown,
  trustedPublicKey: TrustedPublicKey,
  bytes: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
): Promise<VerifiedArtifactIdentity> {
  try {
    return await verifyArtifact(document, trustedPublicKey, bytes);
  } catch {
    throw new SDKError("verification_failed");
  }
}
