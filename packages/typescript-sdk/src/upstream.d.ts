// Adapter declarations for existing JavaScript packages, not generated API edits.
declare module "@bwmp-dev/config-schema" {
  export function parseConfiguration(source: string): unknown;
  export function normalizeConfiguration(value: unknown): string;
  export function hashConfiguration(value: unknown): string;
}
declare module "@bwmp-dev/verification" {
  export function verifyAttestationSignature(
    document: unknown,
    key: string | Uint8Array,
  ): boolean;
  export function verifyAttestedArtifact(
    document: unknown,
    key: string | Uint8Array,
    bytes: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
  ): Promise<{
    readonly sizeBytes: number;
    readonly digest: { readonly algorithm: "sha256"; readonly value: string };
  }>;
}
