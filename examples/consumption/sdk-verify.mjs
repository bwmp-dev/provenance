import { readFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { verifyAttestedArtifact } from "@bwmp-dev/typescript-sdk";

// Public trust input is explicit. Never fetch the untrusted document's key ID.
const [documentPath, artifactPath, trustedPublicKeyPath] =
  process.argv.slice(2);
try {
  if (
    !documentPath ||
    !artifactPath ||
    !trustedPublicKeyPath ||
    process.argv.length !== 5
  )
    throw new Error();
  const document = JSON.parse(await readFile(documentPath, "utf8"));
  const publicKey = await readFile(trustedPublicKeyPath, "utf8");
  async function* bytes() {
    // Opening the artifact is lazy: the verifier authenticates before iteration.
    yield* createReadStream(artifactPath);
  }
  await verifyAttestedArtifact(document, publicKey, bytes());
  console.log("Artifact signature, size and SHA-256 verified");
} catch {
  console.error("Artifact verification failed");
  process.exitCode = 1;
}
