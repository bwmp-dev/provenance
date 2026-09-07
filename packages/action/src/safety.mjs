import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, lstat } from "node:fs/promises";

export class ActionError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
export const fail = (code) => { throw new ActionError(code); };
export const uuid = (v) => typeof v === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v);
export const numeric = (v) => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v);
export const sha = (v) => typeof v === "string" && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(v);
export const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export function finite(v, max) {
  if (!Number.isSafeInteger(v) || v < 1 || v > max) fail("invalid_configuration");
  return v;
}
export function https(value, originOnly = false) {
  let u;
  try { u = new URL(value); } catch { fail("invalid_configuration"); }
  if (u.protocol !== "https:" || u.username || u.password || u.hash || (originOnly && (u.pathname !== "/" || u.search))) fail("invalid_configuration");
  return u;
}
export function timestamp(v) {
  if (typeof v !== "string" || !/^\d{4}-\d\d-\d\dT/.test(v) || !Number.isFinite(Date.parse(v))) fail("invalid_response");
  return Date.parse(v);
}
export function exactKeys(v, required, optional = []) {
  if (!object(v) || required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) fail("invalid_response");
}

// One explicit bounded allocation, no shared file handle or mutable upload stream.
export async function stableFile(path, limit) {
  finite(limit, 2147483647);
  let handle;
  try {
    const link = await lstat(path, { bigint: true });
    if (!link.isFile() || link.isSymbolicLink()) fail("invalid_file");
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(limit) || before.ino !== link.ino || before.dev !== link.dev) fail("invalid_file");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) fail("file_changed");
      offset += bytesRead;
    }
    const digest = createHash("sha256").update(bytes).digest("hex");
    const check = async () => {
      const after = await handle.stat({ bigint: true });
      const current = await lstat(path, { bigint: true });
      for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
        if (after[key] !== before[key] || current[key] !== before[key]) fail("file_changed");
      }
      if (!current.isFile() || current.isSymbolicLink()) fail("file_changed");
    };
    await check();
    return { bytes, digest, check, close: () => handle.close() };
  } catch (e) {
    await handle?.close();
    if (e instanceof ActionError) throw e;
    fail("invalid_file");
  }
}

export async function boundedResponse(response, maxBytes) {
  const chunks = [];
  let size = 0;
  const reader = response.body?.getReader();
  try {
    if (reader) for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) fail("invalid_response");
      chunks.push(value);
    }
    return Buffer.concat(chunks, size);
  } finally { await reader?.cancel().catch(() => {}); }
}
