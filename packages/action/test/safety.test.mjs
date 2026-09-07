import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strictJSON, stableFile, boundedResponse } from "../src/safety.mjs";

test("strict response JSON rejects duplicate authority, Unicode and complexity ambiguity", () => {
  for (const bytes of [
    Buffer.from('{"projectId":"a","projectId":"b"}'),
    Buffer.from('{"projectId":"a","project\\u0049d":"b"}'),
    Buffer.from('{"a":"\\ud800"}'),
    Buffer.from([0x22, 0xff, 0x22]),
    Buffer.from("[".repeat(66) + "0" + "]".repeat(66)),
    Buffer.from('{"value":1e9999}'),
    Buffer.from('{"a":true,}'),
    Buffer.from("[false,]"),
    Buffer.from("true false"),
  ])
    assert.throws(() => strictJSON(bytes), { code: "invalid_response" });
  assert.deepEqual(
    strictJSON(
      Buffer.from('{"a":[true, false, null, -1.5e2],"b":"\\uD83D\\uDE00"}'),
    ),
    { a: [true, false, null, -150], b: "😀" },
  );
});
test("stable file budget and identity reject empty, oversized and symlink input", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "action-file-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, "file"),
    link = join(dir, "link");
  await writeFile(file, "1234");
  await symlink(file, link);
  await assert.rejects(stableFile(file, 3), { code: "invalid_file" });
  await assert.rejects(stableFile(link, 4), { code: "invalid_file" });
  const opened = await stableFile(file, 4);
  assert.equal(opened.bytes.toString(), "1234");
  await writeFile(file, "5678");
  await assert.rejects(opened.check(), { code: "file_changed" });
  await opened.close();
  await writeFile(file, "");
  await assert.rejects(stableFile(file, 4), { code: "invalid_file" });
});
test("streaming response ceiling cancels the source at overflow", async () => {
  let canceled = false;
  const response = new Response(
    new ReadableStream({
      pull(c) {
        c.enqueue(new Uint8Array(5));
      },
      cancel() {
        canceled = true;
      },
    }),
  );
  await assert.rejects(boundedResponse(response, 4), {
    code: "invalid_response",
  });
  assert.equal(canceled, true);
});
