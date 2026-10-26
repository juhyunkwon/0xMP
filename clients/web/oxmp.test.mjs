// Cross-platform vector verification for the JavaScript implementation.
// Run: node --test clients/web/oxmp.test.mjs   (from the repository root)
// The same clients/test_vectors.json must pass for every platform SDK.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  FrameError, FrameType, decodeFrame, decodeMessageAccepted, decodeSyncBatch,
  encodeFrame, encodeHello, encodeMessageSend, fromHex, parseFields, toHex,
} from "./oxmp.js";

const vectors = JSON.parse(
  readFileSync(new URL("../test_vectors.json", import.meta.url), "utf8"));

test("frame vectors reproduce exactly", () => {
  const ping = vectors.frames.find((v) => v.name === "ping_empty");
  assert.equal(toHex(encodeFrame(FrameType.PING)), ping.hex);

  const hello = vectors.frames.find((v) => v.name === "hello_protocol_only");
  const helloFrame = encodeFrame(FrameType.HELLO, encodeHello({ protocolId: "0xmp.v1" }));
  assert.equal(toHex(helloFrame), hello.hex);
  assert.equal(decodeFrame(fromHex(hello.hex)).type, FrameType.HELLO);

  const ext = vectors.frames.find((v) => v.name === "ping_with_extension");
  const extFrame = encodeFrame(FrameType.PING, new TextEncoder().encode("ab"),
                               0, new TextEncoder().encode("xy"));
  assert.equal(toHex(extFrame), ext.hex);
  const decoded = decodeFrame(fromHex(ext.hex));
  assert.equal(new TextDecoder().decode(decoded.extension), "xy");
  assert.equal(new TextDecoder().decode(decoded.payload), "ab");
});

test("negative vectors are all rejected", () => {
  for (const v of vectors.negative_frames) {
    assert.throws(() => decodeFrame(fromHex(v.hex)), FrameError, v.name);
  }
});

test("protobuf payload vectors match the Python implementation", () => {
  const accepted = vectors.payloads.find((v) => v.name === "message_accepted_seq1");
  assert.deepEqual(decodeMessageAccepted(fromHex(accepted.hex)).sequence, 1);

  const send = vectors.payloads.find((v) => v.name === "message_send_fixed_ids");
  const mine = encodeMessageSend({
    messageId: Uint8Array.from({ length: 16 }, (_, i) => i),
    conversationId: Uint8Array.from({ length: 16 }, (_, i) => i + 16),
    senderDeviceId: Uint8Array.from({ length: 16 }, (_, i) => i + 32),
    clientTimestampMs: 1700000000000,
    idempotencyKey: Uint8Array.from({ length: 16 }, (_, i) => i + 48),
    kind: 1, body: new TextEncoder().encode("cross-platform ✓"),
  });
  assert.equal(toHex(mine), send.hex);
  const fields = parseFields(mine);
  assert.equal(Number(fields.get(4)[0]), 1700000000000);
});

test("sync batch (room history) decodes identically", () => {
  const vector = vectors.payloads.find((v) => v.name === "sync_batch_one_text");
  const batch = decodeSyncBatch(fromHex(vector.hex));
  assert.equal(batch.hasMore, false);
  assert.equal(batch.nextAfterSequence, 1);
  assert.equal(batch.events.length, 1);
  assert.equal(batch.events[0].sequence, 1);
  assert.equal(new TextDecoder().decode(batch.events[0].message.body), "room history");
});
