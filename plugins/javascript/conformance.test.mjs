// Proves the JavaScript plugin entry reproduces clients/test_vectors.json.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  FrameError, FrameType, decodeFrame, decodeMessageAccepted, decodeSyncBatch,
  encodeDeleteEvent, decodeDeleteEvent, encodeFrame, encodeHello, encodeMessageSend,
  fromHex, signChallenge, toHex,
} from "./oxmp_plugin.mjs";

const doc = JSON.parse(readFileSync(
  new URL("../../clients/test_vectors.json", import.meta.url), "utf8"));
const hexOf = (name) => {
  for (const section of ["frames", "payloads", "negative_frames"]) {
    const hit = doc[section].find((v) => v.name === name);
    if (hit) return hit.hex;
  }
  throw new Error(name);
};

test("javascript plugin matches the shared vectors", () => {
  assert.equal(toHex(encodeFrame(FrameType.PING)), hexOf("ping_empty"));
  const hello = encodeFrame(FrameType.HELLO, encodeHello({ protocolId: "0xmp.v1" }));
  assert.equal(toHex(hello), hexOf("hello_protocol_only"));
  assert.equal(decodeFrame(hello).type, FrameType.HELLO);
  const ext = encodeFrame(FrameType.PING, new TextEncoder().encode("ab"),
    0, new TextEncoder().encode("xy"));
  assert.equal(toHex(ext), hexOf("ping_with_extension"));
  const decoded = decodeFrame(fromHex(hexOf("ping_with_extension")));
  assert.equal(new TextDecoder().decode(decoded.extension), "xy");
  assert.equal(new TextDecoder().decode(decoded.payload), "ab");
  for (const item of doc.negative_frames) {
    assert.throws(() => decodeFrame(fromHex(item.hex)), FrameError, item.name);
  }
  assert.equal(decodeMessageAccepted(fromHex(hexOf("message_accepted_seq1"))).sequence, 1);
  const body = new Uint8Array(18);
  body.set(new TextEncoder().encode("cross-platform "));
  body.set([0xe2, 0x9c, 0x93], 15);
  const sent = encodeMessageSend({
    messageId: Uint8Array.from({ length: 16 }, (_, i) => i),
    conversationId: Uint8Array.from({ length: 16 }, (_, i) => i + 16),
    senderDeviceId: Uint8Array.from({ length: 16 }, (_, i) => i + 32),
    idempotencyKey: Uint8Array.from({ length: 16 }, (_, i) => i + 48),
    clientTimestampMs: 1700000000000, kind: 1, body,
  });
  assert.equal(toHex(sent), hexOf("message_send_fixed_ids"));
  const batch = decodeSyncBatch(fromHex(hexOf("sync_batch_one_text")));
  assert.equal(batch.hasMore, false);
  assert.equal(batch.nextAfterSequence, 1);
  assert.equal(batch.events[0].sequence, 1);
  assert.equal(new TextDecoder().decode(batch.events[0].message.body), "room history");
  const deleted = decodeDeleteEvent(encodeDeleteEvent({
    conversationId: new Uint8Array(16).fill(0x11),
  }));
  assert.equal(deleted.forEveryone, true);
  assert.equal(deleted.messageId.length, 0);
});

test("Ed25519 challenge signature matches the other language plugins", async () => {
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const pub = fromHex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
  const sig = await signChallenge(seed, pub, "0xmp-challenge");
  assert.equal(toHex(sig),
    "b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b2360" +
    "6fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e");
});
