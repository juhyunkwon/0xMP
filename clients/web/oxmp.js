// 0xMP v0.3 web client codec (browser + Node, no dependencies).
// Mirrors samples/oxmp_frame.py and samples/oxmp.proto. Any behaviour
// difference from the Python vectors in clients/test_vectors.json is a bug.

export const MAGIC = new Uint8Array([0x4d, 0x50]); // "MP"
export const VERSION = 0x01;
export const MAX_PAYLOAD = 1024 * 1024;

export const FrameType = {
  HELLO: 0x01, AUTH: 0x02, AUTH_RESULT: 0x03, HELLO_RESULT: 0x04,
  MESSAGE_SEND: 0x10, MESSAGE_ACCEPTED: 0x11, MESSAGE_DELIVERED: 0x12,
  MESSAGE_READ: 0x13, MESSAGE_EDIT: 0x14, MESSAGE_DELETE: 0x15,
  MESSAGE_INCOMING: 0x16, MESSAGE_DELIVERY_ACK: 0x17,
  SYNC_REQUEST: 0x20, SYNC_BATCH: 0x21, SYNC_ACK: 0x22,
  MEDIA_INIT: 0x30, MEDIA_COMPLETE: 0x31,
  PING: 0x40, PONG: 0x41,
  KEY_BUNDLE_PUBLISH: 0x50, KEY_BUNDLE_REQUEST: 0x51, KEY_BUNDLE_RESPONSE: 0x52,
  ERROR: 0x7f,
};
const KNOWN_TYPES = new Set(Object.values(FrameType));
const KNOWN_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0008;

export class FrameError extends Error {}

export function encodeFrame(type, payload = new Uint8Array(), flags = 0, extension = new Uint8Array()) {
  if (!KNOWN_TYPES.has(type)) throw new FrameError(`unknown frame type ${type}`);
  if (flags & ~KNOWN_FLAGS) throw new FrameError("reserved flag bits set");
  let body = payload;
  if (extension.length) {
    flags |= 0x0004;
    body = new Uint8Array(2 + extension.length + payload.length);
    new DataView(body.buffer).setUint16(0, extension.length);
    body.set(extension, 2);
    body.set(payload, 2 + extension.length);
  }
  if (body.length > MAX_PAYLOAD) throw new FrameError("payload exceeds hard cap");
  const out = new Uint8Array(10 + body.length);
  const view = new DataView(out.buffer);
  out.set(MAGIC, 0);
  view.setUint8(2, VERSION);
  view.setUint8(3, type);
  view.setUint16(4, flags);
  view.setUint32(6, body.length);
  out.set(body, 10);
  return out;
}

export function decodeFrame(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.length < 10) throw new FrameError("frame shorter than fixed header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes[0] !== MAGIC[0] || bytes[1] !== MAGIC[1]) throw new FrameError("bad magic");
  if (view.getUint8(2) !== VERSION) throw new FrameError("unsupported frame version");
  const type = view.getUint8(3);
  const flags = view.getUint16(4);
  const length = view.getUint32(6);
  if (length > MAX_PAYLOAD) throw new FrameError("payload_length exceeds hard cap");
  if (bytes.length !== 10 + length) throw new FrameError("frame length mismatch");
  if (flags & ~KNOWN_FLAGS) throw new FrameError("reserved flag bits set");
  if (!KNOWN_TYPES.has(type)) throw new FrameError(`unknown frame type ${type}`);
  let body = bytes.slice(10);
  let extension = new Uint8Array();
  if (flags & 0x0004) {
    if (body.length < 2) throw new FrameError("extension header truncated");
    const extLen = new DataView(body.buffer, body.byteOffset).getUint16(0);
    if (body.length < 2 + extLen) throw new FrameError("extension body truncated");
    extension = body.slice(2, 2 + extLen);
    body = body.slice(2 + extLen);
  }
  return { type, flags, payload: body, extension, version: VERSION };
}

// --- minimal Protobuf -------------------------------------------------------
class Writer {
  constructor() { this.parts = []; }
  varint(value) {
    let v = BigInt(value);
    const bytes = [];
    do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; bytes.push(b); } while (v);
    this.parts.push(new Uint8Array(bytes)); return this;
  }
  tag(field, wire) { return this.varint((field << 3) | wire); }
  bytes(field, data) {
    if (!data || data.length === 0) return this; // proto3 default omission
    this.tag(field, 2); this.varint(data.length); this.parts.push(data); return this;
  }
  string(field, text) { return this.bytes(field, new TextEncoder().encode(text)); }
  uint(field, value) { if (value) { this.tag(field, 0); this.varint(value); } return this; }
  concat() {
    const total = this.parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total); let at = 0;
    for (const p of this.parts) { out.set(p, at); at += p.length; }
    return out;
  }
}

export function parseFields(data) {
  const fields = new Map();
  let at = 0;
  const readVarint = () => {
    let shift = 0n, result = 0n;
    for (;;) { const b = data[at++]; result |= BigInt(b & 0x7f) << shift; if (!(b & 0x80)) return result; shift += 7n; }
  };
  while (at < data.length) {
    const tag = Number(readVarint());
    const field = tag >> 3, wire = tag & 7;
    let value;
    if (wire === 0) value = readVarint();
    else if (wire === 2) { const len = Number(readVarint()); value = data.slice(at, at + len); at += len; }
    else if (wire === 5) { value = data.slice(at, at + 4); at += 4; }
    else if (wire === 1) { value = data.slice(at, at + 8); at += 8; }
    else throw new FrameError(`unsupported wire type ${wire}`);
    if (!fields.has(field)) fields.set(field, []);
    fields.get(field).push(value);
  }
  return fields;
}
const get = (f, n) => (f.get(n) || [undefined])[0];
const text = (v) => (v ? new TextDecoder().decode(v) : "");

// --- messages (subset used by the web UI) ------------------------------------
export const encodeHello = (o) => new Writer()
  .string(1, o.protocolId || "0xmp.v1").uint(2, o.minProfile || 0).uint(3, o.maxProfile || 0)
  .string(5, o.clientName || "").string(6, o.clientVersion || "").concat();

export const decodeHelloResult = (data) => {
  const f = parseFields(data);
  return { protocolId: text(get(f, 1)), selectedProfile: Number(get(f, 2) || 0n),
           maxPayload: Number(get(f, 4) || 0n), sessionId: text(get(f, 5)) };
};

export const encodeAuth = (o) => new Writer()
  .string(1, o.accessToken).bytes(2, o.deviceId).bytes(4, o.signature).concat();

export const decodeAuthResult = (data) => {
  const f = parseFields(data);
  return { ok: (get(f, 1) || 0n) === 1n, userId: get(f, 2), deviceId: get(f, 3) };
};

export const encodeMessageSend = (o) => {
  const content = new Writer().uint(1, o.kind || 1).bytes(2, o.body).concat();
  return new Writer().bytes(1, o.messageId).bytes(2, o.conversationId)
    .bytes(3, o.senderDeviceId).uint(4, o.clientTimestampMs || Date.now())
    .bytes(5, o.idempotencyKey).bytes(6, content).concat();
};

export const decodeMessageAccepted = (data) => {
  const f = parseFields(data);
  return { messageId: get(f, 1), sequence: Number(get(f, 2) || 0n),
           serverTimestampMs: Number(get(f, 3) || 0n), duplicate: (get(f, 4) || 0n) === 1n };
};

export const decodeMessageIncoming = (data) => {
  const f = parseFields(data);
  const content = parseFields(get(f, 7) || new Uint8Array());
  return { messageId: get(f, 1), conversationId: get(f, 2), senderId: get(f, 3),
           sequence: Number(get(f, 5) || 0n), kind: Number(get(content, 1) || 0n),
           body: get(content, 2) || new Uint8Array() };
};

export const decodeSyncBatch = (data) => {
  const f = parseFields(data);
  const events = (f.get(2) || []).map((raw) => {
    const ev = parseFields(raw);
    return { type: Number(get(ev, 1) || 0n), sequence: Number(get(ev, 2) || 0n),
             message: get(ev, 3) ? decodeMessageIncoming(get(ev, 3)) : null };
  });
  return { conversationId: get(f, 1), events,
           hasMore: (get(f, 3) || 0n) === 1n,
           nextAfterSequence: Number(get(f, 4) || 0n) };
};

export const encodeSyncRequest = (o) => new Writer()
  .bytes(1, o.conversationId).uint(2, o.afterSequence || 0).uint(3, o.limit || 100).concat();

export const encodeSyncAck = (o) => new Writer()
  .bytes(1, o.conversationId).uint(2, o.appliedSequence || 0).concat();

export const encodeDeliveryAck = (o) => new Writer()
  .bytes(1, o.messageId).bytes(2, o.conversationId).uint(3, o.sequence || 0).concat();

// DeleteEvent: empty messageId means "clear the whole conversation".
export const encodeDeleteEvent = (o) => new Writer()
  .bytes(1, o.messageId || new Uint8Array()).bytes(2, o.conversationId)
  .uint(3, o.forEveryone === false ? 0 : 1).concat();

export const decodeDeleteEvent = (data) => {
  const f = parseFields(data);
  return { messageId: get(f, 1) || new Uint8Array(), conversationId: get(f, 2),
           forEveryone: (get(f, 3) || 0n) === 1n };
};

export const decodeError = (data) => {
  const f = parseFields(data);
  return { code: Number(get(f, 1) || 0n), message: text(get(f, 2)),
           retryable: (get(f, 3) || 0n) === 1n };
};

// --- hex helpers ---------------------------------------------------------------
const b64url = (bytes) => btoa(String.fromCharCode(...bytes))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Ed25519 signature over the HELLO session id. WebCrypto needs the public
 * key as well as the 32-byte seed (both come from account provisioning). */
export async function signChallenge(privateKeyRaw, publicKeyRaw, sessionId) {
  if (privateKeyRaw.length !== 32 || publicKeyRaw.length !== 32) {
    throw new FrameError("Ed25519 key material must be 32 bytes");
  }
  const key = await crypto.subtle.importKey("jwk", {
    kty: "OKP", crv: "Ed25519", x: b64url(publicKeyRaw), d: b64url(privateKeyRaw),
  }, { name: "Ed25519" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" }, key, new TextEncoder().encode(sessionId)));
}

export const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
export const fromHex = (hex) => new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
export const uuidBytes = () => crypto.getRandomValues(new Uint8Array(16));
