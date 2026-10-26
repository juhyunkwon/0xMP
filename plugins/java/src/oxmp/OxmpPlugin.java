package oxmp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Standalone 0xMP wire plugin (frame header + client Protobuf messages). */
public final class OxmpPlugin {
    public static final int VERSION = 0x01;
    public static final int MAX_PAYLOAD = 1024 * 1024;
    public static final int KNOWN_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0008;

    public static final int HELLO = 0x01, AUTH = 0x02, AUTH_RESULT = 0x03, HELLO_RESULT = 0x04;
    public static final int MESSAGE_SEND = 0x10, MESSAGE_ACCEPTED = 0x11, MESSAGE_DELIVERED = 0x12;
    public static final int MESSAGE_READ = 0x13, MESSAGE_EDIT = 0x14, MESSAGE_DELETE = 0x15;
    public static final int MESSAGE_INCOMING = 0x16, MESSAGE_DELIVERY_ACK = 0x17;
    public static final int SYNC_REQUEST = 0x20, SYNC_BATCH = 0x21, SYNC_ACK = 0x22;
    public static final int MEDIA_INIT = 0x30, MEDIA_COMPLETE = 0x31;
    public static final int PING = 0x40, PONG = 0x41;
    public static final int KEY_BUNDLE_PUBLISH = 0x50, KEY_BUNDLE_REQUEST = 0x51, KEY_BUNDLE_RESPONSE = 0x52;
    public static final int ERROR = 0x7F;

    private static final int[] TYPES = {
        HELLO, AUTH, AUTH_RESULT, HELLO_RESULT, MESSAGE_SEND, MESSAGE_ACCEPTED,
        MESSAGE_DELIVERED, MESSAGE_READ, MESSAGE_EDIT, MESSAGE_DELETE, MESSAGE_INCOMING,
        MESSAGE_DELIVERY_ACK, SYNC_REQUEST, SYNC_BATCH, SYNC_ACK, MEDIA_INIT, MEDIA_COMPLETE,
        PING, PONG, KEY_BUNDLE_PUBLISH, KEY_BUNDLE_REQUEST, KEY_BUNDLE_RESPONSE, ERROR};

    public static final class FrameException extends RuntimeException {
        public FrameException(String message) { super(message); }
    }

    public record Frame(int type, int flags, byte[] payload, byte[] extension) {}
    public record Incoming(byte[] messageId, byte[] conversationId, byte[] senderId,
                           long sequence, int kind, byte[] body) {}
    public record SyncEvent(int type, long sequence, Incoming message) {}
    public record SyncBatch(byte[] conversationId, List<SyncEvent> events,
                            boolean hasMore, long nextAfterSequence) {}
    public record DeleteEvent(byte[] messageId, byte[] conversationId, boolean forEveryone) {}
    public record AuthResult(boolean ok, byte[] userId, byte[] deviceId) {}
    public record HelloResult(String protocolId, long selectedProfile, long maxPayload, String sessionId) {}
    public record Accepted(byte[] messageId, long sequence, long serverTimestampMs, boolean duplicate) {}
    public record ProtocolError(long code, String message, boolean retryable) {}

    private OxmpPlugin() {}

    private static boolean known(int type) {
        for (int t : TYPES) if (t == type) return true;
        return false;
    }

    public static byte[] encodeFrame(int type, byte[] payload, int flags, byte[] extension) {
        if (!known(type)) throw new FrameException("unknown frame type " + type);
        if ((flags & ~KNOWN_FLAGS) != 0) throw new FrameException("reserved flag bits set");
        payload = payload == null ? new byte[0] : payload;
        extension = extension == null ? new byte[0] : extension;
        byte[] body = payload;
        if (extension.length > 0) {
            if (extension.length > 65535) throw new FrameException("extension too long");
            flags |= 0x0004;
            body = new byte[2 + extension.length + payload.length];
            body[0] = (byte) (extension.length >> 8);
            body[1] = (byte) extension.length;
            System.arraycopy(extension, 0, body, 2, extension.length);
            System.arraycopy(payload, 0, body, 2 + extension.length, payload.length);
        }
        if (body.length > MAX_PAYLOAD) throw new FrameException("payload exceeds hard cap");
        byte[] out = new byte[10 + body.length];
        out[0] = 0x4d; out[1] = 0x50; out[2] = VERSION; out[3] = (byte) type;
        out[4] = (byte) (flags >> 8); out[5] = (byte) flags;
        out[6] = (byte) (body.length >>> 24); out[7] = (byte) (body.length >>> 16);
        out[8] = (byte) (body.length >>> 8); out[9] = (byte) body.length;
        System.arraycopy(body, 0, out, 10, body.length);
        return out;
    }

    public static Frame decodeFrame(byte[] data) {
        if (data.length < 10) throw new FrameException("frame shorter than fixed header");
        if ((data[0] & 255) != 0x4d || (data[1] & 255) != 0x50) throw new FrameException("bad magic");
        if ((data[2] & 255) != VERSION) throw new FrameException("unsupported frame version");
        int type = data[3] & 255;
        int flags = ((data[4] & 255) << 8) | (data[5] & 255);
        long length = u32(data, 6);
        if (length > MAX_PAYLOAD) throw new FrameException("payload_length exceeds hard cap");
        if (data.length != 10 + length) throw new FrameException("frame length mismatch");
        if ((flags & ~KNOWN_FLAGS) != 0) throw new FrameException("reserved flag bits set");
        if (!known(type)) throw new FrameException("unknown frame type " + type);
        byte[] body = slice(data, 10, (int) length);
        byte[] extension = new byte[0];
        if ((flags & 0x0004) != 0) {
            if (body.length < 2) throw new FrameException("extension header truncated");
            int extLen = ((body[0] & 255) << 8) | (body[1] & 255);
            if (body.length < 2 + extLen) throw new FrameException("extension body truncated");
            extension = slice(body, 2, extLen);
            body = slice(body, 2 + extLen, body.length - 2 - extLen);
        }
        return new Frame(type, flags, body, extension);
    }

    public static byte[] encodeHello(String protocolId) {
        W w = new W();
        w.str(1, protocolId == null || protocolId.isEmpty() ? "0xmp.v1" : protocolId);
        return w.concat();
    }

    /** Ed25519 signature over the HELLO session id. Seed is 32 raw bytes. */
    public static byte[] signChallenge(byte[] privateKeyRaw, String sessionId) {
        if (privateKeyRaw == null || privateKeyRaw.length != 32) {
            throw new FrameException("Ed25519 seed must be 32 bytes");
        }
        byte[] prefix = fromHex("302e020100300506032b657004220420");
        byte[] pkcs8 = new byte[prefix.length + 32];
        System.arraycopy(prefix, 0, pkcs8, 0, prefix.length);
        System.arraycopy(privateKeyRaw, 0, pkcs8, prefix.length, 32);
        try {
            var key = java.security.KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
            var sig = java.security.Signature.getInstance("Ed25519");
            sig.initSign(key);
            sig.update(sessionId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return sig.sign();
        } catch (java.security.GeneralSecurityException exc) {
            throw new FrameException(exc.getMessage());
        }
    }

    /** AUTH payload: access token, device id, signature over the HELLO challenge. */
    public static byte[] encodeAuth(String accessToken, byte[] deviceId, byte[] signature) {
        W w = new W();
        w.str(1, accessToken).bytes(2, deviceId).bytes(4, signature);
        return w.concat();
    }

    public static AuthResult decodeAuthResult(byte[] data) {
        Fields f = fields(data);
        return new AuthResult(f.num(1) == 1, f.bytes(2), f.bytes(3));
    }

    public static HelloResult decodeHelloResult(byte[] data) {
        Fields f = fields(data);
        return new HelloResult(text(f.bytes(1)), f.num(2), f.num(4), text(f.bytes(5)));
    }

    public static byte[] encodeSyncRequest(byte[] conversationId, long afterSequence, int limit) {
        W w = new W();
        w.bytes(1, conversationId).uint(2, afterSequence).uint(3, limit == 0 ? 100 : limit);
        return w.concat();
    }

    public static byte[] encodeSyncAck(byte[] conversationId, long appliedSequence) {
        W w = new W();
        w.bytes(1, conversationId).uint(2, appliedSequence);
        return w.concat();
    }

    public static byte[] encodeDeliveryAck(byte[] messageId, byte[] conversationId, long sequence) {
        W w = new W();
        w.bytes(1, messageId).bytes(2, conversationId).uint(3, sequence);
        return w.concat();
    }

    public static Accepted decodeAccepted(byte[] data) {
        Fields f = fields(data);
        return new Accepted(f.bytes(1), f.num(2), f.num(3), f.num(4) == 1);
    }

    public static ProtocolError decodeError(byte[] data) {
        Fields f = fields(data);
        return new ProtocolError(f.num(1), text(f.bytes(2)), f.num(3) == 1);
    }

    private static String text(byte[] data) {
        return data == null ? "" : new String(data, java.nio.charset.StandardCharsets.UTF_8);
    }

    public static byte[] encodeMessageSend(byte[] messageId, byte[] conversationId,
                                           byte[] senderDeviceId, byte[] idempotencyKey,
                                           byte[] body, int kind, long clientTimestampMs) {
        if (kind == 0) kind = 1;
        if (clientTimestampMs == 0) clientTimestampMs = System.currentTimeMillis();
        W content = new W();
        content.uint(1, kind);
        content.bytes(2, body);
        W w = new W();
        w.bytes(1, messageId).bytes(2, conversationId).bytes(3, senderDeviceId);
        w.uint(4, clientTimestampMs).bytes(5, idempotencyKey).bytes(6, content.concat());
        return w.concat();
    }

    public static long decodeAcceptedSequence(byte[] data) {
        return fields(data).num(2);
    }

    public static Incoming decodeIncoming(byte[] data) {
        Fields f = fields(data);
        Fields content = fields(f.bytesOrEmpty(7));
        return new Incoming(f.bytes(1), f.bytes(2), f.bytes(3), f.num(5),
                (int) content.num(1), content.bytesOrEmpty(2));
    }

    public static SyncBatch decodeSyncBatch(byte[] data) {
        Fields f = fields(data);
        List<SyncEvent> events = new ArrayList<>();
        for (byte[] raw : f.all(2)) {
            Fields ev = fields(raw);
            byte[] msg = ev.bytes(3);
            events.add(new SyncEvent((int) ev.num(1), ev.num(2),
                    msg == null ? null : decodeIncoming(msg)));
        }
        return new SyncBatch(f.bytes(1), events, f.num(3) == 1, f.num(4));
    }

    public static byte[] encodeDelete(byte[] conversationId, byte[] messageId, boolean forEveryone) {
        W w = new W();
        w.bytes(1, messageId).bytes(2, conversationId).uint(3, forEveryone ? 1 : 0);
        return w.concat();
    }

    public static DeleteEvent decodeDelete(byte[] data) {
        Fields f = fields(data);
        return new DeleteEvent(f.bytesOrEmpty(1), f.bytes(2), f.num(3) == 1);
    }

    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b & 255));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    private static long u32(byte[] d, int o) {
        return ((d[o] & 255L) << 24) | ((d[o + 1] & 255L) << 16)
                | ((d[o + 2] & 255L) << 8) | (d[o + 3] & 255L);
    }

    private static byte[] slice(byte[] d, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(d, off, out, 0, len);
        return out;
    }

    private static final class W {
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        W varint(long value) {
            while (true) {
                int b = (int) (value & 0x7f);
                value >>>= 7;
                if (value != 0) b |= 0x80;
                out.write(b);
                if (value == 0) break;
            }
            return this;
        }
        W tag(int field, int wire) { return varint((((long) field) << 3) | wire); }
        W bytes(int field, byte[] data) {
            if (data == null || data.length == 0) return this;
            tag(field, 2); varint(data.length); out.write(data, 0, data.length); return this;
        }
        W str(int field, String text) {
            return bytes(field, text == null ? null : text.getBytes(StandardCharsets.UTF_8));
        }
        W uint(int field, long value) {
            if (value != 0) { tag(field, 0); varint(value); }
            return this;
        }
        byte[] concat() { return out.toByteArray(); }
    }

    private static final class Fields {
        final Map<Integer, List<Object>> map = new LinkedHashMap<>();
        Object get(int n) {
            List<Object> v = map.get(n);
            return (v == null || v.isEmpty()) ? null : v.get(0);
        }
        long num(int n) {
            Object o = get(n);
            return o instanceof Long ? (Long) o : 0L;
        }
        byte[] bytes(int n) {
            Object o = get(n);
            return o instanceof byte[] ? (byte[]) o : null;
        }
        byte[] bytesOrEmpty(int n) {
            byte[] b = bytes(n);
            return b == null ? new byte[0] : b;
        }
        List<byte[]> all(int n) {
            List<byte[]> out = new ArrayList<>();
            List<Object> v = map.get(n);
            if (v != null) for (Object o : v) if (o instanceof byte[]) out.add((byte[]) o);
            return out;
        }
    }

    private static Fields fields(byte[] data) {
        Fields f = new Fields();
        int at = 0;
        while (at < data.length) {
            long[] tagBox = readVarint(data, at);
            at = (int) tagBox[1];
            int field = (int) (tagBox[0] >> 3);
            int wire = (int) (tagBox[0] & 7);
            Object value;
            if (wire == 0) {
                long[] n = readVarint(data, at);
                at = (int) n[1];
                value = n[0];
            } else if (wire == 2) {
                long[] n = readVarint(data, at);
                at = (int) n[1];
                int len = (int) n[0];
                if (at + len > data.length) throw new FrameException("truncated length-delimited field");
                value = slice(data, at, len);
                at += len;
            } else if (wire == 5) {
                value = slice(data, at, 4); at += 4;
            } else if (wire == 1) {
                value = slice(data, at, 8); at += 8;
            } else throw new FrameException("unsupported wire type " + wire);
            f.map.computeIfAbsent(field, k -> new ArrayList<>()).add(value);
        }
        return f;
    }

    private static long[] readVarint(byte[] data, int at) {
        int shift = 0;
        long result = 0;
        while (true) {
            if (at >= data.length) throw new FrameException("truncated varint");
            int b = data[at++] & 255;
            result |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) return new long[] {result, at};
            shift += 7;
            if (shift > 63) throw new FrameException("varint too long");
        }
    }
}
