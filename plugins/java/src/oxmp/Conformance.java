package oxmp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Checks this plugin against clients/test_vectors.json. */
public final class Conformance {
    public static void main(String[] args) throws Exception {
        String json = Files.readString(findVectors());
        eq(OxmpPlugin.toHex(OxmpPlugin.encodeFrame(OxmpPlugin.PING, null, 0, null)),
                hex(json, "ping_empty"), "ping");
        byte[] hello = OxmpPlugin.encodeFrame(OxmpPlugin.HELLO, OxmpPlugin.encodeHello("0xmp.v1"), 0, null);
        eq(OxmpPlugin.toHex(hello), hex(json, "hello_protocol_only"), "hello");
        if (OxmpPlugin.decodeFrame(hello).type() != OxmpPlugin.HELLO) fail("hello type");
        byte[] ext = OxmpPlugin.encodeFrame(OxmpPlugin.PING, "ab".getBytes(StandardCharsets.US_ASCII),
                0, "xy".getBytes(StandardCharsets.US_ASCII));
        eq(OxmpPlugin.toHex(ext), hex(json, "ping_with_extension"), "extension");
        OxmpPlugin.Frame decoded = OxmpPlugin.decodeFrame(OxmpPlugin.fromHex(hex(json, "ping_with_extension")));
        eq(new String(decoded.extension(), StandardCharsets.US_ASCII), "xy", "ext");
        eq(new String(decoded.payload(), StandardCharsets.US_ASCII), "ab", "payload");
        int negAt = json.indexOf("\"negative_frames\"");
        String neg = json.substring(negAt);
        int from = 0;
        while (true) {
            int h = neg.indexOf("\"hex\": \"", from);
            if (h < 0) break;
            int start = h + 8;
            String value = neg.substring(start, neg.indexOf('"', start));
            try {
                OxmpPlugin.decodeFrame(OxmpPlugin.fromHex(value));
                fail("negative frame was accepted: " + value);
            } catch (OxmpPlugin.FrameException expected) { /* rejected */ }
            from = start;
        }
        if (OxmpPlugin.decodeAcceptedSequence(OxmpPlugin.fromHex(hex(json, "message_accepted_seq1"))) != 1)
            fail("accepted sequence");
        byte[] body = new byte[18];
        System.arraycopy("cross-platform ".getBytes(StandardCharsets.US_ASCII), 0, body, 0, 15);
        body[15] = (byte) 0xE2; body[16] = (byte) 0x9C; body[17] = (byte) 0x93;
        byte[] sent = OxmpPlugin.encodeMessageSend(range(0, 16), range(16, 16), range(32, 16),
                range(48, 16), body, 1, 1700000000000L);
        eq(OxmpPlugin.toHex(sent), hex(json, "message_send_fixed_ids"), "message send");
        OxmpPlugin.SyncBatch batch = OxmpPlugin.decodeSyncBatch(
                OxmpPlugin.fromHex(hex(json, "sync_batch_one_text")));
        if (batch.hasMore() || batch.nextAfterSequence() != 1 || batch.events().size() != 1)
            fail("sync batch shape");
        if (batch.events().get(0).sequence() != 1) fail("sync sequence");
        eq(new String(batch.events().get(0).message().body(), StandardCharsets.UTF_8),
                "room history", "sync body");
        byte[] room = new byte[16];
        java.util.Arrays.fill(room, (byte) 0x11);
        OxmpPlugin.DeleteEvent deleted = OxmpPlugin.decodeDelete(OxmpPlugin.encodeDelete(room, null, true));
        if (!deleted.forEveryone() || deleted.messageId().length != 0) fail("delete");
        byte[] auth = OxmpPlugin.encodeAuth("token", range(0, 16), range(16, 16));
        eq(OxmpPlugin.toHex(auth),
                "0a05746f6b656e1210000102030405060708090a0b0c0d0e0f2210101112131415161718191a1b1c1d1e1f",
                "auth");
        OxmpPlugin.AuthResult ok = OxmpPlugin.decodeAuthResult(new byte[] {0x08, 0x01});
        if (!ok.ok()) fail("auth result");
        eq(OxmpPlugin.toHex(OxmpPlugin.encodeSyncRequest(range(0, 16), 7, 100)),
                "0a10000102030405060708090a0b0c0d0e0f10071864", "sync request");
        eq(OxmpPlugin.toHex(OxmpPlugin.encodeSyncAck(range(0, 16), 7)),
                "0a10000102030405060708090a0b0c0d0e0f1007", "sync ack");
        eq(OxmpPlugin.toHex(OxmpPlugin.encodeDeliveryAck(range(0, 16), range(16, 16), 9)),
                "0a10000102030405060708090a0b0c0d0e0f1210101112131415161718191a1b1c1d1e1f1809",
                "delivery ack");
        eq(OxmpPlugin.toHex(OxmpPlugin.signChallenge(range(0, 32), "0xmp-challenge")),
                "b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b2360"
                        + "6fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e",
                "ed25519");
        System.out.println("java plugin: test_vectors.json OK");
    }

    private static byte[] range(int start, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) (start + i);
        return out;
    }

    private static Path findVectors() {
        String[] cands = {"clients/test_vectors.json", "../../clients/test_vectors.json"};
        for (String c : cands) if (Files.isRegularFile(Path.of(c))) return Path.of(c);
        throw new IllegalStateException("clients/test_vectors.json not found");
    }

    private static String hex(String json, String name) {
        int at = json.indexOf("\"name\": \"" + name + "\"");
        if (at < 0) fail("missing " + name);
        int h = json.indexOf("\"hex\": \"", at) + 8;
        return json.substring(h, json.indexOf('"', h));
    }

    private static void eq(String actual, String expected, String label) {
        if (!actual.equals(expected)) fail(label + "\n actual " + actual + "\n expect " + expected);
    }

    private static void fail(String message) { throw new AssertionError(message); }
}
