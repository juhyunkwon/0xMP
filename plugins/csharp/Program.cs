using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

/// <summary>Standalone 0xMP wire plugin for C#.</summary>
public static class OxmpPlugin
{
    public const int Version = 0x01;
    public const int MaxPayload = 1024 * 1024;
    public const int KnownFlags = 0x0001 | 0x0002 | 0x0004 | 0x0008;
    public const int Hello = 0x01, Auth = 0x02, AuthResultFrame = 0x03, HelloResult = 0x04;
    public const int MessageSend = 0x10, MessageAccepted = 0x11, MessageDelivered = 0x12;
    public const int MessageRead = 0x13, MessageEdit = 0x14, MessageDelete = 0x15;
    public const int MessageIncoming = 0x16, MessageDeliveryAck = 0x17;
    public const int SyncRequest = 0x20, SyncBatchFrame = 0x21, SyncAck = 0x22;
    public const int MediaInit = 0x30, MediaComplete = 0x31;
    public const int Ping = 0x40, Pong = 0x41;
    public const int KeyBundlePublish = 0x50, KeyBundleRequest = 0x51, KeyBundleResponse = 0x52;
    public const int Error = 0x7F;

    static readonly int[] Types = {
        Hello, Auth, AuthResultFrame, HelloResult, MessageSend, MessageAccepted, MessageDelivered,
        MessageRead, MessageEdit, MessageDelete, MessageIncoming, MessageDeliveryAck,
        SyncRequest, SyncBatchFrame, SyncAck, MediaInit, MediaComplete, Ping, Pong,
        KeyBundlePublish, KeyBundleRequest, KeyBundleResponse, Error};

    public sealed class FrameException : Exception
    {
        public FrameException(string message) : base(message) {}
    }

    public sealed record Frame(int Type, int Flags, byte[] Payload, byte[] Extension);
    public sealed record Incoming(byte[] MessageId, byte[] ConversationId, byte[] SenderId,
                                  long Sequence, int Kind, byte[] Body);
    public sealed record SyncEvent(int Type, long Sequence, Incoming Message);
    public sealed record SyncBatch(byte[] ConversationId, List<SyncEvent> Events,
                                   bool HasMore, long NextAfterSequence);
    public sealed record DeleteEvent(byte[] MessageId, byte[] ConversationId, bool ForEveryone);
    public sealed record AuthResult(bool Ok, byte[] UserId, byte[] DeviceId);
    public sealed record ProtocolError(long Code, string Message, bool Retryable);

    public static byte[] EncodeFrame(int type, byte[] payload, int flags, byte[] extension)
    {
        if (!Types.Contains(type)) throw new FrameException($"unknown frame type {type}");
        if ((flags & ~KnownFlags) != 0) throw new FrameException("reserved flag bits set");
        payload ??= Array.Empty<byte>();
        extension ??= Array.Empty<byte>();
        var body = payload;
        if (extension.Length > 0)
        {
            if (extension.Length > 65535) throw new FrameException("extension too long");
            flags |= 0x0004;
            body = new byte[2 + extension.Length + payload.Length];
            body[0] = (byte)(extension.Length >> 8);
            body[1] = (byte)extension.Length;
            Buffer.BlockCopy(extension, 0, body, 2, extension.Length);
            Buffer.BlockCopy(payload, 0, body, 2 + extension.Length, payload.Length);
        }
        if (body.Length > MaxPayload) throw new FrameException("payload exceeds hard cap");
        var outb = new byte[10 + body.Length];
        outb[0] = 0x4d; outb[1] = 0x50; outb[2] = Version; outb[3] = (byte)type;
        outb[4] = (byte)(flags >> 8); outb[5] = (byte)flags;
        outb[6] = (byte)(body.Length >> 24); outb[7] = (byte)(body.Length >> 16);
        outb[8] = (byte)(body.Length >> 8); outb[9] = (byte)body.Length;
        Buffer.BlockCopy(body, 0, outb, 10, body.Length);
        return outb;
    }

    public static Frame DecodeFrame(byte[] data)
    {
        if (data.Length < 10) throw new FrameException("frame shorter than fixed header");
        if (data[0] != 0x4d || data[1] != 0x50) throw new FrameException("bad magic");
        if (data[2] != Version) throw new FrameException("unsupported frame version");
        int type = data[3];
        int flags = (data[4] << 8) | data[5];
        ulong length = ((ulong)data[6] << 24) | ((ulong)data[7] << 16) | ((ulong)data[8] << 8) | data[9];
        if (length > MaxPayload) throw new FrameException("payload_length exceeds hard cap");
        if ((ulong)data.Length != 10 + length) throw new FrameException("frame length mismatch");
        if ((flags & ~KnownFlags) != 0) throw new FrameException("reserved flag bits set");
        if (!Types.Contains(type)) throw new FrameException($"unknown frame type {type}");
        var body = data[10..];
        var extension = Array.Empty<byte>();
        if ((flags & 0x0004) != 0)
        {
            if (body.Length < 2) throw new FrameException("extension header truncated");
            int extLen = (body[0] << 8) | body[1];
            if (body.Length < 2 + extLen) throw new FrameException("extension body truncated");
            extension = body[2..(2 + extLen)];
            body = body[(2 + extLen)..];
        }
        return new Frame(type, flags, body, extension);
    }

    public static byte[] EncodeHello(string protocolId)
    {
        var w = new W();
        w.Str(1, string.IsNullOrEmpty(protocolId) ? "0xmp.v1" : protocolId);
        return w.Concat();
    }

    public static byte[] SignChallenge(byte[] privateKeyRaw, string sessionId)
    {
        if (privateKeyRaw == null || privateKeyRaw.Length != 32)
            throw new FrameException("Ed25519 seed must be 32 bytes");
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKeyRaw, 0));
        var message = Encoding.UTF8.GetBytes(sessionId);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    public static byte[] EncodeAuth(string accessToken, byte[] deviceId, byte[] signature)
    {
        var w = new W();
        w.Str(1, accessToken).Bytes(2, deviceId).Bytes(4, signature);
        return w.Concat();
    }

    public static AuthResult DecodeAuthResult(byte[] data)
    {
        var f = FieldsOf(data);
        return new AuthResult(f.Num(1) == 1, f.Bytes(2), f.Bytes(3));
    }

    public static byte[] EncodeSyncRequest(byte[] conversationId, long afterSequence, int limit)
    {
        var w = new W();
        w.Bytes(1, conversationId).Uint(2, (ulong)afterSequence).Uint(3, (ulong)(limit == 0 ? 100 : limit));
        return w.Concat();
    }

    public static byte[] EncodeSyncAck(byte[] conversationId, long appliedSequence)
    {
        var w = new W();
        w.Bytes(1, conversationId).Uint(2, (ulong)appliedSequence);
        return w.Concat();
    }

    public static byte[] EncodeDeliveryAck(byte[] messageId, byte[] conversationId, long sequence)
    {
        var w = new W();
        w.Bytes(1, messageId).Bytes(2, conversationId).Uint(3, (ulong)sequence);
        return w.Concat();
    }

    public static ProtocolError DecodeError(byte[] data)
    {
        var f = FieldsOf(data);
        var raw = f.Bytes(2);
        return new ProtocolError(f.Num(1), raw == null ? "" : Encoding.UTF8.GetString(raw), f.Num(3) == 1);
    }

    public static byte[] EncodeMessageSend(byte[] messageId, byte[] conversationId,
        byte[] senderDeviceId, byte[] idempotencyKey, byte[] body, int kind, long clientTimestampMs)
    {
        if (kind == 0) kind = 1;
        if (clientTimestampMs == 0) clientTimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var content = new W();
        content.Uint(1, (ulong)kind);
        content.Bytes(2, body);
        var w = new W();
        w.Bytes(1, messageId).Bytes(2, conversationId).Bytes(3, senderDeviceId);
        w.Uint(4, (ulong)clientTimestampMs).Bytes(5, idempotencyKey).Bytes(6, content.Concat());
        return w.Concat();
    }

    public static long DecodeAcceptedSequence(byte[] data) => FieldsOf(data).Num(2);

    public static Incoming DecodeIncoming(byte[] data)
    {
        var f = FieldsOf(data);
        var content = FieldsOf(f.BytesOrEmpty(7));
        return new Incoming(f.Bytes(1), f.Bytes(2), f.Bytes(3), f.Num(5),
            (int)content.Num(1), content.BytesOrEmpty(2));
    }

    public static SyncBatch DecodeSyncBatch(byte[] data)
    {
        var f = FieldsOf(data);
        var events = new List<SyncEvent>();
        foreach (var raw in f.All(2))
        {
            var ev = FieldsOf(raw);
            var msg = ev.Bytes(3);
            events.Add(new SyncEvent((int)ev.Num(1), ev.Num(2), msg == null ? null : DecodeIncoming(msg)));
        }
        return new SyncBatch(f.Bytes(1), events, f.Num(3) == 1, f.Num(4));
    }

    public static byte[] EncodeDelete(byte[] conversationId, byte[] messageId, bool forEveryone)
    {
        var w = new W();
        w.Bytes(1, messageId).Bytes(2, conversationId).Uint(3, forEveryone ? 1u : 0u);
        return w.Concat();
    }

    public static DeleteEvent DecodeDelete(byte[] data)
    {
        var f = FieldsOf(data);
        return new DeleteEvent(f.BytesOrEmpty(1), f.Bytes(2), f.Num(3) == 1);
    }

    public static string ToHex(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    sealed class W
    {
        readonly List<byte> _out = new();
        public W Varint(ulong value)
        {
            while (true)
            {
                byte b = (byte)(value & 0x7f);
                value >>= 7;
                if (value != 0) b |= 0x80;
                _out.Add(b);
                if (value == 0) break;
            }
            return this;
        }
        public W Tag(int field, int wire) => Varint((ulong)((field << 3) | wire));
        public W Bytes(int field, byte[] data)
        {
            if (data == null || data.Length == 0) return this;
            Tag(field, 2); Varint((ulong)data.Length); _out.AddRange(data); return this;
        }
        public W Str(int field, string text) =>
            Bytes(field, string.IsNullOrEmpty(text) ? null : Encoding.UTF8.GetBytes(text));
        public W Uint(int field, ulong value)
        {
            if (value != 0) { Tag(field, 0); Varint(value); }
            return this;
        }
        public byte[] Concat() => _out.ToArray();
    }

    sealed class Fields
    {
        public readonly Dictionary<int, List<object>> Map = new();
        object Get(int n) => Map.TryGetValue(n, out var v) && v.Count > 0 ? v[0] : null;
        public long Num(int n) => Get(n) is ulong u ? (long)u : 0;
        public byte[] Bytes(int n) => Get(n) as byte[];
        public byte[] BytesOrEmpty(int n) => Bytes(n) ?? Array.Empty<byte>();
        public List<byte[]> All(int n)
        {
            var o = new List<byte[]>();
            if (Map.TryGetValue(n, out var v)) foreach (var item in v) if (item is byte[] b) o.Add(b);
            return o;
        }
    }

    static Fields FieldsOf(byte[] data)
    {
        var f = new Fields();
        int at = 0;
        while (at < data.Length)
        {
            var (tag, next) = ReadVarint(data, at);
            at = next;
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            object value;
            if (wire == 0) { var n = ReadVarint(data, at); at = n.Next; value = n.Value; }
            else if (wire == 2)
            {
                var n = ReadVarint(data, at); at = n.Next;
                int len = (int)n.Value;
                if (at + len > data.Length) throw new FrameException("truncated length-delimited field");
                value = data[at..(at + len)];
                at += len;
            }
            else if (wire == 5) { value = data[at..(at + 4)]; at += 4; }
            else if (wire == 1) { value = data[at..(at + 8)]; at += 8; }
            else throw new FrameException($"unsupported wire type {wire}");
            if (!f.Map.TryGetValue(field, out var list)) f.Map[field] = list = new List<object>();
            list.Add(value);
        }
        return f;
    }

    static (ulong Value, int Next) ReadVarint(byte[] data, int at)
    {
        int shift = 0;
        ulong result = 0;
        while (true)
        {
            if (at >= data.Length) throw new FrameException("truncated varint");
            byte b = data[at++];
            result |= (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0) return (result, at);
            shift += 7;
            if (shift > 63) throw new FrameException("varint too long");
        }
    }
}

public static class Program
{
    public static int Main()
    {
        string json = File.ReadAllText(Find());
        Eq(OxmpPlugin.ToHex(OxmpPlugin.EncodeFrame(OxmpPlugin.Ping, null, 0, null)), Hex(json, "ping_empty"));
        var hello = OxmpPlugin.EncodeFrame(OxmpPlugin.Hello, OxmpPlugin.EncodeHello("0xmp.v1"), 0, null);
        Eq(OxmpPlugin.ToHex(hello), Hex(json, "hello_protocol_only"));
        var ext = OxmpPlugin.EncodeFrame(OxmpPlugin.Ping, Encoding.ASCII.GetBytes("ab"), 0, Encoding.ASCII.GetBytes("xy"));
        Eq(OxmpPlugin.ToHex(ext), Hex(json, "ping_with_extension"));
        var decoded = OxmpPlugin.DecodeFrame(OxmpPlugin.FromHex(Hex(json, "ping_with_extension")));
        if (Encoding.ASCII.GetString(decoded.Extension) != "xy" || Encoding.ASCII.GetString(decoded.Payload) != "ab")
            throw new Exception("extension mismatch");
        var neg = json[json.IndexOf("\"negative_frames\"", StringComparison.Ordinal)..];
        int from = 0;
        while (true)
        {
            int h = neg.IndexOf("\"hex\": \"", from, StringComparison.Ordinal);
            if (h < 0) break;
            int start = h + 8;
            string value = neg[start..neg.IndexOf('"', start)];
            try { OxmpPlugin.DecodeFrame(OxmpPlugin.FromHex(value)); throw new Exception("accepted " + value); }
            catch (OxmpPlugin.FrameException) { }
            from = start;
        }
        if (OxmpPlugin.DecodeAcceptedSequence(OxmpPlugin.FromHex(Hex(json, "message_accepted_seq1"))) != 1)
            throw new Exception("accepted sequence");
        var body = new byte[18];
        Encoding.ASCII.GetBytes("cross-platform ").CopyTo(body, 0);
        body[15] = 0xE2; body[16] = 0x9C; body[17] = 0x93;
        var sent = OxmpPlugin.EncodeMessageSend(Range(0), Range(16), Range(32), Range(48), body, 1, 1700000000000L);
        Eq(OxmpPlugin.ToHex(sent), Hex(json, "message_send_fixed_ids"));
        var batch = OxmpPlugin.DecodeSyncBatch(OxmpPlugin.FromHex(Hex(json, "sync_batch_one_text")));
        if (batch.HasMore || batch.NextAfterSequence != 1 || batch.Events.Count != 1 || batch.Events[0].Sequence != 1)
            throw new Exception("sync shape");
        if (Encoding.UTF8.GetString(batch.Events[0].Message.Body) != "room history")
            throw new Exception("sync body");
        var room = new byte[16]; Array.Fill(room, (byte)0x11);
        var deleted = OxmpPlugin.DecodeDelete(OxmpPlugin.EncodeDelete(room, null, true));
        if (!deleted.ForEveryone || deleted.MessageId.Length != 0) throw new Exception("delete");
        Eq(OxmpPlugin.ToHex(OxmpPlugin.EncodeAuth("token", Range(0), Range(16))),
            "0a05746f6b656e1210000102030405060708090a0b0c0d0e0f2210101112131415161718191a1b1c1d1e1f");
        if (!OxmpPlugin.DecodeAuthResult(new byte[] { 0x08, 0x01 }).Ok) throw new Exception("auth result");
        Eq(OxmpPlugin.ToHex(OxmpPlugin.EncodeSyncRequest(Range(0), 7, 100)),
            "0a10000102030405060708090a0b0c0d0e0f10071864");
        Eq(OxmpPlugin.ToHex(OxmpPlugin.EncodeSyncAck(Range(0), 7)),
            "0a10000102030405060708090a0b0c0d0e0f1007");
        Eq(OxmpPlugin.ToHex(OxmpPlugin.EncodeDeliveryAck(Range(0), Range(16), 9)),
            "0a10000102030405060708090a0b0c0d0e0f1210101112131415161718191a1b1c1d1e1f1809");
        Eq(OxmpPlugin.ToHex(OxmpPlugin.SignChallenge(Range(0, 32), "0xmp-challenge")),
            "b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b2360" +
            "6fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e");
        Console.WriteLine("csharp plugin: test_vectors.json OK");
        return 0;
    }

    static byte[] Range(int start, int len = 16) { var b = new byte[len]; for (int i = 0; i < len; i++) b[i] = (byte)(start + i); return b; }
    static string Find()
    {
        foreach (var c in new[] { "clients/test_vectors.json", "../../clients/test_vectors.json" })
            if (File.Exists(c)) return c;
        throw new Exception("clients/test_vectors.json not found");
    }
    static string Hex(string json, string name)
    {
        int at = json.IndexOf("\"name\": \"" + name + "\"", StringComparison.Ordinal);
        int h = json.IndexOf("\"hex\": \"", at, StringComparison.Ordinal) + 8;
        return json[h..json.IndexOf('"', h)];
    }
    static void Eq(string actual, string expected)
    {
        if (actual != expected) throw new Exception($"mismatch\n actual {actual}\n expect {expected}");
    }
}
