<?php
/** Standalone 0xMP wire plugin for PHP. */

const OXMP_VERSION = 0x01;
const OXMP_MAX_PAYLOAD = 1024 * 1024;
const OXMP_KNOWN_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0008;
const OXMP_TYPES = [
    0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x20, 0x21, 0x22, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51, 0x52, 0x7F,
];

class OxmpFrameError extends RuntimeException {}

final class OxmpWriter {
    public string $buf = '';
    public function varint(int $value): self {
        while (true) {
            $b = $value & 0x7F;
            $value >>= 7;
            if ($value) $b |= 0x80;
            $this->buf .= chr($b);
            if (!$value) break;
        }
        return $this;
    }
    public function tag(int $field, int $wire): self { return $this->varint(($field << 3) | $wire); }
    public function bytes(int $field, string $data): self {
        if ($data === '') return $this;
        $this->tag($field, 2)->varint(strlen($data));
        $this->buf .= $data;
        return $this;
    }
    public function str(int $field, string $text): self { return $this->bytes($field, $text); }
    public function uint(int $field, int $value): self {
        if ($value) $this->tag($field, 0)->varint($value);
        return $this;
    }
}

function oxmp_parse_fields(string $data): array {
    $fields = [];
    $at = 0;
    $len = strlen($data);
    $read = function () use (&$data, &$at, $len): int {
        $shift = 0; $result = 0;
        while (true) {
            if ($at >= $len) throw new OxmpFrameError('truncated varint');
            $b = ord($data[$at++]);
            $result |= ($b & 0x7F) << $shift;
            if (($b & 0x80) === 0) return $result;
            $shift += 7;
            if ($shift > 63) throw new OxmpFrameError('varint too long');
        }
    };
    while ($at < $len) {
        $tag = $read();
        $field = $tag >> 3; $wire = $tag & 7;
        if ($wire === 0) $value = $read();
        elseif ($wire === 2) {
            $n = $read();
            if ($at + $n > $len) throw new OxmpFrameError('truncated length-delimited field');
            $value = substr($data, $at, $n); $at += $n;
        } elseif ($wire === 5) { $value = substr($data, $at, 4); $at += 4; }
        elseif ($wire === 1) { $value = substr($data, $at, 8); $at += 8; }
        else throw new OxmpFrameError("unsupported wire type $wire");
        $fields[$field][] = $value;
    }
    return $fields;
}

function oxmp_get(array $fields, int $n) { return $fields[$n][0] ?? null; }

function oxmp_encode_frame(int $type, string $payload = '', int $flags = 0, string $extension = ''): string {
    if (!in_array($type, OXMP_TYPES, true)) throw new OxmpFrameError("unknown frame type $type");
    if ($flags & ~OXMP_KNOWN_FLAGS) throw new OxmpFrameError('reserved flag bits set');
    $body = $payload;
    if ($extension !== '') {
        if (strlen($extension) > 65535) throw new OxmpFrameError('extension too long');
        $flags |= 0x0004;
        $body = pack('n', strlen($extension)) . $extension . $payload;
    }
    if (strlen($body) > OXMP_MAX_PAYLOAD) throw new OxmpFrameError('payload exceeds hard cap');
    return pack('C4', 0x4d, 0x50, OXMP_VERSION, $type) . pack('n', $flags) . pack('N', strlen($body)) . $body;
}

function oxmp_decode_frame(string $data): array {
    if (strlen($data) < 10) throw new OxmpFrameError('frame shorter than fixed header');
    if ($data[0] !== "\x4d" || $data[1] !== "\x50") throw new OxmpFrameError('bad magic');
    if (ord($data[2]) !== OXMP_VERSION) throw new OxmpFrameError('unsupported frame version');
    $type = ord($data[3]);
    $flags = unpack('n', substr($data, 4, 2))[1];
    $length = unpack('N', substr($data, 6, 4))[1];
    if ($length > OXMP_MAX_PAYLOAD) throw new OxmpFrameError('payload_length exceeds hard cap');
    if (strlen($data) !== 10 + $length) throw new OxmpFrameError('frame length mismatch');
    if ($flags & ~OXMP_KNOWN_FLAGS) throw new OxmpFrameError('reserved flag bits set');
    if (!in_array($type, OXMP_TYPES, true)) throw new OxmpFrameError("unknown frame type $type");
    $body = substr($data, 10);
    $extension = '';
    if ($flags & 0x0004) {
        if (strlen($body) < 2) throw new OxmpFrameError('extension header truncated');
        $extLen = unpack('n', substr($body, 0, 2))[1];
        if (strlen($body) < 2 + $extLen) throw new OxmpFrameError('extension body truncated');
        $extension = substr($body, 2, $extLen);
        $body = substr($body, 2 + $extLen);
    }
    return ['type' => $type, 'flags' => $flags, 'payload' => $body, 'extension' => $extension];
}

function oxmp_encode_hello(string $protocolId = '0xmp.v1'): string {
    $w = new OxmpWriter();
    $w->str(1, $protocolId !== '' ? $protocolId : '0xmp.v1');
    return $w->buf;
}

function oxmp_sign_challenge(string $privateKeyRaw, string $sessionId): string {
    if (strlen($privateKeyRaw) !== 32) {
        throw new OxmpFrameError('Ed25519 seed must be 32 bytes');
    }
    if (!function_exists('sodium_crypto_sign_seed_keypair')) {
        throw new OxmpFrameError(
            'Ed25519 signing needs the sodium extension. Enable it with php -d extension=sodium');
    }
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($privateKeyRaw));
    return sodium_crypto_sign_detached($sessionId, $secret);
}

function oxmp_encode_auth(string $accessToken, string $deviceId, string $signature): string {
    $w = new OxmpWriter();
    $w->str(1, $accessToken)->bytes(2, $deviceId)->bytes(4, $signature);
    return $w->buf;
}

function oxmp_decode_auth_result(string $data): array {
    $f = oxmp_parse_fields($data);
    return ['ok' => (oxmp_get($f, 1) ?? 0) === 1, 'user_id' => oxmp_get($f, 2), 'device_id' => oxmp_get($f, 3)];
}

function oxmp_encode_sync_request(string $conversationId, int $afterSequence = 0, int $limit = 100): string {
    $w = new OxmpWriter();
    $w->bytes(1, $conversationId)->uint(2, $afterSequence)->uint(3, $limit ?: 100);
    return $w->buf;
}

function oxmp_encode_sync_ack(string $conversationId, int $appliedSequence): string {
    $w = new OxmpWriter();
    $w->bytes(1, $conversationId)->uint(2, $appliedSequence);
    return $w->buf;
}

function oxmp_encode_delivery_ack(string $messageId, string $conversationId, int $sequence): string {
    $w = new OxmpWriter();
    $w->bytes(1, $messageId)->bytes(2, $conversationId)->uint(3, $sequence);
    return $w->buf;
}

function oxmp_encode_message_send(string $messageId, string $conversationId, string $senderDeviceId,
    string $idempotencyKey, string $body, int $kind = 1, int $clientTimestampMs = 0): string {
    if (!$kind) $kind = 1;
    if (!$clientTimestampMs) $clientTimestampMs = (int) (microtime(true) * 1000);
    $content = new OxmpWriter();
    $content->uint(1, $kind)->bytes(2, $body);
    $w = new OxmpWriter();
    $w->bytes(1, $messageId)->bytes(2, $conversationId)->bytes(3, $senderDeviceId)
      ->uint(4, $clientTimestampMs)->bytes(5, $idempotencyKey)->bytes(6, $content->buf);
    return $w->buf;
}

function oxmp_decode_incoming(string $data): array {
    $f = oxmp_parse_fields($data);
    $content = oxmp_parse_fields(oxmp_get($f, 7) ?? '');
    return [
        'message_id' => oxmp_get($f, 1), 'conversation_id' => oxmp_get($f, 2),
        'sender_id' => oxmp_get($f, 3), 'sequence' => (int) (oxmp_get($f, 5) ?? 0),
        'kind' => (int) (oxmp_get($content, 1) ?? 0), 'body' => oxmp_get($content, 2) ?? '',
    ];
}

function oxmp_decode_sync_batch(string $data): array {
    $f = oxmp_parse_fields($data);
    $events = [];
    foreach ($f[2] ?? [] as $raw) {
        $ev = oxmp_parse_fields($raw);
        $msg = oxmp_get($ev, 3);
        $events[] = [
            'type' => (int) (oxmp_get($ev, 1) ?? 0),
            'sequence' => (int) (oxmp_get($ev, 2) ?? 0),
            'message' => $msg !== null ? oxmp_decode_incoming($msg) : null,
        ];
    }
    return [
        'conversation_id' => oxmp_get($f, 1), 'events' => $events,
        'has_more' => (oxmp_get($f, 3) ?? 0) === 1,
        'next_after_sequence' => (int) (oxmp_get($f, 4) ?? 0),
    ];
}

function oxmp_encode_delete(string $conversationId, string $messageId = '', bool $forEveryone = true): string {
    $w = new OxmpWriter();
    $w->bytes(1, $messageId)->bytes(2, $conversationId)->uint(3, $forEveryone ? 1 : 0);
    return $w->buf;
}
