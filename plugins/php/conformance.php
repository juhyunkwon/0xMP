<?php
if (!extension_loaded('sodium') && getenv('OXMP_PHP_SODIUM_RETRY') !== '1') {
    putenv('OXMP_PHP_SODIUM_RETRY=1');
    $command = escapeshellarg(PHP_BINARY) . ' -d extension=sodium ' . escapeshellarg(__FILE__);
    passthru($command, $exitCode);
    exit($exitCode);
}
require __DIR__ . '/oxmp.php';

$json = file_get_contents(dirname(__DIR__, 2) . '/clients/test_vectors.json');
$doc = json_decode($json, true);
$byName = [];
foreach (['frames', 'payloads', 'negative_frames'] as $section)
    foreach ($doc[$section] as $item) $byName[$item['name']] = $item['hex'];

function fail(string $m): void { fwrite(STDERR, $m . PHP_EOL); exit(1); }
function eq(string $a, string $b, string $label): void {
    if ($a !== $b) fail("$label\n actual $a\n expect $b");
}

eq(bin2hex(oxmp_encode_frame(0x40)), $byName['ping_empty'], 'ping');
$hello = oxmp_encode_frame(0x01, oxmp_encode_hello());
eq(bin2hex($hello), $byName['hello_protocol_only'], 'hello');
if (oxmp_decode_frame($hello)['type'] !== 0x01) fail('hello type');
$ext = oxmp_encode_frame(0x40, 'ab', 0, 'xy');
eq(bin2hex($ext), $byName['ping_with_extension'], 'extension');
$decoded = oxmp_decode_frame(hex2bin($byName['ping_with_extension']));
if ($decoded['extension'] !== 'xy' || $decoded['payload'] !== 'ab') fail('extension payload');
foreach ($doc['negative_frames'] as $item) {
    try { oxmp_decode_frame(hex2bin($item['hex'])); fail('accepted ' . $item['name']); }
    catch (OxmpFrameError $e) {}
}
$accepted = oxmp_parse_fields(hex2bin($byName['message_accepted_seq1']));
if ((oxmp_get($accepted, 2) ?? 0) !== 1) fail('accepted sequence');
$body = 'cross-platform ' . hex2bin('e29c93');
$sent = oxmp_encode_message_send(
    implode('', array_map('chr', range(0, 15))),
    implode('', array_map('chr', range(16, 31))),
    implode('', array_map('chr', range(32, 47))),
    implode('', array_map('chr', range(48, 63))),
    $body, 1, 1700000000000);
eq(bin2hex($sent), $byName['message_send_fixed_ids'], 'message send');
$batch = oxmp_decode_sync_batch(hex2bin($byName['sync_batch_one_text']));
if ($batch['has_more'] || $batch['next_after_sequence'] !== 1 || count($batch['events']) !== 1)
    fail('sync shape');
if ($batch['events'][0]['sequence'] !== 1 || $batch['events'][0]['message']['body'] !== 'room history')
    fail('sync body');
$deleted = oxmp_parse_fields(oxmp_encode_delete(str_repeat("\x11", 16)));
if ((oxmp_get($deleted, 3) ?? 0) !== 1 || oxmp_get($deleted, 1) !== null) fail('delete');
$span = function (int $start): string {
    return implode('', array_map('chr', range($start, $start + 15)));
};
eq(bin2hex(oxmp_encode_auth('token', $span(0), $span(16))),
    '0a05746f6b656e1210000102030405060708090a0b0c0d0e0f2210101112131415161718191a1b1c1d1e1f', 'auth');
if (!oxmp_decode_auth_result("\x08\x01")['ok']) fail('auth result');
eq(bin2hex(oxmp_encode_sync_request($span(0), 7, 100)),
    '0a10000102030405060708090a0b0c0d0e0f10071864', 'sync request');
eq(bin2hex(oxmp_encode_sync_ack($span(0), 7)),
    '0a10000102030405060708090a0b0c0d0e0f1007', 'sync ack');
eq(bin2hex(oxmp_encode_delivery_ack($span(0), $span(16), 9)),
    '0a10000102030405060708090a0b0c0d0e0f1210101112131415161718191a1b1c1d1e1f1809', 'delivery ack');
$seed = implode('', array_map('chr', range(0, 31)));
eq(bin2hex(oxmp_sign_challenge($seed, '0xmp-challenge')),
    'b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b23606fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e',
    'ed25519');
echo "php plugin: test_vectors.json OK\n";
