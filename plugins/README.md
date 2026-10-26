# 0xMP 언어별 플러그인 사용법

플러그인은 **와이어 코덱**입니다. 10바이트 프레임으로 감싼 Protobuf 본문을 만들고, 받은 바이트를 다시 풀어 줍니다. 계정 발급, 로그인 화면, WebSocket 연결은 포함하지 않습니다. 연결은 각 언어의 WebSocket 라이브러리가 하고, 그 소켓으로는 **바이너리 프레임**만 보냅니다.

서버 기본 주소는 `ws://127.0.0.1:8765` 입니다. 서버는 저장소 루트에서 `python -m server.main` 으로 켭니다.

모든 예제의 메시지 ID, 대화 ID, 기기 ID, 멱등 키는 **16바이트**입니다. 본문 상한은 64KiB, 프레임 전체 상한은 1MiB 입니다.

## 공통 순서

1. 본문을 만듭니다. 예: HELLO, 텍스트 메시지.
2. `encode frame`으로 10바이트 헤더를 붙입니다.
3. WebSocket으로 그 바이트열을 보냅니다.
4. 수신 바이트는 `decode frame`으로 헤더와 본문을 나눕니다.
5. 프레임 타입에 맞는 디코더로 본문을 읽습니다.

| 타입 값 | 이름 | 방향 |
|---|---|---|
| `0x01` | HELLO | 클라이언트 → 서버 |
| `0x04` | HELLO_RESULT | 서버 → 클라이언트 |
| `0x02` / `0x03` | AUTH / AUTH_RESULT | 인증 |
| `0x10` | MESSAGE_SEND | 클라이언트 → 서버 |
| `0x11` | MESSAGE_ACCEPTED | 서버 → 보낸 사람 |
| `0x16` | MESSAGE_INCOMING | 서버 → 다른 멤버 |
| `0x20` / `0x21` / `0x22` | SYNC_REQUEST / SYNC_BATCH / SYNC_ACK | 동기화 |
| `0x15` | MESSAGE_DELETE | 삭제. 메시지 ID가 비어 있으면 방 전체 삭제 |
| `0x40` / `0x41` | PING / PONG | 연결 유지 |
| `0x7F` | ERROR | 오류 |

아래 명령은 모두 **저장소 루트**에서 실행합니다. 한 번에 여섯 언어를 검사하려면 `python run_tests.py tests/test_language_plugins.py` 입니다. 없는 컴파일러는 건너뜁니다.

---

## Python

파일: `plugins/python/oxmp_plugin.py`. 프레임은 표준 라이브러리만 쓰고, `sign_challenge`는 `cryptography` 패키지의 Ed25519를 씁니다.

확인:

```powershell
python plugins/python/oxmp_plugin.py
```

`python plugin: test_vectors.json OK` 가 나오면 바이트가 규격과 같습니다.

가져오기: 그 파일이 있는 폴더를 모듈 경로에 넣습니다.

```python
import sys
sys.path.insert(0, "plugins/python")
from oxmp_plugin import (
    FrameType, encode_frame, decode_frame, encode_hello,
    encode_message_send, decode_message_incoming, decode_sync_batch,
    encode_delete_event,
)

hello = encode_frame(FrameType.HELLO, encode_hello(protocol_id="0xmp.v1"))
# hello 를 WebSocket 바이너리로 전송

text = encode_message_send(
    message_id=b"\x01" * 16,
    conversation_id=b"\x02" * 16,
    sender_device_id=b"\x03" * 16,
    idempotency_key=b"\x04" * 16,
    body="안녕".encode(),
    kind=1,
)
wire = encode_frame(FrameType.MESSAGE_SEND, text)

frame = decode_frame(received)          # received: 소켓에서 읽은 bytes
if frame["type"] == FrameType.MESSAGE_INCOMING:
    msg = decode_message_incoming(frame["payload"])
    print(msg["body"].decode(), msg["sequence"])
```

이 파일만 인증·동기화 요청·전달 확인·오류 디코더까지 있습니다. `encode_auth`, `decode_auth_result`, `encode_sync_request`, `encode_sync_ack`, `encode_delivery_ack`, `decode_error`.

---

## JavaScript

파일: `plugins/javascript/oxmp_plugin.mjs`. 구현은 `clients/web/oxmp.js` 한 곳이고, 플러그인은 그 파일을 재수출합니다. 브라우저 UI도 같은 코드를 씁니다. Node와 브라우저 모두 ESM 입니다.

확인:

```powershell
node --test plugins/javascript/conformance.test.mjs
```

```javascript
import {
  FrameType, encodeFrame, decodeFrame, encodeHello, encodeMessageSend,
  decodeMessageIncoming,
} from "./plugins/javascript/oxmp_plugin.mjs";

const hello = encodeFrame(FrameType.HELLO, encodeHello({ protocolId: "0xmp.v1" }));
ws.send(hello);   // WebSocket binaryType = "arraybuffer"

const id = () => crypto.getRandomValues(new Uint8Array(16));
const text = encodeMessageSend({
  messageId: id(),
  conversationId: conversationId,       // Uint8Array(16)
  senderDeviceId: deviceId,             // Uint8Array(16)
  idempotencyKey: id(),
  kind: 1,
  body: new TextEncoder().encode("안녕"),
});
ws.send(encodeFrame(FrameType.MESSAGE_SEND, text));

ws.onmessage = (event) => {
  const frame = decodeFrame(new Uint8Array(event.data));
  if (frame.type === FrameType.MESSAGE_INCOMING) {
    const msg = decodeMessageIncoming(frame.payload);
    console.log(new TextDecoder().decode(msg.body), msg.sequence);
  }
};
```

`file://`로 HTML을 열면 모듈 로딩이 막힙니다. 웹 화면은 `python clients/web/run_web.py` 로 띄웁니다.

---

## Java

파일: `plugins/java/src/oxmp/OxmpPlugin.java`. 패키지 이름은 `oxmp` 이고 JDK 21이 필요합니다. 외부 라이브러리는 없습니다.

이 PC의 `java` 명령은 Java 8을 가리킵니다. 컴파일러(`javac`)와 같은 JDK 21의 `java.exe`로 실행해야 합니다.

확인:

```powershell
javac -encoding UTF-8 -d plugins/java/build plugins/java/src/oxmp/OxmpPlugin.java plugins/java/src/oxmp/Conformance.java
& "C:\Program Files\Java\jdk-21.0.10\bin\java.exe" -cp plugins/java/build oxmp.Conformance
```

`java plugin: test_vectors.json OK`

다른 프로그램에서는 컴파일된 `oxmp` 패키지를 classpath에 넣고 정적 메서드를 호출합니다.

```java
import oxmp.OxmpPlugin;

byte[] hello = OxmpPlugin.encodeFrame(
    OxmpPlugin.HELLO, OxmpPlugin.encodeHello("0xmp.v1"), 0, null);

byte[] text = OxmpPlugin.encodeMessageSend(
    new byte[16], new byte[16], new byte[16], new byte[16],
    "안녕".getBytes(java.nio.charset.StandardCharsets.UTF_8),
    1, System.currentTimeMillis());
byte[] wire = OxmpPlugin.encodeFrame(OxmpPlugin.MESSAGE_SEND, text, 0, null);

OxmpPlugin.Frame frame = OxmpPlugin.decodeFrame(received);
if (frame.type() == OxmpPlugin.MESSAGE_INCOMING) {
    OxmpPlugin.Incoming msg = OxmpPlugin.decodeIncoming(frame.payload());
    System.out.println(new String(msg.body(), java.nio.charset.StandardCharsets.UTF_8));
}
```

깨진 프레임은 `OxmpPlugin.FrameException` 입니다. 동기화 배치는 `decodeSyncBatch`, 삭제는 `encodeDelete` / `decodeDelete` 입니다. 메시지 ID를 `null`로 주면 방 전체 삭제입니다.

---

## C#

폴더: `plugins/csharp`. 대상 프레임워크는 .NET 10입니다. Ed25519 서명은 NuGet 패키지 `BouncyCastle.Cryptography`를 씁니다. 클래스는 `OxmpPlugin` 입니다.

확인: 이 명령은 벡터 검사 프로그램(`Program.Main`)을 실행합니다.

```powershell
dotnet run --project plugins/csharp -c Release
```

`csharp plugin: test_vectors.json OK`

다른 솔루션에서 쓰려면 이 프로젝트의 `OxmpPlugin` 클래스를 참조합니다. `dotnet run` 자체는 검사 프로그램이라, 자기 프로그램의 `Main`과 동시에 두면 진입점이 둘입니다. 앱에 넣을 때는 `OxmpPlugin`만 가져갑니다.

```csharp
byte[] hello = OxmpPlugin.EncodeFrame(OxmpPlugin.Hello, OxmpPlugin.EncodeHello("0xmp.v1"), 0, null);

byte[] text = OxmpPlugin.EncodeMessageSend(
    new byte[16], new byte[16], new byte[16], new byte[16],
    System.Text.Encoding.UTF8.GetBytes("안녕"),
    1, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
byte[] wire = OxmpPlugin.EncodeFrame(OxmpPlugin.MessageSend, text, 0, null);

OxmpPlugin.Frame frame = OxmpPlugin.DecodeFrame(received);
if (frame.Type == OxmpPlugin.MessageIncoming) {
    OxmpPlugin.Incoming msg = OxmpPlugin.DecodeIncoming(frame.Payload);
    Console.WriteLine(System.Text.Encoding.UTF8.GetString(msg.Body));
}
```

프레임 상수 이름 두 개는 디코더 타입과 겹치지 않게 다르게 두었습니다. 동기화 배치 프레임은 `SyncBatchFrame`(값 `0x21`), 인증 결과 프레임은 `AuthResultFrame`(값 `0x03`)입니다. 삭제는 `EncodeDelete`. 메시지 ID가 `null`이면 방 전체 삭제입니다.

---

## Rust

파일: `plugins/rust/oxmp.rs`. 프레임 코덱은 이 파일 안에 있고, Ed25519 서명은 `ed25519-dalek`를 씁니다. `plugins/rust/Cargo.toml`이 그 의존성을 선언합니다.

확인:

```powershell
cargo test --manifest-path plugins/rust/Cargo.toml
```

`test result: ok`. 처음 한 번은 `cargo`가 `ed25519-dalek`를 받습니다.

다른 프로젝트에서는 이 크레이트를 경로 의존성으로 붙입니다. `oxmp.rs`만 복사하면 서명 함수가 컴파일되지 않습니다.

```rust
mod oxmp;

let hello = oxmp::encode_frame(oxmp::HELLO, &oxmp::encode_hello("0xmp.v1"), 0, b"")?;
let text = oxmp::encode_message_send(
    &[1; 16], &[2; 16], &[3; 16], &[4; 16],
    "안녕".as_bytes(), 1, 1_700_000_000_000,
);
let wire = oxmp::encode_frame(0x10, &text, 0, b"")?;

let frame = oxmp::decode_frame(&received)?;
if frame.frame_type == 0x16 {
    let msg = oxmp::decode_incoming(&frame.payload)?;
    println!("{}", String::from_utf8_lossy(&msg.body));
}
```

`encode_frame`과 `decode_frame`은 `Result`입니다. 실패하면 `FrameError`입니다. 동기화는 `decode_sync_batch`, 삭제는 `encode_delete`. 메시지 ID를 `b""`로 주면 방 전체 삭제입니다.

---

## PHP

파일: `plugins/php/oxmp.php`. PHP 8에서 `require` 합니다. 프레임은 확장 없이 동작하고, `oxmp_sign_challenge`는 libsodium(Ed25519)을 씁니다. 이 PHP 빌드의 OpenSSL은 Ed25519 키를 읽지만 서명은 거절하므로 sodium 확장이 필요합니다. 확인 스크립트는 확장이 꺼져 있으면 `php -d extension=sodium`으로 자신을 다시 실행합니다. 바이트는 PHP 문자열로 다룹니다.

확인:

```powershell
php plugins/php/conformance.php
```

다른 프로그램에서 `oxmp.php`를 `require` 해 서명할 때는 그 프로세스에 sodium이 있어야 합니다. `php -m`에 없으면 `php -d extension=sodium`으로 띄우거나 `php.ini`에서 `extension=sodium`을 켭니다.

`php plugin: test_vectors.json OK`

```php
<?php
require __DIR__ . "/oxmp.php";

$hello = oxmp_encode_frame(0x01, oxmp_encode_hello("0xmp.v1"));

$text = oxmp_encode_message_send(
    str_repeat("\x01", 16),
    str_repeat("\x02", 16),
    str_repeat("\x03", 16),
    str_repeat("\x04", 16),
    "안녕",
    1,
    (int) (microtime(true) * 1000)
);
$wire = oxmp_encode_frame(0x10, $text);

$frame = oxmp_decode_frame($received);
if ($frame["type"] === 0x16) {
    $msg = oxmp_decode_incoming($frame["payload"]);
    echo $msg["body"], " #", $msg["sequence"], PHP_EOL;
}
```

깨진 프레임은 `OxmpFrameError` 입니다. 동기화는 `oxmp_decode_sync_batch`, 삭제는 `oxmp_encode_delete`. 메시지 ID를 `''`로 주면 방 전체 삭제입니다.

---

## 언어마다 들어 있는 기능

| 기능 | Python | JavaScript | Java | C# | Rust | PHP |
|---|---|---|---|---|---|---|
| 프레임 인코딩·디코딩, 손상 프레임 거부 | 있음 | 있음 | 있음 | 있음 | 있음 | 있음 |
| HELLO, 텍스트 송신, 수신 메시지, 동기화 배치, 삭제 | 있음 | 있음 | 있음 | 있음 | 있음 | 있음 |
| AUTH, 동기화 요청·ACK, 전달 확인 | 있음 | 있음 | 있음 | 있음 | 있음 | 있음 |

AUTH까지 플러그인 안에 있습니다. HELLO 결과의 `session_id`를 기기 비밀키(32바이트 시드)로 Ed25519 서명하고, 그 서명을 AUTH 본문에 넣습니다. 여섯 언어는 같은 시드·같은 챌린지에 같은 64바이트 서명을 만듭니다. 알고리즘은 각 언어의 검증된 구현입니다. Python은 `cryptography`, JavaScript는 WebCrypto, Java는 JDK `Ed25519`, C#은 BouncyCastle, Rust는 `ed25519-dalek`, PHP는 libsodium 입니다.

```python
signature = sign_challenge(bytes.fromhex(creds["device_private_key_raw"]), session_id)
auth = encode_auth(creds["access_token"], bytes.fromhex(creds["device_id"]), signature)
wire = encode_frame(FrameType.AUTH, auth)
```

```javascript
const signature = await signChallenge(privateKeyRaw, publicKeyRaw, sessionId);
const auth = encodeAuth({ accessToken, deviceId, signature });
ws.send(encodeFrame(FrameType.AUTH, auth));
```

JavaScript만 공개키도 같이 넘깁니다. WebCrypto가 비밀키 JWK에 공개키(`x`)를 요구하기 때문입니다. 계정 발급 응답의 `device_public_key`를 쓰면 됩니다.

```java
byte[] signature = OxmpPlugin.signChallenge(privateKeyRaw, sessionId);
byte[] auth = OxmpPlugin.encodeAuth(accessToken, deviceId, signature);
byte[] wire = OxmpPlugin.encodeFrame(OxmpPlugin.AUTH, auth, 0, null);
```

```csharp
byte[] signature = OxmpPlugin.SignChallenge(privateKeyRaw, sessionId);
byte[] auth = OxmpPlugin.EncodeAuth(accessToken, deviceId, signature);
byte[] wire = OxmpPlugin.EncodeFrame(OxmpPlugin.Auth, auth, 0, null);
```

```rust
let signature = oxmp::sign_challenge(private_key_raw, session_id)?;
let auth = oxmp::encode_auth(access_token, device_id, &signature);
let wire = oxmp::encode_frame(0x02, &auth, 0, b"")?;
```

```php
$signature = oxmp_sign_challenge($privateKeyRaw, $sessionId);
$auth = oxmp_encode_auth($accessToken, $deviceId, $signature);
$wire = oxmp_encode_frame(0x02, $auth);
```

서버가 돌려준 AUTH_RESULT 본문은 `decodeAuthResult` / `DecodeAuthResult` / `decode_auth_result` / `oxmp_decode_auth_result` 로 읽습니다. `ok`가 참이면 인증된 것입니다. JavaScript는 `decodeAuthResult` 입니다.

Kotlin, Swift 런타임은 이 환경에 없어서 Android/iOS 플러그인은 없습니다. 추가할 때는 `clients/test_vectors.json`과 바이트가 같아야 합니다.
