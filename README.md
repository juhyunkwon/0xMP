# 0xMP 프로젝트 가이드

**0xMP (0x Messaging Protocol)** — 주요 메신저의 공개 프로토콜을 비교·분석하고, 검증된 표준 암호화 방식으로 보안을 보강해 독자 설계한 범용 메시징 프로토콜과 그 참조 구현입니다.

- 현재 명세 버전: **v0.5.0-draft** (`0xMP 기술 명세서 v0.5.docx`)
- 검증 상태: 자동화 테스트 **69건 통과**, 동시 접속 1,000개까지 단계별 부하 측정 완료
- 실행 환경: Windows 기준, Python 3.14, Node.js 24에서 검증

---

## 1. 폴더 구조

### 1.1 한눈에 보기

| 폴더/파일 | 역할 | 직접 실행? |
|---|---|---|
| `server/` | 실서비스용 서버와 클라이언트 라이브러리 (제품 코드) | `python -m server.main` |
| `tests/` | pytest 자동화 테스트 90건 | pytest로만 실행 |
| `samples/` | 프로토콜을 배우기 위한 최소 샘플 (초기 검증용) | 일부 파일만 직접 실행 |
| `clients/` | 플랫폼별 클라이언트와 공통 테스트 벡터 | 웹은 브라우저로 열기 |
| `plugins/` | 언어별 와이어 코덱과 Ed25519 AUTH 서명 (Python, JavaScript, Java, C#, Rust, PHP) | `plugins/README.md` |
| `tools/` | 부하 측정, 인증서 생성, 결과 보존 등 운영 도구 | 파일별 직접 실행 |
| `reports/` | 보존된 검증·부하 측정 결과 (JSON/CSV) | 결과 보관용 |
| `media-blobs/` | 파일 전송으로 업로드된 실제 파일이 저장되는 곳 | 자동 생성 |
| `run_tests.py` | 테스트 실행 러너 | `python run_tests.py` |
| `0xMP 기술 명세서 v*.docx` | 프로토콜 명세서 (버전별) | 문서 |
| `oxmp.db`, `oxmp.db-wal`, `oxmp.db-shm` | 서버 실행 중 생기는 SQLite 데이터베이스 파일 3종 세트 | 자동 생성 |

### 1.2 `server/` — 실제 서버 코드

| 파일 | 설명 |
|---|---|
| `main.py` | **배포용 통합 진입점.** WebSocket 서버 + 계정 API를 한 번에 실행 |
| `app.py` | WebSocket 서버 본체. HELLO 협상 → 인증 → 메시지 송수신·동기화·미디어·키 번들 처리, 연결별 송신 큐로 팬아웃 |
| `api.py` | HTTP API. 계정 생성, 기기 추가/해지, 토큰 갱신, 대화 생성, 파일 업로드/다운로드, 푸시 토큰 등록 |
| `auth.py` | 토큰 인증. HMAC 서명 단기 액세스 토큰(15분), 리프레시 토큰 해시 저장·회전·재사용 탐지 |
| `store.py` | SQLite 영구 저장. 저장 완료 후 ACK, 멱등성 UNIQUE 제약, 대화별 순번 발급, 동기화 커서, 키 번들, 미디어, 푸시 토큰 |
| `client.py` | Python 참조 클라이언트 라이브러리. 테스트와 도구가 이걸 사용 |
| `provision.py` | 계정·기기 발급 모델. Ed25519 기기 키 쌍 생성, 자격증명 발급 |
| `push.py` | 푸시 알림 제공자. 기록용(테스트), 웹훅(FCM/APNs 브리지 지점). 평문은 절대 넣지 않음 |
| `e2e.py` | E2E(종단 간 암호화) 클라이언트 어댑터. Signal 프로토콜 구현을 감싸 키 번들과 암복호화 제공 |
| `testing.py` | 테스트 하니스. 임시 DB와 임시 포트로 실제 서버를 띄워 주는 도구 |

### 1.3 `tests/` — 자동화 테스트 (pytest 전용)

> ⚠️ 이 폴더의 파일은 **직접 실행하는 파일이 아닙니다.**
> `python tests/test_features.py`처럼 실행하면 `ModuleNotFoundError: No module named 'server'`가 발생합니다.
> 반드시 프로젝트 루트에서 pytest나 `run_tests.py`로 실행하세요. (이유는 6장 참고)

| 파일 | 검증 내용 |
|---|---|
| `conftest.py` | 프로젝트 루트를 모듈 경로에 올려 주는 공통 설정 |
| `test_frame_security.py` | 프레임 코덱 보안: 위조 헤더, 잘린 프레임, 초과 길이, 예약 비트 거부 + 기존 벡터 회귀 |
| `test_auth.py` | 토큰 위조·변조·만료, 리프레시 회전과 재사용 탐지 시 기기 해지 |
| `test_store_durability.py` | DB 재시작 후 메시지 보존, 중복 저장 방지, 동시 20스레드 동일 키 → 1건 저장, 순번 무간격 |
| `test_server_p0.py` | WebSocket 통합: 위조/만료 토큰 거부, 저장 후 ACK, 재생 시 중복 판정, 팬아웃 순서 |
| `test_server_restart.py` | 서버 완전 재시작 후 메시지와 커서 보존 |
| `test_reconnect_sync.py` | 오프라인 복구, 커서 경계값, ACK 유실 후 재시도, SYNC_ACK 신규 적용 vs 재확인 구분 |
| `test_network_faults.py` | 실제 소켓에 쓰레기/부분 프레임 주입 시 오류 프레임 후 종료 |
| `test_security_tls.py` | 인증서 정상/미신뢰/만료/호스트 불일치, AUTH 프레임 재생 거부, E2E 암호문 변조 탐지 |
| `test_tls.py` | wss:// 실제 왕복 (인증서 검증 포함) |
| `test_api.py` | 계정·기기 API: 발급, 갱신, 해지, 타인 기기 해지 거부 |
| `test_features.py` | 그룹 채팅, 전달 확인 통지, 오프라인 동기화, 파일 전송 왕복·무결성, 푸시 발송 |
| `test_e2e.py` | 키 번들 프레임, 서버 DB에 암호문만 저장되는지, 양방향 복호화 |
| `test_platform_vectors.py` | 플랫폼 공통 벡터가 Python과 JavaScript에서 바이트 단위 일치하는지 |

### 1.4 `samples/` — 학습용 최소 샘플

초기 프로토콜 검증 단계의 산출물입니다. 실서비스 코드는 `server/`를 보세요.

| 파일 | 설명 | 직접 실행 |
|---|---|---|
| `oxmp.proto` | 전체 Protobuf 스키마 초안 (명세의 기준) | — |
| `oxmp_frame.py` | 10바이트 프레임 헤더 코덱 **라이브러리** | ❌ 실행해도 아무 출력 없이 종료되는 게 정상 |
| `oxmp_payload.py` | protoc 없이 쓰도록 기술자(descriptor)로 만든 동적 Protobuf 메시지 | — |
| `sample_client.py` | 협상→인증→송신→멱등 재시도→수신 확인→동기화 전체 흐름 데모 | ✅ `python samples/sample_client.py` |
| `test_vectors.py` | 규격 테스트 벡터 12건 검증 스크립트 | ✅ `python samples/test_vectors.py` |

### 1.5 `clients/` — 플랫폼 클라이언트

| 경로 | 설명 |
|---|---|
| `test_vectors.json` | **모든 플랫폼이 재현해야 할 공통 와이어 벡터.** `tools/generate_vectors.py`로 재생성 |
| `web/oxmp.js` | 의존성 없는 JavaScript 프레임 코덱 + Protobuf 인코더 (브라우저·Node 공용) |
| `web/index.html` | 웹 채팅 UI. WebCrypto로 Ed25519 서명까지 수행 |
| `web/oxmp.test.mjs` | 공통 벡터를 JS 구현이 재현하는지 검증하는 Node 테스트 |

플랫폼 검증 현황: Python, JavaScript, Java, C#, Rust, PHP 플러그인이 같은 `clients/test_vectors.json` 바이트를 재현합니다 (`plugins/README.md`). Android/iOS 네이티브 SDK는 아직 없으며, 만들 때 이 벡터 파일이 합격 기준이 됩니다.

### 1.6 `tools/` — 운영 도구

| 파일 | 용도 | 실행 예 |
|---|---|---|
| `staged_load.py` | 동시 접속 10→100→500→1,000 단계별 부하 측정, 결과를 `reports/`에 보존 | `python tools/staged_load.py` |
| `load_test.py` | 그룹 팬아웃 등 임의 규모 부하 측정 | `python tools/load_test.py --clients 25 --messages 100` |
| `preserve_results.py` | 프로토콜 검증 결과를 `reports/`에 기록으로 보존 | `python tools/preserve_results.py` |
| `generate_vectors.py` | `clients/test_vectors.json` 재생성 | `python tools/generate_vectors.py` |
| `make_dev_cert.py` | 개발용 자체 서명 인증서(cert.pem/key.pem) 생성 | `python tools/make_dev_cert.py dev-cert` |
| `e2e_flow.py` | E2E 전체 흐름 실증 (키 번들→암호화 송신→복호화) | 5.6절 참고 |

### 1.7 `reports/` — 보존된 결과

측정할 때마다 덮어쓰지 않고 시각이 붙은 파일로 쌓입니다. 삭제해도 코드는 동작하지만, 검증 이력이 사라지니 보관하는 것을 권장합니다.

- `protocol_verification_*.json` — 벡터 검증 기록 (실행 시각, 종료 코드, 벡터 파일 SHA-256)
- `staged_load_*.json`, `staged_load_*.csv` — 단계별 부하 측정 원본

### 1.8 자동 생성 파일 (지워도 되는 것, 주의할 것)

| 파일 | 정체 | 취급 |
|---|---|---|
| `oxmp.db` (+ `-wal`, `-shm`) | 서버가 쓰는 SQLite DB 3종 세트 (WAL 모드) | 서버를 **완전히 종료한 뒤**에만 이동/삭제. 사용자는 계정·메시지가 들어 있음. 세 파일을 따로 떼어 옮기지 말 것 |
| `media-blobs/` | 업로드된 파일 실물 | 지우면 다운로드가 깨짐. 테스트만 했으면 삭제 가능 |
| `__pycache__/`, `.pytest_cache/` | Python/pytest 캐시 | 언제 지워도 됨. 자동 재생성 |

### 1.9 명세서 docx 버전 안내

**평소에는 `0xMP 기술 명세서 v0.5.docx`만 보면 됩니다.** 나머지는 개정 이력 보관용입니다.

| 버전 | 내용 |
|---|---|
| v0.1 | 최초 초안 (비교 분석과 기본 설계) |
| v0.2 | 문서 점검 반영: 프레이밍 확정, 보안 장 전면 보강, 샘플 추가 |
| v0.3 | 실서버 구현과 자동화 테스트 40건, 부하 측정 결과 (부록 C) |
| v0.4 | 계정 API, TLS 배포, E2E 실증, 웹 클라이언트 (부록 D) |
| **v0.5** | **검증 보존, TLS 보안 검증, 단계별 부하 10→1,000, 메신저 기능 (부록 E) — 최신** |

---

## 2. 사전 준비

### 2.1 필수 소프트웨어

- Python 3.11 이상 (3.14에서 검증)
- Node.js 20 이상 (JavaScript 벡터 검증을 할 때만 필요)

### 2.2 패키지 설치

프로젝트 루트에서:

```powershell
python -m pip install websockets pytest cryptography protobuf psutil libsignal
```

| 패키지 | 쓰는 곳 |
|---|---|
| `websockets` | 서버·클라이언트 WebSocket 통신 |
| `pytest` | 자동화 테스트 |
| `cryptography` | Ed25519 기기 서명, 인증서 생성/검증 |
| `protobuf` | 메시지 직렬화 (동적 메시지 생성 포함) |
| `psutil` | 부하 테스트의 CPU·메모리 측정 |
| `libsignal` | E2E 어댑터 (구 Signal 프로토콜 순수 Python 포트). E2E를 안 쓰면 없어도 됨 |

---

## 3. 빠른 시작 (5분)

아래 순서대로 하면 서버를 띄우고 메시지가 오가는 것까지 확인할 수 있습니다.

### 1단계 — 프로토콜 기본 검증

```powershell
python samples/test_vectors.py
python tools/preserve_results.py
```

기대 결과: `All test vectors passed.`, `all_passed=True`가 찍히고 `reports/`에 기록이 남습니다.

### 2단계 — 서버 실행

터미널을 하나 열고 프로젝트 루트에서:

```powershell
$env:OXMP_SECRET = "개발용이라도-32바이트-이상-긴-문자열로-교체하세요"
python -m server.main
```

기대 출력:

```text
0xMP server: ws://127.0.0.1:8765  api=http://127.0.0.1:8770  db=oxmp.db
WARNING: plain ws:// - local development only; production requires TLS 1.3 (SEC-01).
```

두 번째 경고는 평문 실행이라 뜨는 것이며, 로컬 개발에서는 정상입니다. 이 터미널은 서버를 끄기 전까지 그대로 두세요.

### 3단계 — 계정 발급 확인

**다른 터미널**에서:

```powershell
Invoke-RestMethod http://127.0.0.1:8770/v1/health
$body = @{ name = "alice" } | ConvertTo-Json
$alice = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8770/v1/accounts -Body $body -ContentType "application/json"
$alice | ConvertTo-Json
```

응답에 `user_id`, `device_id`, `access_token`, `refresh_token`, `device_private_key_raw`가 들어 있으면 성공입니다. 이 JSON은 웹 클라이언트에 붙여 넣어 씁니다.

### 4단계 — 웹 클라이언트로 접속

```powershell
python clients/web/run_web.py
```

브라우저가 자동으로 열립니다. **이름을 적고 [채팅 시작하기]만 누르면** 계정 발급과 접속이 한 번에 됩니다. 같은 이름으로 다시 들어오면 저장된 계정을 재사용하고, 토큰이 만료됐으면 자동 갱신합니다. 로비에서 사용자를 눌러 1:1 대화를 시작하거나, 사용자를 체크하고 그룹을 만들거나, 대화 목록에서 방에 입장하세요. 방에 입장하면 과거 메시지가 동기화로 표시됩니다. 서버 주소 변경이나 기존 자격증명으로 접속하는 일은 로그인 화면의 **고급 설정** 안에 있습니다.

**연결·동기화 동작**: 채팅 화면은 15초마다, 그리고 창이 다시 보이거나 네트워크가 복귀할 때 자동으로 현재 방을 동기화합니다(중복 표시는 메시지 ID로 방지). 연결이 끊기면 사이드바에 "재연결 중"이 표시되고 1→2→4→8→10초 간격으로 자동 재접속을 시도하며, 25초마다 핑으로 죽은 연결을 감지합니다. 끊긴 동안 보낸 메시지는 같은 메시지 ID·멱등 키로 대기열에 쌓였다가 재연결 직후 자동 재전송되므로 중복 생성되지 않습니다. 페이지를 새로고침하면 저장된 세션으로 자동 재접속합니다. 방 정보 패널에서는 멤버 확인·초대·이름 변경·나가기·(방장) 내보내기가 가능하고, 1:1 방에서 사용자를 초대하면 기존 상대와 초대자를 포함한 새 그룹으로 전환됩니다.

**친구·그룹 이름 동작**: 사이드바에는 전체 사용자가 아니라 **친구 목록만** 표시됩니다. 새 사용자는 사이드바 아래 "친구 추가" 영역에서 추가하세요(추가하면 상대 목록에도 서로 친구로 나타납니다). 1:1 대화 시작, 그룹 만들기, 방 초대, 1:1→그룹 전환의 대상은 모두 친구로 제한됩니다. 1:1 방에서 그룹으로 전환할 때는 그룹 이름이 참여자 이름으로 미리 채워지며(수정 가능), 전환된 그룹방에서는 채팅 상단의 **[이름 변경]** 버튼으로 바로 이름을 바꿀 수 있습니다. 친구 목록과 친구 추가 영역에는 각각 **이름 검색창**이 있어 입력 즉시 필터링됩니다.

**세션·삭제·파일 동작**: 사이드바 상단의 **[로그아웃]**은 이 기기의 세션을 서버에서 삭제(토큰 즉시 무효화)하고 브라우저 저장 정보까지 지웁니다. 다른 기기의 세션은 유지되며, 모든 기기를 끝내려면 API `POST /v1/auth/logout-all`을 사용하세요. 내 메시지 말풍선의 **[삭제]** 버튼은 모두에게 삭제합니다(본인 메시지만 가능). 서버는 원본을 지우고 tombstone만 동기화하므로 다른 기기에서도 "삭제된 메시지입니다"로 수렴합니다. 방 정보 패널의 **전체 삭제**는 방의 모든 메시지를 한 번에 삭제합니다(그룹은 방장만, 1:1은 양쪽 가능, 되돌릴 수 없음). 채팅 상단의 **[방 나가기]**는 확인 후 멤버에서 탈퇴합니다. 입력창 옆 **😀** 버튼은 이모지 패널, **📎** 버튼은 파일 전송입니다. 파일 실물은 미디어 API(해시 검증)를 거치고 채팅에는 참조(kind=2, JSON 본문)만 흐르며, 이미지는 말풍선에서 바로 미리보기 됩니다(웹 기준 20MB 제한).

> ⚠️ `index.html`을 **더블클릭으로 열면 안 됩니다.** `file://`로 연 페이지는 브라우저 CORS 정책상 `oxmp.js` 모듈을 불러올 수 없어 `Access to script ... has been blocked by CORS policy` 오류가 납니다. 반드시 위처럼 HTTP로 띄워서 `http://127.0.0.1:8000`으로 접속하세요.

### 5단계 — 전체 테스트

```powershell
python run_tests.py
```

기대 결과: `90 passed`. 여기서 실패하면 코드가 깨진 것이니, 아래 6장의 문제 해결을 참고하세요. 언어 플러그인만 보려면 `python run_tests.py tests/test_language_plugins.py` 입니다. 그 머신에 없는 컴파일러는 건너뜁니다.

---

## 4. 서버 실행 상세

### 4.1 환경변수

`python -m server.main`은 아래 환경변수를 읽습니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `OXMP_SECRET` | 개발용 고정값 (경고 출력) | 토큰 서명 비밀. **운영에서는 반드시 32바이트 이상 임의값으로 설정** |
| `OXMP_DB` | `oxmp.db` | SQLite 파일 경로 |
| `OXMP_HOST` | `127.0.0.1` | 바인드 주소. 외부 공개 시에도 보통은 리버스 프록시 뒤에 두고 loopback 유지 권장 |
| `OXMP_PORT` | `8765` | WebSocket 포트 |
| `OXMP_API_PORT` | `8770` | HTTP API 포트 |
| `OXMP_TLS_CERT` | 없음 | PEM 인증서 경로. `OXMP_TLS_KEY`와 함께 지정하면 `wss://` |
| `OXMP_TLS_KEY` | 없음 | PEM 비밀키 경로 |

### 4.2 TLS(wss)로 실행

```powershell
python tools/make_dev_cert.py dev-cert
$env:OXMP_TLS_CERT = "dev-cert/cert.pem"
$env:OXMP_TLS_KEY  = "dev-cert/key.pem"
$env:OXMP_SECRET   = "개발용이라도-32바이트-이상-긴-문자열로-교체하세요"
python -m server.main
```

`https`가 아니라 `wss://127.0.0.1:8765`로 접속해야 합니다. 자체 서명 인증서는 개발용이며, 운영에서는 CA 발급 인증서를 쓰세요. 비밀키(`key.pem`)는 절대 공유·커밋하지 마세요.

### 4.3 API 요약

모든 API는 `Authorization: Bearer <access_token>` 헤더가 필요합니다 (계정 생성과 헬스 체크 제외).

| 메서드/경로 | 용도 |
|---|---|
| `GET /v1/health` | 서버 살아 있는지 확인 |
| `POST /v1/accounts` `{name}` | 계정 + 첫 기기 + 토큰 발급 |
| `POST /v1/devices` | 내 계정에 기기 추가 |
| `POST /v1/devices/revoke` `{device_id}` | 기기 해지 (본인 기기만) |
| `POST /v1/auth/refresh` `{refresh_token}` | 토큰 갱신. 이미 쓴 토큰 재사용 시 기기 전체 해지 |
| `POST /v1/auth/logout` | 세션 삭제(로그아웃). 이 기기의 액세스·리프레시 토큰 즉시 무효화 (기기 자체는 유지) |
| `POST /v1/auth/logout-all` | 내 모든 기기의 세션 삭제 |
| `POST /v1/conversations` `{member_user_ids, title, kind}` | 그룹 대화 생성 |
| `POST /v1/conversations/direct` `{user_id}` | 그 사용자와의 1:1 방 (있으면 기존 방 반환) |
| `POST /v1/conversations/{id}/members` `{user_id}` | 방에 멤버 추가 (기존 멤버만 가능) |
| `POST /v1/conversations/{id}/rename` `{title}` | 그룹 이름 변경 (그룹·멤버만) |
| `POST /v1/conversations/{id}/leave` | 대화방 나가기 (본인 탈퇴) |
| `POST /v1/conversations/{id}/remove` `{user_id}` | 멤버 내보내기 (방장만) |
| `GET /v1/conversations` | 내가 속한 대화 목록 (제목·종류·멤버·마지막 순번 포함) |
| `GET /v1/users` | 전체 사용자 목록 (본인·친구 여부 표시 포함, 친구 추가용) |
| `GET /v1/friends` | 내 친구 목록 |
| `POST /v1/friends` `{user_id}` | 친구 추가 (양방향, 중복 추가는 무시) |
| `POST /v1/friends/remove` `{user_id}` | 친구 삭제 (양쪽에서 제거) |
| `POST /v1/media/init` | 파일 업로드 그랜트 발급 |
| `PUT /v1/media/{id}/content` | 파일 실물 업로드 (크기·SHA-256 검증) |
| `GET /v1/media/{id}/content` | 파일 다운로드 (대화 멤버만) |
| `POST /v1/devices/push-token` | 푸시 토큰 등록 |

---

## 5. 용도별 실행 방법

### 5.1 전체 테스트

```powershell
python run_tests.py                    # 전체 69건
python -m pytest tests -q              # 같은 결과 (pytest 직접 실행)
```

### 5.2 특정 테스트만

```powershell
python run_tests.py tests/test_features.py          # 기능 테스트만
python run_tests.py tests/test_security_tls.py -v   # 보안 검증을 상세히
python -m pytest tests/test_auth.py -q              # 인증만
```

### 5.3 샘플 데모

```powershell
python samples/sample_client.py    # 인메모리 흐름 데모 (서버 불필요)
python samples/test_vectors.py     # 규격 벡터 12건
```

### 5.4 JavaScript 상호운용 검증

```powershell
node --test clients/web/oxmp.test.mjs
```

Python 구현과 바이트 단위로 같은 결과가 나와야 합니다.

### 5.5 부하 테스트

```powershell
python tools/load_test.py --clients 25 --messages 100
python tools/staged_load.py
python tools/staged_load.py --stages 10,100 --messages 5
```

`staged_load.py`는 동시 접속 10→100→500→1,000 단계마다 처리량, p50/p95/p99 지연, 오류율, CPU, 메모리를 측정해 `reports/`에 JSON/CSV로 보존합니다.

최근 측정 (로컬 loopback, 개발 기준선): 1,000 접속 전부 성공, 오류율 0%, 처리량 약 949 msg/s. 단, 전원 동시 송신 시 p95 지연이 1.3초까지 커지는 것이 알려진 병목입니다.

### 5.6 E2E(종단 간 암호화) 흐름

레거시 Signal 포트의 제약 때문에 환경변수가 하나 더 필요합니다.

```powershell
$env:PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION = "python"
python tools/e2e_flow.py
```

기대 결과 마지막 줄: `E2E FLOW OK`. 서버 DB에는 암호문만 남고, 양쪽이 서로의 메시지를 복호화하는 과정이 출력됩니다.

### 5.7 공통 벡터 재생성

프로토콜 와이어 형식을 바꿨을 때만 필요합니다.

```powershell
python tools/generate_vectors.py
node --test clients/web/oxmp.test.mjs
python run_tests.py tests/test_platform_vectors.py
```

---

## 6. 자주 겪는 문제

| 증상 | 원인 | 해결 |
|---|---|---|
| `ModuleNotFoundError: No module named 'server'` | 테스트 파일을 직접 실행함 (`python tests/test_features.py`) | 루트에서 `python run_tests.py` 또는 `python -m pytest tests -q`. 테스트 파일은 루트를 경로에 넣어 주는 pytest/conftest가 있어야 동작합니다 |
| `oxmp_frame.py`를 실행했는데 아무 일도 안 일어남 | 정상. 실행 파일이 아니라 라이브러리라 진입점이 없음 | 검증은 `python samples/test_vectors.py`로 |
| `Address already in use` (포트 사용 중) | 서버가 이미 떠 있거나 이전 서버가 안 꺼짐 | 기존 서버 터미널에서 `Ctrl+C`. 또는 `OXMP_PORT`/`OXMP_API_PORT` 변경 |
| `WARNING: OXMP_SECRET unset...` | 비밀 미설정으로 개발용 비밀 사용 중 | `$env:OXMP_SECRET`에 32바이트 이상 임의 문자열 설정 |
| `WARNING: plain ws://` | TLS 미적용 평문 실행 | 로컬 개발은 무시 가능. 외부 노출 시 4.2절처럼 TLS 적용 필수 |
| E2E 실행 시 protobuf 관련 `TypeError` | 레거시 libsignal이 새 protobuf와 충돌 | 5.6절처럼 `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` 설정 후 실행 |
| 브라우저에서 웹 클라이언트 접속 실패 | 서버 미실행, URL 오타, 또는 https 페이지에서 ws 접속 차단 | 서버 실행 확인, `ws://127.0.0.1:8765` 확인. 페이지를 `http://`로 열었는지 확인 |
| `Access to script ... blocked by CORS policy` (oxmp.js 로딩 실패) | `index.html`을 더블클릭해 `file://`로 열었음. 브라우저는 file:// 출처의 모듈 import를 차단함 | 파일로 열지 말고 `python clients/web/run_web.py`로 HTTP 서빙 후 `http://127.0.0.1:8000` 접속 |
| 테스트에서 인증 실패가 갑자기 남 | `oxmp.db`에 남은 예전 계정/기기 상태를 재사용 | 서버를 끄고 `oxmp.db*` 3개 파일을 지운 뒤 재시작하면 깨끗한 상태가 됩니다 |

---

## 7. 개발할 때 알아둘 규칙

- **명세가 기준입니다.** 와이어 형식을 바꾸면 `samples/oxmp.proto`와 `samples/oxmp_frame.py`, `server/` 구현, `clients/test_vectors.json`을 함께 고치고 벡터 테스트를 통과시켜야 합니다.
- **자체 암호 알고리즘을 만들지 않습니다.** E2E는 검증된 라이브러리의 결과물을 운반만 합니다 (명세 SEC-06).
- **저장 후 ACK.** `MESSAGE_ACCEPTED`는 DB 커밋이 끝난 뒤에만 보내야 합니다. 멱등성 키 재요청에는 새로 저장하지 말고 기존 결과를 재반환하세요.
- **푸시에 평문을 넣지 않습니다.** 푸시 이벤트에는 대화/메시지 식별자만 들어갑니다.
- **새 기능에는 테스트를 같이.** `tests/`에 넣으면 `run_tests.py`가 자동으로 수집합니다.

## 8. 아직 남은 과제

- 1,000 동시 접속 시 p95 지연 개선 (쓰기 큐 분리, 배치 커밋, 운영 DB 전환)
- 속도 제한(오류 0x0005) 실제 적용과 운영 메트릭/로깅
- FCM/APNs 직접 연동 (현재는 웹훅 브리지까지)
- Android/iOS 네이티브 SDK (Kotlin/Swift 런타임이 이 환경에 없음. `plugins/`와 같은 벡터가 합격 기준)
- E2E 어댑터를 유지보수되는 공식 libsignal 바인딩으로 교체
