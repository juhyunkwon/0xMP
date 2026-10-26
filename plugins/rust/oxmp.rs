//! 0xMP wire plugin for Rust. Frame codec is local; Ed25519 uses ed25519-dalek.
use std::collections::HashMap;
use ed25519_dalek::{Signer, SigningKey};

const VERSION: u8 = 0x01;
const MAX_PAYLOAD: usize = 1024 * 1024;
const KNOWN_FLAGS: u16 = 0x0001 | 0x0002 | 0x0004 | 0x0008;

pub const HELLO: u8 = 0x01;
pub const PING: u8 = 0x40;

fn known(t: u8) -> bool {
    matches!(t,
        0x01 | 0x02 | 0x03 | 0x04 | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16
        | 0x17 | 0x20 | 0x21 | 0x22 | 0x30 | 0x31 | 0x40 | 0x41 | 0x50 | 0x51 | 0x52 | 0x7F)
}

#[derive(Debug)]
pub struct FrameError(pub &'static str);

pub struct Frame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
    pub extension: Vec<u8>,
}

pub struct Incoming {
    pub sequence: u64,
    pub body: Vec<u8>,
}

pub struct SyncEvent {
    pub sequence: u64,
    pub message: Option<Incoming>,
}

pub struct SyncBatch {
    pub events: Vec<SyncEvent>,
    pub has_more: bool,
    pub next_after_sequence: u64,
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { b |= 0x80; }
        out.push(b);
        if value == 0 { break; }
    }
}

fn tag(out: &mut Vec<u8>, field: u32, wire: u32) { varint(out, ((field << 3) | wire) as u64); }

fn bytes_field(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    if data.is_empty() { return; }
    tag(out, field, 2);
    varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn uint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    if value != 0 { tag(out, field, 0); varint(out, value); }
}

enum Val { Num(u64), Bytes(Vec<u8>) }

fn parse(data: &[u8]) -> Result<HashMap<u32, Vec<Val>>, FrameError> {
    let mut fields: HashMap<u32, Vec<Val>> = HashMap::new();
    let mut at = 0;
    while at < data.len() {
        let (tag_v, next) = read_varint(data, at)?;
        at = next;
        let field = (tag_v >> 3) as u32;
        let wire = (tag_v & 7) as u32;
        let value = if wire == 0 {
            let (n, next) = read_varint(data, at)?;
            at = next;
            Val::Num(n)
        } else if wire == 2 {
            let (n, next) = read_varint(data, at)?;
            at = next;
            let len = n as usize;
            if at + len > data.len() { return Err(FrameError("truncated length-delimited field")); }
            let v = Val::Bytes(data[at..at + len].to_vec());
            at += len;
            v
        } else if wire == 5 {
            let v = Val::Bytes(data[at..at + 4].to_vec()); at += 4; v
        } else if wire == 1 {
            let v = Val::Bytes(data[at..at + 8].to_vec()); at += 8; v
        } else {
            return Err(FrameError("unsupported wire type"));
        };
        fields.entry(field).or_default().push(value);
    }
    Ok(fields)
}

fn read_varint(data: &[u8], mut at: usize) -> Result<(u64, usize), FrameError> {
    let mut shift = 0;
    let mut result = 0u64;
    loop {
        if at >= data.len() { return Err(FrameError("truncated varint")); }
        let b = data[at];
        at += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 { return Ok((result, at)); }
        shift += 7;
        if shift > 63 { return Err(FrameError("varint too long")); }
    }
}

fn num(fields: &HashMap<u32, Vec<Val>>, n: u32) -> u64 {
    match fields.get(&n).and_then(|v| v.first()) {
        Some(Val::Num(n)) => *n,
        _ => 0,
    }
}

fn blob<'a>(fields: &'a HashMap<u32, Vec<Val>>, n: u32) -> Option<&'a [u8]> {
    match fields.get(&n).and_then(|v| v.first()) {
        Some(Val::Bytes(b)) => Some(b),
        _ => None,
    }
}

pub fn encode_frame(frame_type: u8, payload: &[u8], mut flags: u16, extension: &[u8]) -> Result<Vec<u8>, FrameError> {
    if !known(frame_type) { return Err(FrameError("unknown frame type")); }
    if (flags & !KNOWN_FLAGS) != 0 { return Err(FrameError("reserved flag bits set")); }
    let mut body = payload.to_vec();
    if !extension.is_empty() {
        if extension.len() > 65535 { return Err(FrameError("extension too long")); }
        flags |= 0x0004;
        body = Vec::with_capacity(2 + extension.len() + payload.len());
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(extension);
        body.extend_from_slice(payload);
    }
    if body.len() > MAX_PAYLOAD { return Err(FrameError("payload exceeds hard cap")); }
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&[0x4d, 0x50, VERSION, frame_type]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_frame(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < 10 { return Err(FrameError("frame shorter than fixed header")); }
    if data[0] != 0x4d || data[1] != 0x50 { return Err(FrameError("bad magic")); }
    if data[2] != VERSION { return Err(FrameError("unsupported frame version")); }
    let frame_type = data[3];
    let flags = u16::from_be_bytes([data[4], data[5]]);
    let length = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
    if length > MAX_PAYLOAD { return Err(FrameError("payload_length exceeds hard cap")); }
    if data.len() != 10 + length { return Err(FrameError("frame length mismatch")); }
    if (flags & !KNOWN_FLAGS) != 0 { return Err(FrameError("reserved flag bits set")); }
    if !known(frame_type) { return Err(FrameError("unknown frame type")); }
    let mut body = data[10..].to_vec();
    let mut extension = Vec::new();
    if (flags & 0x0004) != 0 {
        if body.len() < 2 { return Err(FrameError("extension header truncated")); }
        let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + ext_len { return Err(FrameError("extension body truncated")); }
        extension = body[2..2 + ext_len].to_vec();
        body = body[2 + ext_len..].to_vec();
    }
    Ok(Frame { frame_type, payload: body, extension })
}

pub fn encode_hello(protocol_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let id = if protocol_id.is_empty() { "0xmp.v1" } else { protocol_id };
    bytes_field(&mut out, 1, id.as_bytes());
    out
}

pub struct AuthResult {
    pub ok: bool,
    pub user_id: Vec<u8>,
    pub device_id: Vec<u8>,
}

pub fn sign_challenge(private_key_raw: &[u8], session_id: &str) -> Result<[u8; 64], FrameError> {
    if private_key_raw.len() != 32 {
        return Err(FrameError("Ed25519 seed must be 32 bytes"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(private_key_raw);
    Ok(SigningKey::from_bytes(&seed).sign(session_id.as_bytes()).to_bytes())
}

pub fn encode_auth(access_token: &str, device_id: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(&mut out, 1, access_token.as_bytes());
    bytes_field(&mut out, 2, device_id);
    bytes_field(&mut out, 4, signature);
    out
}

pub fn decode_auth_result(data: &[u8]) -> Result<AuthResult, FrameError> {
    let f = parse(data)?;
    Ok(AuthResult {
        ok: num(&f, 1) == 1,
        user_id: blob(&f, 2).unwrap_or(b"").to_vec(),
        device_id: blob(&f, 3).unwrap_or(b"").to_vec(),
    })
}

pub fn encode_sync_request(conversation_id: &[u8], after_sequence: u64, limit: u64) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(&mut out, 1, conversation_id);
    uint_field(&mut out, 2, after_sequence);
    uint_field(&mut out, 3, if limit == 0 { 100 } else { limit });
    out
}

pub fn encode_sync_ack(conversation_id: &[u8], applied_sequence: u64) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(&mut out, 1, conversation_id);
    uint_field(&mut out, 2, applied_sequence);
    out
}

pub fn encode_delivery_ack(message_id: &[u8], conversation_id: &[u8], sequence: u64) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(&mut out, 1, message_id);
    bytes_field(&mut out, 2, conversation_id);
    uint_field(&mut out, 3, sequence);
    out
}

pub fn encode_message_send(message_id: &[u8], conversation_id: &[u8], sender_device_id: &[u8],
                           idempotency_key: &[u8], body: &[u8], mut kind: u64, client_timestamp_ms: u64) -> Vec<u8> {
    if kind == 0 { kind = 1; }
    let mut content = Vec::new();
    uint_field(&mut content, 1, kind);
    bytes_field(&mut content, 2, body);
    let mut out = Vec::new();
    bytes_field(&mut out, 1, message_id);
    bytes_field(&mut out, 2, conversation_id);
    bytes_field(&mut out, 3, sender_device_id);
    uint_field(&mut out, 4, client_timestamp_ms);
    bytes_field(&mut out, 5, idempotency_key);
    bytes_field(&mut out, 6, &content);
    out
}

pub fn decode_accepted_sequence(data: &[u8]) -> Result<u64, FrameError> {
    Ok(num(&parse(data)?, 2))
}

pub fn decode_incoming(data: &[u8]) -> Result<Incoming, FrameError> {
    let f = parse(data)?;
    let content = parse(blob(&f, 7).unwrap_or(b""))?;
    Ok(Incoming {
        sequence: num(&f, 5),
        body: blob(&content, 2).unwrap_or(b"").to_vec(),
    })
}

pub fn decode_sync_batch(data: &[u8]) -> Result<SyncBatch, FrameError> {
    let f = parse(data)?;
    let mut events = Vec::new();
    if let Some(list) = f.get(&2) {
        for raw in list {
            if let Val::Bytes(raw) = raw {
                let ev = parse(raw)?;
                let message = match blob(&ev, 3) {
                    Some(m) => Some(decode_incoming(m)?),
                    None => None,
                };
                events.push(SyncEvent { sequence: num(&ev, 2), message });
            }
        }
    }
    Ok(SyncBatch { events, has_more: num(&f, 3) == 1, next_after_sequence: num(&f, 4) })
}

pub fn encode_delete(conversation_id: &[u8], message_id: &[u8], for_everyone: bool) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(&mut out, 1, message_id);
    bytes_field(&mut out, 2, conversation_id);
    uint_field(&mut out, 3, if for_everyone { 1 } else { 0 });
    out
}

fn to_hex(data: &[u8]) -> String { data.iter().map(|b| format!("{b:02x}")).collect() }

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_named(json: &str, name: &str) -> String {
        let key = format!("\"name\": \"{name}\"");
        let at = json.find(&key).unwrap_or_else(|| panic!("missing {name}"));
        let h = json[at..].find("\"hex\": \"").unwrap() + at + 8;
        let end = json[h..].find('"').unwrap() + h;
        json[h..end].to_string()
    }

    #[test]
    fn conformance() {
        let json = std::fs::read_to_string("clients/test_vectors.json")
            .or_else(|_| std::fs::read_to_string("../../clients/test_vectors.json"))
            .expect("vectors");
        assert_eq!(to_hex(&encode_frame(PING, b"", 0, b"").unwrap()), hex_named(&json, "ping_empty"));
        let hello = encode_frame(HELLO, &encode_hello("0xmp.v1"), 0, b"").unwrap();
        assert_eq!(to_hex(&hello), hex_named(&json, "hello_protocol_only"));
        assert_eq!(decode_frame(&hello).unwrap().frame_type, HELLO);
        let ext = encode_frame(PING, b"ab", 0, b"xy").unwrap();
        assert_eq!(to_hex(&ext), hex_named(&json, "ping_with_extension"));
        let decoded = decode_frame(&from_hex(&hex_named(&json, "ping_with_extension"))).unwrap();
        assert_eq!(decoded.extension, b"xy");
        assert_eq!(decoded.payload, b"ab");
        let neg_at = json.find("\"negative_frames\"").unwrap();
        let mut rest = &json[neg_at..];
        while let Some(i) = rest.find("\"hex\": \"") {
            let start = i + 8;
            let end = rest[start..].find('"').unwrap() + start;
            let value = &rest[start..end];
            assert!(decode_frame(&from_hex(value)).is_err(), "{value}");
            rest = &rest[end..];
        }
        assert_eq!(decode_accepted_sequence(&from_hex(&hex_named(&json, "message_accepted_seq1"))).unwrap(), 1);
        let mut body = b"cross-platform ".to_vec();
        body.extend_from_slice(&[0xe2, 0x9c, 0x93]);
        let ids = |start: u8| -> Vec<u8> { (0..16).map(|i| start + i).collect() };
        let sent = encode_message_send(&ids(0), &ids(16), &ids(32), &ids(48), &body, 1, 1700000000000);
        assert_eq!(to_hex(&sent), hex_named(&json, "message_send_fixed_ids"));
        let batch = decode_sync_batch(&from_hex(&hex_named(&json, "sync_batch_one_text"))).unwrap();
        assert!(!batch.has_more && batch.next_after_sequence == 1 && batch.events.len() == 1);
        assert_eq!(batch.events[0].sequence, 1);
        assert_eq!(batch.events[0].message.as_ref().unwrap().body, b"room history");
        let deleted = encode_delete(&[0x11; 16], b"", true);
        let fields = parse(&deleted).unwrap();
        assert_eq!(num(&fields, 3), 1);
        assert!(blob(&fields, 1).is_none());
        let ids = |start: u8| -> Vec<u8> { (0..16).map(|i| start + i).collect() };
        assert_eq!(
            to_hex(&encode_auth("token", &ids(0), &ids(16))),
            "0a05746f6b656e1210000102030405060708090a0b0c0d0e0f2210101112131415161718191a1b1c1d1e1f");
        assert!(decode_auth_result(&[0x08, 0x01]).unwrap().ok);
        let sig = sign_challenge(&(0..32).collect::<Vec<u8>>(), "0xmp-challenge").unwrap();
        assert_eq!(to_hex(&sig), concat!(
            "b914dcdda90eba28435578c0b7f1a4cff88245a7f13dfa866a9ad722bb7b2360",
            "6fcb63f2d80f8adac7f266c3631e09e8937324f494c35dd799059b8030ba110e"));
        assert_eq!(to_hex(&encode_sync_request(&ids(0), 7, 100)),
            "0a10000102030405060708090a0b0c0d0e0f10071864");
        assert_eq!(to_hex(&encode_sync_ack(&ids(0), 7)),
            "0a10000102030405060708090a0b0c0d0e0f1007");
        assert_eq!(to_hex(&encode_delivery_ack(&ids(0), &ids(16), 9)),
            "0a10000102030405060708090a0b0c0d0e0f1210101112131415161718191a1b1c1d1e1f1809");
    }
}
