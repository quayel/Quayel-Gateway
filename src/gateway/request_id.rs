//! Request IDs (`X-QG-Request-Id`).
//!
//! Every request gets an ID, created first thing in `early_request_filter`
//! (before ACME, protection and every plugin), so blocked and refused
//! requests carry one too. It is written to the access log, sent to the
//! upstream and returned to the client in the same header.
//!
//! IDs are UUIDv7 (RFC 9562): 48-bit Unix milliseconds, then random bits, in
//! the standard 36-character form. They sort by time, never repeat across
//! restarts or instances, and fit ClickHouse's native `UUID` column. When the
//! client (or a proxy in front) already sent a valid UUID in
//! `X-QG-Request-Id`, it is reused so one ID follows the request through every
//! hop; anything else is replaced.

use http::HeaderMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HEADER: &str = "x-qg-request-id";

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A new UUIDv7 for the current time.
pub fn generate() -> String {
    generate_at(now_ms())
}

/// A new UUIDv7 whose time part is `ms` (Unix milliseconds).
pub fn generate_at(ms: u64) -> String {
    let random: u128 = rand::random();
    let mut v = ((ms as u128) & 0xFFFF_FFFF_FFFF) << 80 | (random & ((1u128 << 80) - 1));
    v = (v & !(0xF << 76)) | (0x7 << 76); // version 7
    v = (v & !(0b11 << 62)) | (0b10 << 62); // RFC 9562 variant
    encode(v)
}

fn encode(v: u128) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 36];
    let mut nibble = 0;
    for (i, slot) in out.iter_mut().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            *slot = b'-';
            continue;
        }
        *slot = HEX[((v >> (124 - nibble * 4)) & 0xF) as usize];
        nibble += 1;
    }
    // Only ASCII hex digits and dashes were written.
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

/// True for the canonical UUID text form (any version, either case).
pub fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The incoming `X-QG-Request-Id` when it is a valid UUID.
pub fn incoming(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(HEADER)?.to_str().ok()?;
    is_uuid(value).then_some(value)
}

/// The ID for this request: the incoming one when allowed and valid, else a
/// new UUIDv7 stamped with `ms`.
pub fn resolve(headers: &HeaderMap, accept_incoming: bool, ms: u64) -> String {
    if accept_incoming {
        if let Some(id) = incoming(headers) {
            return id.to_string();
        }
    }
    generate_at(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HEADER, v.parse().unwrap());
        h
    }

    #[test]
    fn generated_ids_are_uuidv7_and_unique() {
        let a = generate();
        let b = generate();
        assert!(is_uuid(&a), "{a}");
        assert_ne!(a, b);
        assert_eq!(&a[14..15], "7", "version nibble");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"), "variant: {a}");
    }

    #[test]
    fn time_part_is_the_millisecond_timestamp() {
        let ms = 0x0192_d4e8_7c1a;
        let id = generate_at(ms);
        assert!(id.starts_with("0192d4e8-7c1a-7"), "{id}");
        // Later milliseconds sort after earlier ones.
        assert!(generate_at(ms + 1) > id);
    }

    #[test]
    fn valid_incoming_uuid_is_reused() {
        let uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        assert_eq!(resolve(&headers(uuid), true, 1), uuid);
        let upper = "3F2504E0-4F89-11D3-9A0C-0305E82C3301";
        assert_eq!(resolve(&headers(upper), true, 1), upper);
    }

    #[test]
    fn incoming_id_ignored_when_not_accepted() {
        let uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let id = resolve(&headers(uuid), false, 1);
        assert_ne!(id, uuid);
        assert!(is_uuid(&id));
    }

    #[test]
    fn non_uuid_incoming_ids_are_replaced() {
        for bad in [
            "client-chosen",
            "has space",
            "3f2504e0-4f89-11d3-9a0c-0305e82c330",   // short
            "3f2504e0-4f89-11d3-9a0c-0305e82c33011", // long
            "3f2504e04f8911d39a0c0305e82c3301",      // no dashes
            "3f2504e0-4f89-11d3-9a0c-0305e82c330g",  // not hex
        ] {
            let id = resolve(&headers(bad), true, 1);
            assert_ne!(id, bad);
            assert!(is_uuid(&id), "{bad}");
        }
        assert!(is_uuid(&resolve(&HeaderMap::new(), true, 1)));
    }
}
