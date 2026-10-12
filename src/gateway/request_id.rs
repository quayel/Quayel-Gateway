//! Request IDs (`X-QG-Request-Id`).
//!
//! Every request gets an ID that is written to the access log, sent to the
//! upstream and returned to the client in the same header. When the client
//! (or a proxy in front) already sent a well-formed `X-QG-Request-Id`, it is
//! reused so one ID follows the request through every hop. Otherwise a random
//! 128-bit ID is generated, so IDs never repeat across restarts or instances.

use http::HeaderMap;

pub const HEADER: &str = "x-qg-request-id";

/// Longest incoming ID that is reused. Longer ones are replaced.
const MAX_INCOMING_LEN: usize = 128;

/// A new random ID: 32 lowercase hex characters (128 bits).
pub fn generate() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// The incoming `X-QG-Request-Id` when it is safe to reuse: 1-128 characters
/// from `A-Z a-z 0-9 - _ . : / + =` (covers UUIDs, ULIDs, trace IDs and
/// base64). Anything else is ignored so log lines and headers stay clean.
pub fn incoming(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(HEADER)?.to_str().ok()?;
    let valid = !value.is_empty()
        && value.len() <= MAX_INCOMING_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/+=".contains(&b));
    valid.then_some(value)
}

/// The ID for this request: the incoming one when allowed and valid, else new.
pub fn resolve(headers: &HeaderMap, accept_incoming: bool) -> String {
    if accept_incoming {
        if let Some(id) = incoming(headers) {
            return id.to_string();
        }
    }
    generate()
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
    fn generated_ids_are_128_bit_hex_and_unique() {
        let a = generate();
        let b = generate();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn valid_incoming_id_is_reused() {
        let uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        assert_eq!(resolve(&headers(uuid), true), uuid);
        assert_eq!(resolve(&headers("abc+/=_.:"), true), "abc+/=_.:");
    }

    #[test]
    fn incoming_id_ignored_when_not_accepted() {
        let id = resolve(&headers("client-chosen"), false);
        assert_ne!(id, "client-chosen");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn bad_incoming_ids_are_replaced() {
        for bad in [
            "has space",
            "quote\"",
            "semi;colon",
            "{json}",
            &"a".repeat(129),
        ] {
            let id = resolve(&headers(bad), true);
            assert_ne!(id, bad);
            assert_eq!(id.len(), 32, "{bad}");
        }
        assert_eq!(resolve(&HeaderMap::new(), true).len(), 32);
        assert_eq!(resolve(&headers(&"a".repeat(128)), true), "a".repeat(128));
    }
}
