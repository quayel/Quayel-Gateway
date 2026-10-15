//! Read the TLS server name (SNI) from a connection without consuming it.
//!
//! The ClientHello is peeked: the bytes are put back, so whoever handles the
//! connection next (the HTTPS stack, a TLS-terminating stream, or a
//! passthrough target) sees an untouched handshake.

use pingora_core::protocols::Stream;
use std::time::Duration;

/// Largest TLS record (2^14) plus its 5-byte header.
const MAX_RECORD: usize = 5 + 16384;

pub enum Peeked {
    /// A TLS ClientHello; the server name if it carries one.
    Tls(Option<String>),
    /// Not TLS (first byte isn't a handshake record) or unparseable.
    Other,
}

/// Peek the first TLS record. Err(true) → the deadline passed, Err(false) →
/// the connection failed or closed first.
pub async fn peek_sni(stream: &mut Stream, deadline: Option<Duration>) -> Result<Peeked, bool> {
    let peek = async {
        let mut head = [0u8; 5];
        if !stream.try_peek(&mut head).await.map_err(|_| false)? {
            return Ok(Peeked::Other);
        }
        if head[0] != 0x16 || head[1] != 0x03 {
            return Ok(Peeked::Other);
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if len == 0 || 5 + len > MAX_RECORD {
            return Ok(Peeked::Other);
        }
        let mut record = vec![0u8; 5 + len];
        stream.try_peek(&mut record).await.map_err(|_| false)?;
        Ok(match parse_client_hello(&record[5..]) {
            Some(name) => Peeked::Tls(name),
            None => Peeked::Other,
        })
    };
    match deadline {
        Some(d) => tokio::time::timeout(d, peek).await.unwrap_or(Err(true)),
        None => peek.await,
    }
}

/// Server name from a ClientHello handshake message (record payload).
/// Some(None) → a valid ClientHello without SNI; None → not parseable (e.g.
/// the hello continues in a second record).
pub fn parse_client_hello(b: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(b);
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let hello_len = r.u24()? as usize;
    let mut r = Reader(r.take(hello_len)?);
    r.take(2 + 32)?; // client_version, random
    let n = r.u8()? as usize;
    r.take(n)?; // session_id
    let n = r.u16()? as usize;
    r.take(n)?; // cipher_suites
    let n = r.u8()? as usize;
    r.take(n)?; // compression_methods
    if r.0.is_empty() {
        return Some(None); // no extensions
    }
    let n = r.u16()? as usize;
    let mut ext = Reader(r.take(n)?);
    while !ext.0.is_empty() {
        let kind = ext.u16()?;
        let n = ext.u16()? as usize;
        let body = ext.take(n)?;
        if kind != 0x0000 {
            continue;
        }
        let mut list = Reader(body);
        let n = list.u16()? as usize;
        let mut list = Reader(list.take(n)?);
        while !list.0.is_empty() {
            let name_type = list.u8()?;
            let n = list.u16()? as usize;
            let name = list.take(n)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name).ok()?;
                return Some(Some(name.trim_end_matches('.').to_ascii_lowercase()));
            }
        }
        return Some(None);
    }
    Some(None)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ClientHello record, with an SNI extension if `name` is set.
    pub(crate) fn client_hello(name: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        // An unrelated extension first (supported_versions).
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if let Some(name) = name {
            let n = name.len() as u16;
            ext.extend_from_slice(&[0x00, 0x00]);
            ext.extend_from_slice(&(n + 5).to_be_bytes());
            ext.extend_from_slice(&(n + 3).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&n.to_be_bytes());
            ext.extend_from_slice(name.as_bytes());
        }
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[7u8; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        hello.extend_from_slice(&[0x01, 0x00]); // null compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut msg = vec![0x01];
        msg.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&hello);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    #[test]
    fn parses_sni_and_lowercases() {
        let rec = client_hello(Some("DB-7f3a.Redis.Example.com."));
        assert_eq!(
            parse_client_hello(&rec[5..]),
            Some(Some("db-7f3a.redis.example.com".to_string()))
        );
        assert_eq!(parse_client_hello(&client_hello(None)[5..]), Some(None));
    }

    #[test]
    fn truncated_or_garbage_is_none() {
        let rec = client_hello(Some("a.example.com"));
        assert_eq!(parse_client_hello(&rec[5..rec.len() - 3]), None);
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), None);
    }

    async fn pair() -> (Stream, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = tokio::net::TcpStream::connect(l.local_addr().unwrap())
            .await
            .unwrap();
        let (s, _) = l.accept().await.unwrap();
        (
            Box::new(pingora_core::protocols::l4::stream::Stream::from(s)),
            c,
        )
    }

    #[tokio::test]
    async fn peek_leaves_the_bytes_in_place() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut s, mut c) = pair().await;
        let rec = client_hello(Some("x.example.com"));
        // Split across two writes, as a real client may.
        c.write_all(&rec[..20]).await.unwrap();
        let rest = rec[20..].to_vec();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c.write_all(&rest).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        match peek_sni(&mut s, Some(Duration::from_secs(2))).await {
            Ok(Peeked::Tls(Some(n))) => assert_eq!(n, "x.example.com"),
            _ => panic!("no sni"),
        }
        let mut back = vec![0u8; rec.len()];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(back, rec);
    }

    #[tokio::test]
    async fn plain_http_and_silence() {
        use tokio::io::AsyncWriteExt;
        let (mut s, mut c) = pair().await;
        c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(
            peek_sni(&mut s, Some(Duration::from_secs(1))).await,
            Ok(Peeked::Other)
        ));
        let (mut s, _c) = pair().await;
        assert!(matches!(
            peek_sni(&mut s, Some(Duration::from_millis(200))).await,
            Err(true)
        ));
    }
}
