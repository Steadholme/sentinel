//! Dependency-light outbound HTTP/1.1 GET — the backbone of the Vitals + Watchtower feeds.
//!
//! Hindsight correlates live data from internal services (Vitals, Watchtower). Each fetch is a
//! tiny `GET` over the `holdfast` Docker network to a plaintext `http://service:port` URL, so
//! rather than pull in a full HTTP client (and an OpenSSL/TLS tree) we keep the estate's
//! dependency-light approach: a raw `tokio::net::TcpStream` HTTP/1.1 GET with a short timeout.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, malformed response)
//! collapses to `None`. Callers turn `None` into an "unavailable" feed, so a down or slow
//! backend NEVER errors or hangs a page load.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hard cap on the buffered response body. The JSON snapshots are small (a few hundred audit
/// events / metric samples); this only stops a misbehaving upstream from exhausting memory.
const MAX_BODY: usize = 4_194_304; // 4 MiB

/// `GET url`, returning the response BODY as a string, or `None` on ANY failure. `timeout`
/// bounds the whole connect + write + read so a stalled backend can never tie up a page load.
pub async fn fetch_text(url: &str, timeout: Duration) -> Option<String> {
    match tokio::time::timeout(timeout, fetch_body(url)).await {
        Ok(Ok(body)) => Some(body),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "feed fetch failed — marking unavailable");
            None
        }
        Err(_) => {
            tracing::warn!(url = %url, "feed fetch timed out — marking unavailable");
            None
        }
    }
}

/// Connect, send a minimal HTTP/1.1 GET, and return the response BODY (everything after the
/// header terminator). `Connection: close` lets us read to EOF without parsing the length. Only
/// plain `http://` is accepted (the internal hops are plaintext).
async fn fetch_body(url: &str) -> std::io::Result<String> {
    let (host, port, path) = parse_http_url(url).ok_or_else(|| io_err("invalid http URL"))?;
    let mut stream = TcpStream::connect((host.as_str(), port)).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: hindsight/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut acc: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_BODY {
            break;
        }
    }
    split_body(&acc)
}

/// Split a raw HTTP response into its body (the bytes after the first blank line), returned as a
/// lossy UTF-8 string for JSON parsing.
fn split_body(raw: &[u8]) -> std::io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("no HTTP header terminator"))?;
    Ok(String::from_utf8_lossy(&raw[sep + 4..]).into_owned())
}

/// Parse `http://host[:port]/path` into `(host, port, path)`. Minimal by design — the backend
/// URLs are operator-controlled service URLs, not arbitrary user input.
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Some((host, port, path))
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_body_extracts_payload_after_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(split_body(raw).unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn parse_http_url_variants() {
        assert_eq!(
            parse_http_url("http://vitals:8300/api/metrics"),
            Some(("vitals".to_string(), 8300, "/api/metrics".to_string()))
        );
        assert_eq!(
            parse_http_url("http://watchtower:8500"),
            Some(("watchtower".to_string(), 8500, "/".to_string()))
        );
        assert_eq!(parse_http_url("https://nope"), None);
        assert_eq!(parse_http_url("ftp://nope"), None);
    }
}
