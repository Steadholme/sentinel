//! Bounded, typed outbound HTTP/1.1 acquisition for Hindsight feeds.

use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{lookup_host, TcpStream};

use crate::view_contract::{ChannelId, ACQUISITION_CAP_BYTES};

const HEADER_CAP_BYTES: usize = 65_536;
const CHUNK_LINE_CAP_BYTES: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureKind {
    Dns,
    Connect,
    Timeout,
    Write,
    Read,
    InvalidStatusLine,
    InvalidFraming,
    InvalidUtf8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpAcquisition {
    ConfigurationAbsentOrInvalid,
    Unavailable(TransportFailureKind),
    NonSuccess { status: u16 },
    OversizeTruncated,
    CompleteBody(Vec<u8>),
}

pub async fn acquire(
    channel: ChannelId,
    endpoint: Option<&str>,
    timeout: Duration,
) -> HttpAcquisition {
    let Some(endpoint) = endpoint.filter(|value| !value.trim().is_empty()) else {
        return HttpAcquisition::ConfigurationAbsentOrInvalid;
    };
    let Some(target) = Target::parse(endpoint) else {
        return HttpAcquisition::ConfigurationAbsentOrInvalid;
    };
    let outcome = match tokio::time::timeout(timeout, fetch_response(&target)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(kind)) => HttpAcquisition::Unavailable(kind),
        Err(_) => HttpAcquisition::Unavailable(TransportFailureKind::Timeout),
    };
    tracing::debug!(
        channel = channel_token(channel),
        outcome = outcome_token(&outcome),
        "feed acquisition completed"
    );
    outcome
}

async fn fetch_response(target: &Target) -> Result<HttpAcquisition, TransportFailureKind> {
    let addresses = lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|_| TransportFailureKind::Dns)?;
    let mut connected = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            connected = Some(stream);
            break;
        }
    }
    let mut stream = connected.ok_or(TransportFailureKind::Connect)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: hindsight/0.2\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path = target.path,
        authority = target.authority,
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| TransportFailureKind::Write)?;
    stream
        .flush()
        .await
        .map_err(|_| TransportFailureKind::Write)?;

    let mut reader = BufReader::new(stream);
    let head = read_final_head(&mut reader).await?;
    if !(200..300).contains(&head.status) {
        return Ok(HttpAcquisition::NonSuccess {
            status: head.status,
        });
    }
    let body = if head.chunked {
        match read_chunked_body(&mut reader).await {
            Ok(body) => body,
            Err(ChunkReadError::Oversize) => return Ok(HttpAcquisition::OversizeTruncated),
            Err(ChunkReadError::Transport(kind)) => return Err(kind),
        }
    } else if let Some(length) = head.content_length {
        if length > ACQUISITION_CAP_BYTES {
            return Ok(HttpAcquisition::OversizeTruncated);
        }
        let mut body = vec![0_u8; length];
        read_exact_framed(&mut reader, &mut body).await?;
        require_eof(&mut reader).await?;
        body
    } else {
        let take_limit = u64::try_from(ACQUISITION_CAP_BYTES)
            .expect("acquisition cap fits u64")
            .checked_add(1)
            .expect("acquisition cap plus one fits u64");
        let mut body = Vec::new();
        reader
            .take(take_limit)
            .read_to_end(&mut body)
            .await
            .map_err(|_| TransportFailureKind::Read)?;
        if body.len() > ACQUISITION_CAP_BYTES {
            return Ok(HttpAcquisition::OversizeTruncated);
        }
        body
    };
    if std::str::from_utf8(&body).is_err() {
        return Ok(HttpAcquisition::Unavailable(
            TransportFailureKind::InvalidUtf8,
        ));
    }
    Ok(HttpAcquisition::CompleteBody(body))
}

#[cfg(test)]
fn parse_response(raw: &[u8]) -> HttpAcquisition {
    let (head, body) = match split_final_response(raw) {
        Ok(parts) => parts,
        Err(kind) => return HttpAcquisition::Unavailable(kind),
    };
    let parsed = match parse_head(head) {
        Ok(parsed) => parsed,
        Err(kind) => return HttpAcquisition::Unavailable(kind),
    };
    if !(200..300).contains(&parsed.status) {
        return HttpAcquisition::NonSuccess {
            status: parsed.status,
        };
    }

    let body = if parsed.chunked {
        match decode_chunked(body) {
            Ok(body) => body,
            Err(ChunkError::Oversize) => return HttpAcquisition::OversizeTruncated,
            Err(ChunkError::Framing) => {
                return HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
            }
        }
    } else if let Some(length) = parsed.content_length {
        if length > ACQUISITION_CAP_BYTES {
            return HttpAcquisition::OversizeTruncated;
        }
        if body.len() != length {
            return HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming);
        }
        body.to_vec()
    } else {
        if body.len() > ACQUISITION_CAP_BYTES {
            return HttpAcquisition::OversizeTruncated;
        }
        body.to_vec()
    };

    if body.len() > ACQUISITION_CAP_BYTES {
        return HttpAcquisition::OversizeTruncated;
    }
    if std::str::from_utf8(&body).is_err() {
        return HttpAcquisition::Unavailable(TransportFailureKind::InvalidUtf8);
    }
    HttpAcquisition::CompleteBody(body)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedHead {
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_head(head: &[u8]) -> Result<ParsedHead, TransportFailureKind> {
    let Ok(head_text) = std::str::from_utf8(head) else {
        return Err(TransportFailureKind::InvalidStatusLine);
    };
    let mut lines = head_text.split("\r\n");
    let Some(status_line) = lines.next() else {
        return Err(TransportFailureKind::InvalidStatusLine);
    };
    let status = parse_status_line(status_line)?;

    let mut content_lengths = Vec::new();
    let mut transfer_encodings = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(TransportFailureKind::InvalidFraming);
        };
        if !valid_header_name(name.as_bytes())
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(TransportFailureKind::InvalidFraming);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let Some(length) = parse_decimal_usize(value) else {
                return Err(TransportFailureKind::InvalidFraming);
            };
            content_lengths.push(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encodings.extend(
                value
                    .split(',')
                    .map(|part| part.trim().to_ascii_lowercase()),
            );
        }
    }
    if content_lengths.windows(2).any(|pair| pair[0] != pair[1])
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
        || transfer_encodings.len() > 1
        || transfer_encodings
            .first()
            .is_some_and(|value| value != "chunked")
    {
        return Err(TransportFailureKind::InvalidFraming);
    }
    Ok(ParsedHead {
        status,
        content_length: content_lengths.first().copied(),
        chunked: transfer_encodings
            .first()
            .is_some_and(|value| value == "chunked"),
    })
}

fn parse_decimal_usize(value: &str) -> Option<usize> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<usize>().ok()
}

async fn read_final_head<R>(reader: &mut R) -> Result<ParsedHead, TransportFailureKind>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let mut head = Vec::new();
        let mut consumed = 0usize;
        loop {
            let remaining = HEADER_CAP_BYTES
                .checked_sub(consumed)
                .ok_or(TransportFailureKind::InvalidFraming)?;
            let (line, line_bytes) = read_crlf_line(reader, remaining).await?;
            consumed = consumed
                .checked_add(line_bytes)
                .ok_or(TransportFailureKind::InvalidFraming)?;
            if line.is_empty() {
                break;
            }
            if !head.is_empty() {
                head.extend_from_slice(b"\r\n");
            }
            head.extend_from_slice(&line);
        }
        let parsed = parse_head(&head)?;
        if (100..200).contains(&parsed.status) {
            continue;
        }
        return Ok(parsed);
    }
}

async fn read_crlf_line<R>(
    reader: &mut R,
    cap: usize,
) -> Result<(Vec<u8>, usize), TransportFailureKind>
where
    R: AsyncBufRead + Unpin,
{
    let limit = cap
        .checked_add(1)
        .ok_or(TransportFailureKind::InvalidFraming)?;
    let mut line = Vec::new();
    let read = reader
        .take(u64::try_from(limit).map_err(|_| TransportFailureKind::InvalidFraming)?)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| TransportFailureKind::Read)?;
    if read == 0 || read > cap || !line.ends_with(b"\r\n") {
        return Err(TransportFailureKind::InvalidFraming);
    }
    line.truncate(line.len() - 2);
    Ok((line, read))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkReadError {
    Oversize,
    Transport(TransportFailureKind),
}

async fn read_chunked_body<R>(reader: &mut R) -> Result<Vec<u8>, ChunkReadError>
where
    R: AsyncBufRead + Unpin,
{
    let mut decoded = Vec::new();
    loop {
        let (line, _) = read_crlf_line(reader, CHUNK_LINE_CAP_BYTES)
            .await
            .map_err(ChunkReadError::Transport)?;
        let size = parse_chunk_size_line(&line)
            .map_err(|_| ChunkReadError::Transport(TransportFailureKind::InvalidFraming))?;
        if size == 0 {
            read_chunk_trailers(reader).await?;
            require_eof(reader)
                .await
                .map_err(ChunkReadError::Transport)?;
            return Ok(decoded);
        }
        let next_len = decoded
            .len()
            .checked_add(size)
            .ok_or(ChunkReadError::Oversize)?;
        if next_len > ACQUISITION_CAP_BYTES {
            return Err(ChunkReadError::Oversize);
        }
        let start = decoded.len();
        decoded.resize(next_len, 0);
        read_exact_framed(reader, &mut decoded[start..])
            .await
            .map_err(ChunkReadError::Transport)?;
        let mut terminator = [0_u8; 2];
        read_exact_framed(reader, &mut terminator)
            .await
            .map_err(ChunkReadError::Transport)?;
        if terminator != *b"\r\n" {
            return Err(ChunkReadError::Transport(
                TransportFailureKind::InvalidFraming,
            ));
        }
    }
}

async fn read_chunk_trailers<R>(reader: &mut R) -> Result<(), ChunkReadError>
where
    R: AsyncBufRead + Unpin,
{
    let mut consumed = 0usize;
    loop {
        let remaining = HEADER_CAP_BYTES
            .checked_sub(consumed)
            .ok_or(ChunkReadError::Transport(
                TransportFailureKind::InvalidFraming,
            ))?;
        let (line, line_bytes) = read_crlf_line(reader, remaining)
            .await
            .map_err(ChunkReadError::Transport)?;
        consumed = consumed
            .checked_add(line_bytes)
            .ok_or(ChunkReadError::Transport(
                TransportFailureKind::InvalidFraming,
            ))?;
        if line.is_empty() {
            return Ok(());
        }
        validate_trailer_line(&line)
            .map_err(|_| ChunkReadError::Transport(TransportFailureKind::InvalidFraming))?;
    }
}

async fn read_exact_framed<R>(reader: &mut R, buffer: &mut [u8]) -> Result<(), TransportFailureKind>
where
    R: tokio::io::AsyncRead + Unpin,
{
    reader
        .read_exact(buffer)
        .await
        .map(|_| ())
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                TransportFailureKind::InvalidFraming
            } else {
                TransportFailureKind::Read
            }
        })
}

async fn require_eof<R>(reader: &mut R) -> Result<(), TransportFailureKind>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut extra = [0_u8; 1];
    match reader
        .read(&mut extra)
        .await
        .map_err(|_| TransportFailureKind::Read)?
    {
        0 => Ok(()),
        _ => Err(TransportFailureKind::InvalidFraming),
    }
}

/// Skip any informational response and return the final response head/body.
#[cfg(test)]
fn split_final_response(mut raw: &[u8]) -> Result<(&[u8], &[u8]), TransportFailureKind> {
    loop {
        let separator = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(TransportFailureKind::InvalidStatusLine)?;
        if separator > HEADER_CAP_BYTES {
            return Err(TransportFailureKind::InvalidFraming);
        }
        let head = &raw[..separator];
        let status_line_end = head
            .windows(2)
            .position(|window| window == b"\r\n")
            .unwrap_or(head.len());
        let status_line = std::str::from_utf8(&head[..status_line_end])
            .map_err(|_| TransportFailureKind::InvalidStatusLine)?;
        let status = parse_status_line(status_line)?;
        let after = &raw[separator + 4..];
        if (100..200).contains(&status) {
            raw = after;
            continue;
        }
        return Ok((head, after));
    }
}

fn parse_status_line(line: &str) -> Result<u16, TransportFailureKind> {
    let bytes = line.as_bytes();
    let Some(rest) = bytes.strip_prefix(b"HTTP/1.1 ") else {
        return Err(TransportFailureKind::InvalidStatusLine);
    };
    if rest.len() < 4
        || !rest[..3].iter().all(u8::is_ascii_digit)
        || rest[3] != b' '
        || rest[4..]
            .iter()
            .any(|byte| byte.is_ascii_control() && *byte != b'\t')
    {
        return Err(TransportFailureKind::InvalidStatusLine);
    }
    let code =
        std::str::from_utf8(&rest[..3]).map_err(|_| TransportFailureKind::InvalidStatusLine)?;
    let status = code
        .parse::<u16>()
        .map_err(|_| TransportFailureKind::InvalidStatusLine)?;
    if !(100..=599).contains(&status) {
        return Err(TransportFailureKind::InvalidStatusLine);
    }
    Ok(status)
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize, ()> {
    let mut cursor = 0usize;
    let size_start = cursor;
    while line
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_hexdigit())
    {
        cursor += 1;
    }
    if cursor == size_start {
        return Err(());
    }
    let size_text = std::str::from_utf8(&line[size_start..cursor]).map_err(|_| ())?;
    let size = usize::from_str_radix(size_text, 16).map_err(|_| ())?;
    skip_ows(line, &mut cursor);
    while cursor < line.len() {
        if line[cursor] != b';' {
            return Err(());
        }
        cursor += 1;
        skip_ows(line, &mut cursor);
        let name_start = cursor;
        while line.get(cursor).is_some_and(|byte| is_token_byte(*byte)) {
            cursor += 1;
        }
        if cursor == name_start {
            return Err(());
        }
        skip_ows(line, &mut cursor);
        if line.get(cursor) == Some(&b'=') {
            cursor += 1;
            skip_ows(line, &mut cursor);
            if line.get(cursor) == Some(&b'"') {
                parse_quoted_string(line, &mut cursor)?;
            } else {
                let value_start = cursor;
                while line.get(cursor).is_some_and(|byte| is_token_byte(*byte)) {
                    cursor += 1;
                }
                if cursor == value_start {
                    return Err(());
                }
            }
            skip_ows(line, &mut cursor);
        }
    }
    Ok(size)
}

fn skip_ows(value: &[u8], cursor: &mut usize) {
    while value
        .get(*cursor)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn parse_quoted_string(value: &[u8], cursor: &mut usize) -> Result<(), ()> {
    if value.get(*cursor) != Some(&b'"') {
        return Err(());
    }
    *cursor += 1;
    loop {
        let byte = *value.get(*cursor).ok_or(())?;
        match byte {
            b'"' => {
                *cursor += 1;
                return Ok(());
            }
            b'\\' => {
                *cursor += 1;
                let escaped = *value.get(*cursor).ok_or(())?;
                if !(escaped == b'\t'
                    || escaped == b' '
                    || (0x21..=0x7e).contains(&escaped)
                    || escaped >= 0x80)
                {
                    return Err(());
                }
                *cursor += 1;
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => {
                *cursor += 1;
            }
            _ => return Err(()),
        }
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkError {
    Framing,
    #[cfg(test)]
    Oversize,
}

#[cfg(test)]
fn decode_chunked(mut encoded: &[u8]) -> Result<Vec<u8>, ChunkError> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(ChunkError::Framing)?;
        if line_end > CHUNK_LINE_CAP_BYTES {
            return Err(ChunkError::Framing);
        }
        let size = parse_chunk_size_line(&encoded[..line_end]).map_err(|_| ChunkError::Framing)?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            validate_chunk_trailer(encoded)?;
            return Ok(decoded);
        }
        if size > encoded.len() || encoded.len() < size.saturating_add(2) {
            return Err(ChunkError::Framing);
        }
        let next_len = decoded
            .len()
            .checked_add(size)
            .ok_or(ChunkError::Oversize)?;
        if next_len > ACQUISITION_CAP_BYTES {
            return Err(ChunkError::Oversize);
        }
        decoded.extend_from_slice(&encoded[..size]);
        if &encoded[size..size + 2] != b"\r\n" {
            return Err(ChunkError::Framing);
        }
        encoded = &encoded[size + 2..];
    }
}

#[cfg(test)]
fn validate_chunk_trailer(encoded: &[u8]) -> Result<(), ChunkError> {
    if encoded.len() > HEADER_CAP_BYTES {
        return Err(ChunkError::Framing);
    }
    if encoded == b"\r\n" {
        return Ok(());
    }
    let trailer = encoded.strip_suffix(b"\r\n").ok_or(ChunkError::Framing)?;
    if trailer.is_empty() {
        return Err(ChunkError::Framing);
    }
    for framed_line in trailer.split_inclusive(|byte| *byte == b'\n') {
        let line = framed_line
            .strip_suffix(b"\r\n")
            .ok_or(ChunkError::Framing)?;
        validate_trailer_line(line)?;
    }
    Ok(())
}

fn validate_trailer_line(line: &[u8]) -> Result<(), ChunkError> {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(ChunkError::Framing);
    };
    let (name, value_with_colon) = line.split_at(colon);
    if !valid_header_name(name)
        || value_with_colon[1..]
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(*byte, b'\t'))
    {
        return Err(ChunkError::Framing);
    }
    if name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
    {
        return Err(ChunkError::Framing);
    }
    Ok(())
}

fn valid_header_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|byte| is_token_byte(*byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Target {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Option<Self> {
        if !url.is_ascii()
            || url
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'#')
        {
            return None;
        }
        let uri = url.parse::<axum::http::Uri>().ok()?;
        if uri.scheme_str() != Some("http") {
            return None;
        }
        let authority = uri.authority()?.as_str();
        if authority.contains('@') || authority.contains('\\') {
            return None;
        }
        let host = uri.host()?.to_string();
        let port = uri.port_u16().unwrap_or(80);
        let path = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        if path.contains('#') || path.contains('\\') || !path.starts_with('/') {
            return None;
        }
        Some(Self {
            host,
            port,
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }
}

fn channel_token(channel: ChannelId) -> &'static str {
    match channel {
        ChannelId::Audit => "audit",
        ChannelId::Log => "log",
        ChannelId::Metric => "metric",
    }
}

fn outcome_token(outcome: &HttpAcquisition) -> &'static str {
    match outcome {
        HttpAcquisition::ConfigurationAbsentOrInvalid => "configuration-absent-or-invalid",
        HttpAcquisition::Unavailable(_) => "unavailable",
        HttpAcquisition::NonSuccess { .. } => "non-success",
        HttpAcquisition::OversizeTruncated => "oversize-truncated",
        HttpAcquisition::CompleteBody(_) => "complete-body",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_accepts_only_bounded_plain_http() {
        let target = Target::parse("http://vitals:8300/api/metrics").unwrap();
        assert_eq!(target.host, "vitals");
        assert_eq!(target.port, 8300);
        assert_eq!(target.path, "/api/metrics");
        assert!(Target::parse("https://vitals:8300/api/metrics").is_none());
        assert!(Target::parse("http://user@host/path").is_none());
        assert!(Target::parse("http://host\\evil/path").is_none());
        assert!(Target::parse("http://bad host/path").is_none());
        assert!(Target::parse("http://host/path with space").is_none());
        assert!(Target::parse("http://host/path#fragment").is_none());
    }

    #[test]
    fn content_length_and_status_remain_distinct() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            parse_response(ok),
            HttpAcquisition::CompleteBody(b"{}".to_vec())
        );
        let redirect = b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response(redirect),
            HttpAcquisition::NonSuccess { status: 302 }
        );
        let http_10 = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            parse_response(http_10),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidStatusLine)
        );
        let invalid_interim =
            b"BAD 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            parse_response(invalid_interim),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidStatusLine)
        );
        for invalid in [
            b" HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\x01\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        ] {
            assert_eq!(
                parse_response(invalid),
                HttpAcquisition::Unavailable(TransportFailureKind::InvalidStatusLine)
            );
        }
    }

    #[test]
    fn framing_and_utf8_fail_closed() {
        let conflict =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx";
        assert_eq!(
            parse_response(conflict),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
        );
        let signed_length = b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx";
        assert_eq!(
            parse_response(signed_length),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
        );
        let invalid_utf8 = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n\xff";
        assert_eq!(
            parse_response(invalid_utf8),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidUtf8)
        );

        let mut oversized_header = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
        oversized_header.resize(HEADER_CAP_BYTES + 1, b'a');
        oversized_header.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_response(&oversized_header),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
        );
    }

    #[test]
    fn chunked_body_decodes_without_loss() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(raw),
            HttpAcquisition::CompleteBody(b"{}".to_vec())
        );
        let with_trailer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nDigest: synthetic\r\n\r\n";
        assert_eq!(
            parse_response(with_trailer),
            HttpAcquisition::CompleteBody(b"{}".to_vec())
        );
        let garbage_trailer =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\ngarbage\r\n\r\n";
        assert_eq!(
            parse_response(garbage_trailer),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
        );
        let valid_extensions = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 \t; name = \"synthetic value\" ;flag\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(valid_extensions),
            HttpAcquisition::CompleteBody(b"{}".to_vec())
        );
        let invalid_extension =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;=bad\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(invalid_extension),
            HttpAcquisition::Unavailable(TransportFailureKind::InvalidFraming)
        );
    }

    #[tokio::test]
    async fn streaming_chunked_counts_decoded_bytes_not_framing_bytes() {
        let extension = "a".repeat(4_096);
        let mut encoded = Vec::new();
        for _ in 0..1_100 {
            encoded.extend_from_slice(format!("1;{extension}\r\nx\r\n").as_bytes());
        }
        encoded.extend_from_slice(b"0\r\n\r\n");
        assert!(encoded.len() > ACQUISITION_CAP_BYTES + HEADER_CAP_BYTES);

        let cursor = std::io::Cursor::new(encoded);
        let mut reader = BufReader::new(cursor);
        let decoded = read_chunked_body(&mut reader).await.unwrap();
        assert_eq!(decoded, vec![b'x'; 1_100]);
    }
}
