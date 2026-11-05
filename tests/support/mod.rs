//! Shared helpers for unit and integration tests: a synthetic repository builder
//! and a single-request loopback HTTP server.

// Keep Clippy's test-specific policy active for these shared helpers.
#![cfg(test)]
#![expect(dead_code, reason = "each test binary uses a subset of the helpers")]
#![expect(
    unreachable_pub,
    reason = "helpers are shared by unit and integration test modules"
)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

/// Longest a test waits for the client to send a request or for the server
/// to finish serving it. A regression that never sends fails instead of
/// hanging the suite.
const DEADLINE: Duration = Duration::from_secs(30);

use tempfile::TempDir;

pub mod audit;
pub mod jobs;

/// A synthetic repository with the given files (relative path, contents).
pub fn repository(files: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (relative, contents) in files {
        write_file(&dir.path().join(relative), contents.as_bytes());
    }
    dir
}

pub fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write file");
}

/// Serves exactly one HTTP/1.1 request on a loopback port and records it.
pub struct MockServer {
    address: SocketAddr,
    request: Receiver<Vec<u8>>,
}

impl MockServer {
    /// Start a server that answers the next request with `response` (raw
    /// bytes, status line included).
    pub fn respond_with(response: Vec<u8>) -> Self {
        Self::respond_with_handler(move |mut stream| {
            stream.write_all(&response).expect("write response");
            stream.flush().expect("flush response");
        })
    }

    /// Run a response handler after reading the complete request. Tests can
    /// hold headers or body behind an event without racing the upload.
    pub fn respond_with_handler(handler: impl FnOnce(TcpStream) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let (sender, request) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(DEADLINE))
                .expect("read timeout");
            stream
                .set_write_timeout(Some(DEADLINE))
                .expect("write timeout");
            let bytes = read_request(&stream);
            handler(stream);
            sender.send(bytes).expect("deliver request");
        });
        Self { address, request }
    }

    /// Origin to put in `GITHITS_API_URL`.
    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The raw request bytes the server received; fails after the deadline.
    pub fn request(self) -> Vec<u8> {
        self.request
            .recv_timeout(DEADLINE)
            .expect("the client never completed a request")
    }
}

fn read_request(stream: &TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = Vec::new();
        reader
            .read_until(b'\n', &mut line)
            .expect("read header line");
        request.extend_from_slice(&line);
        let text = String::from_utf8_lossy(&line);
        if let Some(value) = text.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().expect("content-length");
        }
        if line == b"\r\n" || line.is_empty() {
            break;
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).expect("read body");
    request.extend_from_slice(&body);
    request
}

/// Build a raw HTTP/1.1 response.
pub fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(body);
    bytes
}

/// The request head (everything before the body) lower-cased for
/// case-insensitive header assertions.
pub fn head(request: &[u8]) -> String {
    let text = String::from_utf8_lossy(request);
    let end = text.find("\r\n\r\n").unwrap_or(text.len());
    text[..end].to_ascii_lowercase()
}

/// The request body as text.
pub fn body(request: &[u8]) -> String {
    let text = String::from_utf8_lossy(request).into_owned();
    let start = text.find("\r\n\r\n").map_or(text.len(), |i| i + 4);
    text[start..].to_owned()
}
