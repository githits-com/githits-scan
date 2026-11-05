//! Deterministic multi-exchange loopback fixtures for the job protocol.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use super::{DEADLINE, read_request, response};

pub const ID: &str = "01900000-0000-7000-8000-000000000001";
pub const BASE: &str = "/v1/experimental/lockfile-jobs/01900000-0000-7000-8000-000000000001";

pub fn accepted() -> serde_json::Value {
    serde_json::json!({"id": ID, "state": "queued", "expires_at": "2026-10-12T12:00:00Z", "status_url": BASE, "events_url": format!("{BASE}/events"), "result_url": format!("{BASE}/result")})
}

pub fn snapshot(state: &str, phase: &str, revision: u64) -> serde_json::Value {
    serde_json::json!({"id": ID, "kind": "sbom", "format": "cyclonedx", "state": state, "attempt": 1, "phase": phase, "counts": {}, "error": null, "result_url": format!("{BASE}/result"), "expires_at": "2026-10-12T12:00:00Z", "revision": revision})
}

pub fn accept_response() -> Vec<u8> {
    response(
        "202 Accepted",
        &[("Content-Type", "application/json")],
        &serde_json::to_vec(&accepted()).expect("json"),
    )
}

pub fn frame(value: &serde_json::Value) -> Vec<u8> {
    format!(
        "event: snapshot\nid: {}\ndata: {}\n\n",
        value["revision"], value
    )
    .into_bytes()
}

pub fn events_response(values: &[serde_json::Value]) -> Vec<u8> {
    let body: Vec<u8> = values.iter().flat_map(frame).collect();
    response(
        "200 OK",
        &[
            ("Content-Type", "text/event-stream"),
            ("X-Request-ID", "req-events"),
        ],
        &body,
    )
}

pub type Handler = Box<dyn FnOnce(TcpStream) + Send>;

pub struct ScriptedServer {
    address: SocketAddr,
    requests: Receiver<Vec<Vec<u8>>>,
}

impl ScriptedServer {
    pub fn respond_with(responses: Vec<Vec<u8>>) -> Self {
        Self::with_handlers(responses.into_iter().map(response_handler).collect())
    }

    pub fn success(format: &str, document: &[u8]) -> Self {
        let mut terminal = snapshot("succeeded", "succeeded", 1);
        terminal["format"] = format.into();
        let media = [
            ("cyclonedx", "application/vnd.cyclonedx+json"),
            ("spdx", "text/spdx"),
            ("text", "text/plain"),
        ]
        .into_iter()
        .find_map(|(name, media)| (name == format).then_some(media))
        .expect("supported fixture format");
        Self::respond_with(vec![
            accept_response(),
            events_response(&[terminal]),
            response(
                "200 OK",
                &[("Content-Type", &format!("{media}; charset=utf-8"))],
                document,
            ),
        ])
    }

    pub fn with_handlers(handlers: Vec<Handler>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let (sender, requests) = mpsc::channel();
        thread::spawn(move || serve(&listener, handlers, &sender));
        Self { address, requests }
    }

    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn requests(self) -> Vec<Vec<u8>> {
        self.requests
            .recv_timeout(Duration::from_secs(30))
            .expect("expected exchanges did not complete")
    }
}

pub fn response_handler(bytes: Vec<u8>) -> Handler {
    Box::new(move |mut stream| {
        // Client limit/cancellation cases deliberately stop reading.
        let _ = stream.write_all(&bytes);
    })
}

fn serve(listener: &TcpListener, handlers: Vec<Handler>, sender: &mpsc::Sender<Vec<Vec<u8>>>) {
    let mut requests = Vec::new();
    for handler in handlers {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(DEADLINE))
            .expect("read deadline");
        stream
            .set_write_timeout(Some(DEADLINE))
            .expect("write deadline");
        requests.push(read_request(&stream));
        handler(stream);
    }
    let _ = sender.send(requests);
}
