use std::ffi::OsString;
use std::io::Write as _;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use super::*;
use crate::api::UploadFile;
use crate::env;
use crate::test_support::jobs::{
    ScriptedServer, accept_response, events_response, frame, response_handler, snapshot,
};
use crate::test_support::{MockServer, response};

fn environment(origin: &str) -> Environment {
    env::from_source(|name| match name {
        "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
        "GITHITS_API_URL" => Some(OsString::from(origin)),
        _ => None,
    })
    .expect("environment")
}

fn upload() -> UploadSet {
    UploadSet::try_new(vec![UploadFile {
        path: "Cargo.lock".into(),
        contents: "# lock\n".into(),
    }])
    .expect("upload")
}

#[test]
fn production_caller_pins_finite_and_per_read_stream_allowances() {
    assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(210));
    assert_eq!(STREAM_TIMEOUT, Duration::from_secs(60));
    let server = ScriptedServer::success("text", b"document");
    let api = HttpSbomApi::new(environment(&server.origin())).expect("client");
    let document = api
        .generate(upload(), OutputFormat::Text, &mut |_| Ok(()))
        .expect("document");
    assert_eq!(document.bytes, b"document");
    assert_eq!(server.requests().len(), 3);
}

fn stalled_response_error(headers: &[u8]) -> ApiError {
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let headers = headers.to_vec();
    let server = MockServer::respond_with_handler(move |mut stream| {
        stream.write_all(&headers).expect("headers");
        stream.flush().expect("flush");
        arrived_tx.send(()).expect("arrived");
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
    });
    let origin = server.origin();
    let (done_tx, done_rx) = mpsc::channel();
    let client = thread::spawn(move || {
        let api = HttpSbomApi::with_timeouts(
            environment(&origin),
            Duration::from_secs(1),
            STREAM_TIMEOUT,
        )
        .expect("client");
        let _ = done_tx.send(api.generate(upload(), OutputFormat::Text, &mut |_| Ok(())));
    });
    arrived_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("arrival");
    let result = done_rx.recv_timeout(Duration::from_secs(5));
    drop(release_tx);
    server.request();
    client.join().expect("client");
    result.expect("timeout completion").expect_err("timeout")
}

#[test]
fn header_timeout_remains_a_typed_transport_error() {
    let error = stalled_response_error(b"");
    assert!(matches!(&error, ApiError::Transport(source) if source.is_timeout()));
    assert!(error.to_string().contains("GITHITS_API_URL"));
    assert!(error.to_string().contains("proxy"));
    assert!(!format!("{error:?}").contains("test-token"));
}

#[test]
fn body_timeout_remains_a_typed_read_error() {
    let error = stalled_response_error(b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n");
    let timeout = match &error {
        ApiError::Read(source) => source
            .get_ref()
            .and_then(|s| s.downcast_ref::<reqwest::Error>()),
        _ => None,
    };
    assert!(timeout.is_some_and(reqwest::Error::is_timeout), "{error:?}");
    assert!(error.to_string().contains("GITHITS_API_URL"));
    assert!(error.to_string().contains("proxy"));
}

#[test]
fn established_read_timeout_reopens_but_initial_read_timeout_fails() {
    for established in [false, true] {
        established_case(established);
    }
}

fn established_case(established: bool) {
    let (hold_tx, hold_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let mut handlers: Vec<crate::test_support::jobs::Handler> = vec![Box::new(|mut s| {
        s.write_all(&accept_response()).expect("accept");
    })];
    handlers.push(Box::new(move |mut s| {
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").expect("headers");
            if established { s.write_all(&frame(&snapshot("queued", "queued", 0))).expect("snapshot"); }
            hold_tx.send(s).expect("hold socket");
            // Return so the listener can serve the reconnect while this socket stays open.
        }));
    if established {
        handlers.push(response_handler(events_response(&[snapshot(
            "succeeded",
            "succeeded",
            1,
        )])));
        handlers.push(response_handler(response(
            "200 OK",
            &[("Content-Type", "application/vnd.cyclonedx+json")],
            b"{}",
        )));
    }
    let server = ScriptedServer::with_handlers(handlers);
    let origin = server.origin();
    let client = thread::spawn(move || {
        let api = HttpSbomApi::with_timeouts(
            environment(&origin),
            REQUEST_TIMEOUT,
            Duration::from_secs(1),
        )
        .expect("client");
        let result = api.generate(upload(), OutputFormat::CycloneDx, &mut |_| Ok(()));
        done_tx.send(result).expect("completion");
    });
    let held = hold_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stream open");
    let result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("timeout completion");
    // Server completion proves any reconnect finished without waiting for EOF here.
    assert_eq!(server.requests().len(), if established { 4 } else { 2 });
    drop(held);
    client.join().expect("client");
    if established {
        assert_eq!(result.expect("recovered").bytes, b"{}");
    } else {
        assert!(matches!(result, Err(ApiError::Read(_))));
    }
}

#[test]
fn stream_can_outlive_read_allowance_without_a_total_deadline() {
    let allowance = Duration::from_secs(1);
    let (socket_tx, socket_rx) = mpsc::channel();
    let (callback_tx, callback_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let first = frame(&snapshot("queued", "queued", 0));
    let terminal = frame(&snapshot("succeeded", "succeeded", 1));
    let length = first.len() + terminal.len();
    let server = ScriptedServer::with_handlers(vec![
        Box::new(|mut s| {
            s.write_all(&accept_response()).expect("accept");
        }),
        Box::new(move |mut s| {
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).expect("headers");
            s.write_all(&first).expect("first");
            socket_tx.send(s).expect("socket");
        }),
        Box::new(|mut s| {
            s.write_all(&response(
                "200 OK",
                &[("Content-Type", "application/vnd.cyclonedx+json")],
                b"{}",
            ))
            .expect("result");
        }),
    ]);
    let origin = server.origin();
    let started = Instant::now();
    let client = thread::spawn(move || {
        let api = HttpSbomApi::with_timeouts(environment(&origin), REQUEST_TIMEOUT, allowance)
            .expect("client");
        let result = api.generate(upload(), OutputFormat::CycloneDx, &mut |p| {
            hold_queued(p, &callback_tx, &release_rx);
            Ok(())
        });
        done_tx.send(result).expect("completion");
    });
    callback_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("incremental callback before EOF");
    assert!(matches!(
        done_rx.recv_timeout(allowance * 2),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(started.elapsed() > allowance);
    let mut socket = socket_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("socket");
    socket.write_all(&terminal).expect("terminal");
    release_tx.send(()).expect("release");
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("completion")
            .expect("no total deadline")
            .bytes,
        b"{}"
    );
    client.join().expect("client");
    assert_eq!(server.requests().len(), 3, "one stream and no reconnect");
}

#[test]
fn terminal_or_callback_failure_releases_socket_before_eof() {
    for cancel in [false, true] {
        cancel_case(cancel);
    }
}

fn cancel_case(cancel: bool) {
    let (socket_tx, socket_rx) = mpsc::channel();
    let state = if cancel { "queued" } else { "succeeded" };
    let mut handlers: Vec<crate::test_support::jobs::Handler> = vec![Box::new(|mut s| {
        s.write_all(&accept_response()).expect("accept");
    })];
    handlers.push(Box::new(move |mut s| {
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").expect("headers");
            s.write_all(&frame(&snapshot(state, state, 0))).expect("snapshot");
            socket_tx.send(s).expect("socket");
        }));
    if !cancel {
        handlers.push(response_handler(response(
            "200 OK",
            &[("Content-Type", "application/vnd.cyclonedx+json")],
            b"{}",
        )));
    }
    let server = ScriptedServer::with_handlers(handlers);
    let api = HttpSbomApi::new(environment(&server.origin())).expect("client");
    let result = api.generate(upload(), OutputFormat::CycloneDx, &mut |_| {
        if cancel {
            Err(std::io::Error::other("writer closed"))
        } else {
            Ok(())
        }
    });
    if cancel {
        assert!(matches!(result, Err(ApiError::Progress(_))));
    } else {
        assert_eq!(result.expect("terminal").bytes, b"{}");
    }
    let mut socket = socket_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read bound");
    assert_eq!(socket.read(&mut [0]).expect("server sees release"), 0);
    assert_eq!(server.requests().len(), if cancel { 2 } else { 3 });
}

fn hold_queued(p: &ProgressEvent, arrived: &mpsc::Sender<()>, release: &mpsc::Receiver<()>) {
    if !matches!(p, ProgressEvent::Snapshot(p) if p.phase == crate::api::jobs::Phase::Queued) {
        return;
    }
    arrived.send(()).expect("callback");
    release
        .recv_timeout(Duration::from_secs(5))
        .expect("release");
}

#[test]
fn connect_timeout_bounds_a_stalled_tls_handshake() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let origin = format!("https://{}", listener.local_addr().expect("address"));
    let (accepted_tx, accepted_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("connection");
        accepted_tx.send(()).expect("accepted");
        let _ = release_rx.recv_timeout(Duration::from_secs(30));
        drop(stream);
    });
    let (done_tx, done_rx) = mpsc::channel();
    let client = thread::spawn(move || {
        let api = HttpSbomApi::new(environment(&origin)).expect("client");
        let _ = done_tx.send(api.generate(upload(), OutputFormat::Text, &mut |_| Ok(())));
    });
    accepted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accepted");
    let result = done_rx.recv_timeout(Duration::from_secs(22));
    drop(release_tx);
    server.join().expect("server");
    client.join().expect("client");
    let error = result
        .expect("connect deadline, before the 210s response budget")
        .expect_err("stalled handshake");
    assert!(error.to_string().contains("GITHITS_API_URL"));
    assert!(error.to_string().contains("proxy"));
    assert!(matches!(error, ApiError::Transport(source) if source.is_timeout()));
}

#[test]
fn rate_limit_nonzero_waits_share_the_exact_300_second_budget() {
    use crate::test_support::jobs::rate_limited;
    let server = ScriptedServer::respond_with(vec![
        rate_limited("150"),
        accept_response(),
        rate_limited("150"),
        events_response(&[snapshot("succeeded", "succeeded", 1)]),
        rate_limited("1"),
    ]);
    let mut api = HttpSbomApi::new(environment(&server.origin())).expect("client");
    api.sleep = |delay| assert_eq!(delay, Duration::from_secs(150));
    let mut delays = Vec::new();
    let error = api
        .generate(upload(), OutputFormat::CycloneDx, &mut |event| {
            if let ProgressEvent::RateLimited { delay, .. } = event {
                delays.push(*delay);
            }
            Ok(())
        })
        .expect_err("waiting budget exhausted");
    assert!(
        matches!(error, ApiError::Problem { retry_after, .. } if retry_after.as_deref() == Some("1"))
    );
    assert_eq!(delays, vec![Duration::from_secs(150); 2]);
    assert_eq!(server.requests().len(), 5);
}
