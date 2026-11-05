//! Incremental, bounded SSE framing. EOF discards an unfinished frame.

use std::io::BufRead;

use super::{ApiError, MAX_EVENT_BYTES};

pub(super) struct Event {
    pub id: String,
    pub data: Vec<u8>,
}

pub(super) struct Events<R> {
    reader: R,
    skip_lf: bool,
}

impl<R: BufRead> Events<R> {
    pub(super) const fn new(reader: R) -> Self {
        Self {
            reader,
            skip_lf: false,
        }
    }

    pub(super) fn next(&mut self) -> Result<Option<Event>, ApiError> {
        next_event(self)
    }
}

fn next_event<R: BufRead>(events: &mut Events<R>) -> Result<Option<Event>, ApiError> {
    let mut frame = Frame::default();
    let mut line = Vec::new();
    let mut size = 0;
    loop {
        let mut byte = [0];
        if events.reader.read(&mut byte).map_err(ApiError::Read)? == 0 {
            return Ok(None);
        }
        if events.skip_lf && byte[0] == b'\n' {
            events.skip_lf = false;
            continue;
        }
        events.skip_lf = byte[0] == b'\r';
        // Reserve the optional LF of CRLF before dispatching on CR, so
        // a standalone CR frame can still be delivered without lookahead.
        size += if byte[0] == b'\r' { 2 } else { 1 };
        if size > MAX_EVENT_BYTES {
            return Err(ApiError::protocol("progress event exceeds the frame limit"));
        }
        if !matches!(byte[0], b'\r' | b'\n') {
            line.push(byte[0]);
            continue;
        }
        if !line.is_empty() {
            frame.line(&line)?;
            line.clear();
            continue;
        }
        if frame.name == "snapshot" && !frame.data.is_empty() {
            return Ok(Some(Event {
                id: frame.id,
                data: frame.data,
            }));
        }
        frame = Frame::default();
        size = 0;
    }
}

#[derive(Default)]
struct Frame {
    name: String,
    id: String,
    data: Vec<u8>,
}

impl Frame {
    fn line(&mut self, bytes: &[u8]) -> Result<(), ApiError> {
        let line = std::str::from_utf8(bytes)
            .map_err(|_| ApiError::protocol("analysis event is not UTF-8"))?;
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => value.clone_into(&mut self.name),
            "id" => value.clone_into(&mut self.id),
            "data" => {
                append_data(&mut self.data, value);
            }
            _ => {}
        }
        Ok(())
    }
}

fn append_data(data: &mut Vec<u8>, value: &str) {
    if !data.is_empty() {
        data.push(b'\n');
    }
    data.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    #[test]
    fn line_endings_comments_multiline_and_split_utf8_are_incremental() {
        for ending in ["\n", "\r\n", "\r"] {
            let bytes = [
                ": keepalive",
                "",
                "event: unknown",
                "data: ignored",
                "",
                "event: snapshot",
                "id: 7",
                "data: {\"label\":",
                "data: \"é\"}",
                "",
                "",
            ]
            .join(ending)
            .into_bytes();
            let mut events = Events::new(BufReader::with_capacity(1, Cursor::new(bytes)));
            let event = events.next().expect("frame").expect("snapshot");
            assert_eq!(event.id, "7");
            assert_eq!(event.data, "{\"label\":\n\"é\"}".as_bytes());
            assert!(events.next().expect("EOF").is_none());
        }
    }

    #[test]
    fn unfinished_frames_are_not_published() {
        let mut events = Events::new(Cursor::new(b"event: snapshot\nid: 1\ndata: {}\n"));
        assert!(events.next().expect("EOF").is_none());
    }

    #[test]
    fn frame_cap_applies_even_to_comments_and_unknown_events() {
        for prefix in [
            ": ",
            "event: unknown\ndata: ",
            "event: snapshot\nid: 0\ndata: ",
        ] {
            let mut bytes = prefix.as_bytes().to_vec();
            bytes.resize(MAX_EVENT_BYTES - 2, b'x');
            bytes.extend_from_slice(b"\n\n");
            let mut events = Events::new(Cursor::new(&bytes));
            assert!(events.next().is_ok(), "at cap");
            bytes.insert(prefix.len(), b'x');
            let mut events = Events::new(Cursor::new(bytes));
            assert!(
                matches!(events.next(), Err(ApiError::Protocol { .. })),
                "one past cap"
            );
        }
    }
}
