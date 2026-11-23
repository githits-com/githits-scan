//! Resolve explicit Go workspace membership inside the upload namespace.

use std::borrow::Cow;

use crate::catalog;

use super::relative_directory;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    Use,
    Other,
}

/// Yield the normalized `go.mod` paths named by valid local `use` directives.
pub(crate) fn members<'a>(
    workspace: &'a str,
    contents: &'a str,
) -> impl Iterator<Item = String> + 'a {
    let directory = workspace.rsplit_once('/').map_or("", |(parent, _)| parent);
    let mut block = None;
    contents.lines().filter_map(move |line| {
        let path = use_path(line.trim(), &mut block)?;
        if path.is_empty() || path.contains(['\\', ':', '\0']) {
            return None;
        }
        let directory = relative_directory(directory, &path)?;
        Some(if directory.is_empty() {
            catalog::GO_MANIFEST.to_owned()
        } else {
            format!("{directory}/{}", catalog::GO_MANIFEST)
        })
    })
}

fn use_path<'a>(line: &'a str, block: &mut Option<Block>) -> Option<Cow<'a, str>> {
    if comment_or_empty(line) {
        return None;
    }
    if let Some(mode) = *block {
        if line.strip_prefix(')').is_some_and(comment_or_empty) {
            *block = None;
            return None;
        }
        return (mode == Block::Use).then(|| path_word(line)).flatten();
    }
    let boundary = line.find(|ch: char| ch.is_ascii_whitespace() || ch == '(')?;
    let (verb, args) = line.split_at(boundary);
    let args = args.trim_start();
    if args.strip_prefix('(').is_some_and(comment_or_empty) {
        *block = Some(if verb == "use" {
            Block::Use
        } else {
            Block::Other
        });
        return None;
    }
    (verb == "use").then(|| path_word(args)).flatten()
}

fn comment_or_empty(value: &str) -> bool {
    let value = value.trim_start();
    value.is_empty() || value.starts_with("//")
}

fn path_word(line: &str) -> Option<Cow<'_, str>> {
    if let Some(quoted) = line.strip_prefix('"') {
        return quoted_path(quoted);
    }
    let word = line
        .split_once("//")
        .map_or(line, |(word, _)| word)
        .trim_end();
    (!word.is_empty()
        && !word
            .chars()
            .any(|ch| ch.is_whitespace() || "[]{}(),\"`'".contains(ch)))
    .then_some(Cow::Borrowed(word))
}

fn quoted_path(quoted: &str) -> Option<Cow<'_, str>> {
    let mut escaped = false;
    let close = quoted.char_indices().find_map(|(index, ch)| {
        if escaped {
            escaped = false;
            return None;
        }
        escaped = ch == '\\';
        (ch == '"').then_some(index)
    })?;
    if !comment_or_empty(&quoted[close + 1..]) {
        return None;
    }
    let body = &quoted[..close];
    if !body.contains('\\') {
        return Some(Cow::Borrowed(body));
    }
    unescape(body.as_bytes()).map(Cow::Owned)
}

// Go numeric escapes differ from JSON. Control-character and backslash
// paths cannot be multipart filenames, so control escapes need no decoding.
fn unescape(mut body: &[u8]) -> Option<String> {
    let mut output = Vec::with_capacity(body.len());
    while let Some((&byte, rest)) = body.split_first() {
        if byte != b'\\' {
            output.push(byte);
            body = rest;
            continue;
        }
        body = decode_escape(rest, &mut output)?;
    }
    String::from_utf8(output).ok()
}

fn decode_escape<'a>(body: &'a [u8], output: &mut Vec<u8>) -> Option<&'a [u8]> {
    let (&kind, rest) = body.split_first()?;
    let (digits, width, radix) = match kind {
        b'"' | b'\\' => {
            output.push(kind);
            return Some(rest);
        }
        b'0'..=b'7' => (body, 3, 8),
        b'x' => (rest, 2, 16),
        b'u' => (rest, 4, 16),
        b'U' => (rest, 8, 16),
        _ => return None,
    };
    let digits = digits.get(..width)?;
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let value = u32::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()?;
    if matches!(kind, b'u' | b'U') {
        let mut codepoint = [0; 4];
        output.extend_from_slice(
            char::from_u32(value)?
                .encode_utf8(&mut codepoint)
                .as_bytes(),
        );
    } else {
        output.push(u8::try_from(value).ok()?);
    }
    Some(if radix == 8 {
        &body[width..]
    } else {
        &rest[width..]
    })
}
