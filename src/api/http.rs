//! Blocking job transport: one submission, latest-snapshot SSE, one capped result.
//!
//! Finite and streaming clients share security policy but have separate client-level
//! read allowances. A request-level timeout in locked reqwest would impose a whole-
//! stream deadline. No redirect, submission retry, polling or result fallback exists.

use std::io::{BufReader, Read as _};
use std::time::Duration;

use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{ACCEPT, HeaderMap, RETRY_AFTER};
use reqwest::redirect::Policy;
use url::Url;

use super::jobs::{Accepted, Snapshot, State};
use super::sse::Events;
use super::{
    ApiError, AuditApi, CLIENT_NAME, CLIENT_VERSION, Document, JOBS_PATH, LICENSES_PATH,
    LicensesApi, MAX_EVENT_BYTES, MAX_PROBLEM_BYTES, MAX_RESPONSE_BYTES, Operation, OutputFormat,
    ProgressEvent, REQUEST_TIMEOUT, STREAM_TIMEOUT, SbomApi, UploadSet, audit, licenses, problem,
};
use crate::env::{Environment, Token};

const REQUEST_ID: &str = "x-request-id";

/// HTTP client for asynchronous SBOM generation and audit.
pub struct HttpSbomApi {
    client: Client,
    events: Client,
    endpoint: Url,
    token: Token,
}

impl std::fmt::Debug for HttpSbomApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpSbomApi")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl HttpSbomApi {
    /// Build clients using the environment's validated origin and bearer.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Transport`] when TLS cannot be initialized.
    pub fn new(environment: Environment) -> Result<Self, ApiError> {
        Self::with_timeouts(environment, REQUEST_TIMEOUT, STREAM_TIMEOUT)
    }

    fn with_timeouts(
        environment: Environment,
        finite: Duration,
        stream: Duration,
    ) -> Result<Self, ApiError> {
        let mut endpoint = environment.origin;
        endpoint.set_path(JOBS_PATH);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(Self {
            client: client(finite)?,
            events: client(stream)?,
            endpoint,
            token: environment.token,
        })
    }

    /// The submission URL, before its kind/format query is added.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    fn execute<T>(
        &self,
        upload: UploadSet,
        operation: Operation,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
        decode: impl FnOnce(Vec<u8>) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let job = self.submit(upload, operation)?;
        wait(self, &job, operation, progress)?;
        progress(&ProgressEvent::Downloading).map_err(ApiError::Progress)?;
        self.result(&job, operation, decode)
    }

    fn authenticate(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .bearer_auth(self.token.expose())
            .header("X-GitHits-Client-Name", CLIENT_NAME)
            .header("X-GitHits-Client-Version", CLIENT_VERSION)
    }

    fn submit(&self, upload: UploadSet, operation: Operation) -> Result<Accepted, ApiError> {
        let mut form = Form::new().percent_encode_noop();
        for file in upload.into_files() {
            let part = Part::text(file.contents)
                .file_name(file.path)
                .mime_str("application/octet-stream")
                .map_err(ApiError::Transport)?;
            form = form.part("files[]", part);
        }
        let mut url = self.endpoint.clone();
        url.set_query(Some(&format!(
            "kind={}&format={}",
            operation.kind(),
            operation.format()
        )));
        let response = self
            .authenticate(self.client.post(url))
            .multipart(form)
            .send()
            .map_err(ApiError::Transport)?;
        let response = expect_status(response, 202)?;
        let request_id = header(response.headers(), REQUEST_ID);
        let accepted = (|| {
            require_media(&response, "application/json")?;
            Accepted::parse(&read_capped(response, MAX_EVENT_BYTES)?)
        })();
        accepted.map_err(|error| error.with_request_id(request_id))
    }

    fn result<T>(
        &self,
        job: &Accepted,
        operation: Operation,
        decode: impl FnOnce(Vec<u8>) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let path = match operation {
            Operation::Licenses => format!("{LICENSES_PATH}/{}", job.id),
            Operation::Sbom(_) | Operation::Audit => job.result_url.clone(),
        };
        let url = Accepted::resolve(&self.endpoint, &path)?;
        let response = self
            .authenticate(self.client.get(url))
            .send()
            .map_err(ApiError::Transport)?;
        let response = expect_status(response, 200)?;
        let request_id = header(response.headers(), REQUEST_ID);
        require_media(&response, media(operation))
            .map_err(|error| error.with_request_id(request_id.clone()))?;
        let bytes = read_bounded(response, MAX_RESPONSE_BYTES)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge);
        }
        decode(bytes).map_err(|error| error.with_request_id(request_id))
    }
}

impl SbomApi for HttpSbomApi {
    fn generate(
        &self,
        upload: UploadSet,
        format: OutputFormat,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Document, ApiError> {
        self.execute(upload, Operation::Sbom(format), progress, |bytes| {
            Ok(Document { bytes })
        })
    }
}

impl AuditApi for HttpSbomApi {
    fn audit(
        &self,
        upload: UploadSet,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<audit::Report, ApiError> {
        self.execute(upload, Operation::Audit, progress, |bytes| {
            audit::Report::from_bytes(&bytes)
        })
    }
}

impl LicensesApi for HttpSbomApi {
    fn report(
        &self,
        upload: UploadSet,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<licenses::Report, ApiError> {
        self.execute(upload, Operation::Licenses, progress, |bytes| {
            licenses::Report::from_bytes(bytes).map_err(|error| ApiError::protocol(error.reason()))
        })
    }
}

fn wait(
    api: &HttpSbomApi,
    job: &Accepted,
    operation: Operation,
    progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
) -> Result<(), ApiError> {
    let url = Accepted::resolve(&api.endpoint, &job.events_url)?;
    let mut revision = None;
    loop {
        // Every opening constructs a fresh authenticated request. There is no
        // replay promise and no token renewal mechanism in a process environment.
        let response = api
            .authenticate(api.events.get(url.clone()))
            .header(ACCEPT, "text/event-stream")
            .send()
            .map_err(ApiError::Transport)?;
        let response = expect_status(response, 200)?;
        let request_id = header(response.headers(), REQUEST_ID);
        require_media(&response, "text/event-stream")
            .map_err(|error| error.with_request_id(request_id.clone()))?;
        if consume(
            response,
            job,
            operation,
            &mut revision,
            progress,
            request_id,
        )? {
            return Ok(());
        }
        // `events` drops here before reopening; loss never resubmits or cancels.
        progress(&ProgressEvent::Reconnecting).map_err(ApiError::Progress)?;
    }
}

/// Consume one opening. False means an established stream was lost and may reopen.
fn consume(
    response: Response,
    job: &Accepted,
    operation: Operation,
    revision: &mut Option<u64>,
    progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    request_id: Option<String>,
) -> Result<bool, ApiError> {
    let mut events = Events::new(BufReader::new(response));
    let mut established = false;
    loop {
        let event = match events.next() {
            Ok(Some(event)) => event,
            Ok(None) | Err(ApiError::Read(_)) if established => return Ok(false),
            Ok(None) => {
                return Err(ApiError::protocol("stream ended before its first snapshot")
                    .with_request_id(request_id));
            }
            Err(error) => return Err(error.with_request_id(request_id)),
        };
        let snapshot = Snapshot::parse(&event.data, &event.id, job, operation, *revision)
            .map_err(|error| error.with_request_id(request_id.clone()))?;
        *revision = Some(snapshot.revision);
        established = true;
        progress(&ProgressEvent::Snapshot(snapshot.progress)).map_err(ApiError::Progress)?;
        match snapshot.state {
            State::Succeeded => return Ok(true),
            State::Failed(code) => {
                return Err(ApiError::JobFailed { code, request_id });
            }
            State::Pending => {}
        }
    }
}

fn client(timeout: Duration) -> Result<Client, ApiError> {
    Client::builder()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(super::CONNECT_TIMEOUT)
        .timeout(timeout)
        .user_agent(format!("{CLIENT_NAME}/{CLIENT_VERSION}"))
        .build()
        .map_err(ApiError::Transport)
}

fn expect_status(response: Response, expected: u16) -> Result<Response, ApiError> {
    let status = response.status().as_u16();
    if status == expected {
        return Ok(response);
    }
    let request_id = header(response.headers(), REQUEST_ID);
    let retry_after = header(response.headers(), RETRY_AFTER.as_str());
    let body = read_bounded(response, MAX_PROBLEM_BYTES)?;
    let parsed = (body.len() <= MAX_PROBLEM_BYTES)
        .then(|| problem::parse(&body))
        .flatten();
    Err(parsed.map_or(
        ApiError::Unexpected { status, request_id },
        |mut problem| {
            // Every request through this client sends the configured bearer token.
            if status == 401 {
                problem.detail =
                    "the supplied GITHITS_API_TOKEN was rejected; replace it with a valid token"
                        .into();
            }
            ApiError::Problem {
                problem: Box::new(problem),
                retry_after,
            }
        },
    ))
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn require_media(response: &Response, expected: &str) -> Result<(), ApiError> {
    let value = header(response.headers(), "content-type").unwrap_or_default();
    let mut parts = value.split(';');
    let valid = parts
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case(expected))
        && parts.all(|part| {
            part.trim().split_once('=').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("charset")
                    && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
            })
        });
    if !valid {
        return Err(ApiError::protocol("unexpected response media type"));
    }
    Ok(())
}

const fn media(operation: Operation) -> &'static str {
    match operation {
        Operation::Audit | Operation::Licenses => "application/json",
        Operation::Sbom(OutputFormat::CycloneDx) => "application/vnd.cyclonedx+json",
        Operation::Sbom(OutputFormat::Spdx) => "text/spdx",
        Operation::Sbom(OutputFormat::Text) => "text/plain",
    }
}

fn read_capped(response: Response, cap: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = read_bounded(response, cap)?;
    if bytes.len() > cap {
        return Err(ApiError::protocol(
            "analysis response exceeds the body limit",
        ));
    }
    Ok(bytes)
}

/// Read cap + 1 so equality at the boundary is distinguishable from overflow.
fn read_bounded(response: Response, cap: usize) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::new();
    response
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ApiError::Read)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
