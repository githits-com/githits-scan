//! Explicit HTTP 429 recovery shared by all requests in one analysis.
use std::time::{Duration, SystemTime};

use reqwest::blocking::{RequestBuilder, Response};
use reqwest::header::RETRY_AFTER;

use super::{HttpSbomApi, REQUEST_ID, header};
use crate::api::{
    ApiError, MAX_RATE_LIMIT_RETRIES, MAX_RATE_LIMIT_WAIT, ProgressEvent, RateLimitStop,
    RequestStage,
};

/// Successful requests and stream reopenings never replenish this budget.
#[derive(Default)]
pub(super) struct RetryBudget {
    attempts: u8,
    waited: Duration,
}

impl RetryBudget {
    fn reserve(&mut self, delay: Duration) -> Result<u8, RateLimitStop> {
        if self.attempts >= MAX_RATE_LIMIT_RETRIES {
            return Err(RateLimitStop::RetriesExhausted);
        }
        let remaining = MAX_RATE_LIMIT_WAIT.saturating_sub(self.waited);
        if delay > remaining {
            return Err(RateLimitStop::WaitExceeded {
                requested: delay,
                remaining,
            });
        }
        let waited = self.waited + delay;
        self.attempts += 1;
        self.waited = waited;
        Ok(self.attempts)
    }
}

pub(super) fn send(
    api: &HttpSbomApi,
    retries: &mut RetryBudget,
    stage: RequestStage,
    progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    mut build: impl FnMut() -> Result<RequestBuilder, ApiError>,
) -> Result<Response, ApiError> {
    loop {
        let response = api
            .authenticate(build()?)
            .send()
            .map_err(ApiError::Transport)?;
        if response.status().as_u16() != 429 {
            return Ok(response);
        }
        let delay = header(response.headers(), RETRY_AFTER.as_str())
            .and_then(|value| delay(&value, SystemTime::now()));
        let Some(delay) = delay else {
            return Ok(response);
        };
        let attempt = match retries.reserve(delay) {
            Ok(attempt) => attempt,
            Err(reason) => {
                progress(&ProgressEvent::RateLimitStopped(reason)).map_err(ApiError::Progress)?;
                return Ok(response);
            }
        };
        let request_id = header(response.headers(), REQUEST_ID);
        // Release the rejected body/socket before notifying or sleeping.
        drop(response);
        progress(&ProgressEvent::RateLimited {
            stage,
            attempt,
            delay,
            request_id,
        })
        .map_err(ApiError::Progress)?;
        (api.sleep)(delay);
    }
}

fn delay(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(now).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests;
