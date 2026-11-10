//! One paired submission, using the same authenticated event/result lifecycle.
use super::{
    HttpSbomApi, REQUEST_ID, RetryBudget, expect_status, header, multipart, read_capped,
    require_media, send,
};
use crate::api::{
    ApiError, MAX_EVENT_BYTES, Operation, ProgressEvent, RequestStage,
    diff::{self, DiffApi, Input, Report},
    jobs::Accepted,
};
use reqwest::blocking::multipart::Form;

impl DiffApi for HttpSbomApi {
    fn diff(
        &self,
        input: Input,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Report, ApiError> {
        self.execute(
            Operation::Diff,
            progress,
            |retries, progress| self.submit_diff(input, retries, progress),
            Report::from_bytes,
        )
    }
}

impl HttpSbomApi {
    fn submit_diff(
        &self,
        input: Input,
        retries: &mut RetryBudget,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Accepted, ApiError> {
        let mut url = self.endpoint.clone();
        url.set_path(diff::PATH);
        url.set_query(None);
        let response = send(self, retries, RequestStage::Submission, progress, || {
            let files = input
                .base
                .iter()
                .flat_map(crate::api::UploadSet::files)
                .map(|f| ("base_files[]", f))
                .chain(
                    input
                        .head
                        .iter()
                        .flat_map(crate::api::UploadSet::files)
                        .map(|f| ("head_files[]", f)),
                );
            let form = multipart(
                Form::new()
                    .percent_encode_noop()
                    .text("request", input.request.clone()),
                files,
            )?;
            Ok(self.client.post(url.clone()).multipart(form))
        })?;
        // No downstream request may need another submission of these bytes.
        drop(input);
        let response = expect_status(response, 202)?;
        let request_id = header(response.headers(), REQUEST_ID);
        (|| {
            require_media(&response, "application/json")?;
            Accepted::parse(&read_capped(response, MAX_EVENT_BYTES)?)
        })()
        .map_err(|e| e.with_request_id(request_id))
    }
}
