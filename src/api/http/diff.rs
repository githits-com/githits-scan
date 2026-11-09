//! One paired submission, using the same authenticated event/result lifecycle.
use super::{HttpSbomApi, REQUEST_ID, expect_status, header, read_capped, require_media, wait};
use crate::api::{
    ApiError, MAX_EVENT_BYTES, Operation, ProgressEvent,
    diff::{self, DiffApi, Input, Report},
    jobs::Accepted,
};
use reqwest::blocking::multipart::{Form, Part};

impl DiffApi for HttpSbomApi {
    fn diff(
        &self,
        input: Input,
        progress: &mut dyn FnMut(&ProgressEvent) -> std::io::Result<()>,
    ) -> Result<Report, ApiError> {
        let mut form = Form::new()
            .percent_encode_noop()
            .text("request", input.request);
        let files = input
            .base
            .into_iter()
            .flat_map(crate::api::UploadSet::into_files)
            .map(|f| ("base_files[]", f))
            .chain(
                input
                    .head
                    .into_iter()
                    .flat_map(crate::api::UploadSet::into_files)
                    .map(|f| ("head_files[]", f)),
            );
        for (field, file) in files {
            let part = Part::text(file.contents)
                .file_name(file.path)
                .mime_str("application/octet-stream")
                .map_err(ApiError::Transport)?;
            form = form.part(field, part);
        }
        let mut url = self.endpoint.clone();
        url.set_path(diff::PATH);
        url.set_query(None);
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
        })()
        .map_err(|e| e.with_request_id(request_id))?;
        wait(self, &accepted, Operation::Diff, progress)?;
        progress(&ProgressEvent::Downloading).map_err(ApiError::Progress)?;
        self.result(&accepted, Operation::Diff, Report::from_bytes)
    }
}
