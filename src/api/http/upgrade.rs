//! Upgrade reviews reuse the finite authenticated transport and its security policy.
use super::{
    ApiError, HttpSbomApi, MAX_RESPONSE_BYTES, REQUEST_ID, expect_status, header, read_capped,
    require_media,
};
use crate::api::upgrade::{self, Package, Review, UpgradeApi};

impl UpgradeApi for HttpSbomApi {
    fn review(&self, packages: &[Package]) -> Result<Vec<Review>, ApiError> {
        if packages.is_empty()
            || packages.len() > upgrade::MAX_PACKAGES
            || packages.iter().any(|p| !p.supported())
        {
            return Err(ApiError::protocol("unsupported upgrade review batch"));
        }
        let mut url = self.endpoint.clone();
        url.set_path(upgrade::PATH);
        url.set_query(Some("fields=security.direct,changelog"));
        let body = serde_json::to_vec(&serde_json::json!({"packages": packages}))
            .map_err(|_| ApiError::protocol("cannot encode upgrade request"))?;
        let response = self
            .authenticate(self.client.post(url))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(ApiError::Transport)?;
        let response = expect_status(response, 200)?;
        let request_id = header(response.headers(), REQUEST_ID);
        let decode = || {
            require_media(&response, "application/json")?;
            let bytes = read_capped(response, MAX_RESPONSE_BYTES)?;
            upgrade::decode(&bytes, packages)
        };
        decode().map_err(|error| error.with_request_id(request_id))
    }
}
