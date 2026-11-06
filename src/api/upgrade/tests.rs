use super::*;
use crate::{
    api::http::HttpSbomApi,
    env,
    test_support::{self, MockServer, diff as fixture, response},
};
use std::ffi::OsString;

fn package() -> Package {
    Package {
        registry: "npm".into(),
        name: "minimist".into(),
        current_version: "1.2.5".into(),
        target_version: "1.2.8".into(),
    }
}

fn api(origin: &str) -> HttpSbomApi {
    HttpSbomApi::new(
        env::from_source(|name| match name {
            "GITHITS_API_TOKEN" => Some(OsString::from("test-token")),
            "GITHITS_API_URL" => Some(OsString::from(origin)),
            _ => None,
        })
        .expect("environment"),
    )
    .expect("client")
}

#[test]
fn upgrade_response_retains_unknowns_null_links_and_open_values() {
    let mut review = fixture::review("canonical-name", "1.2.5", "1.2.8");
    review["unknown_details"] = serde_json::json!([{"section":"future_section","code":"new_code","message":"not available","retryable":null}]);
    review["changelog"]["entries"][0]["html_url"] = serde_json::Value::Null;
    review["version_delta"] = "future_delta".into();
    let bytes =
        serde_json::to_vec(&serde_json::json!({"total":1,"reviews":[review]})).expect("JSON");
    let reviews = decode(&bytes, &[package()]).expect("reviews");
    assert_eq!(reviews[0].name, "canonical-name");
    assert_eq!(reviews[0].version_delta, "future_delta");
    assert_eq!(reviews[0].unknown_details[0].code, "new_code");
    assert_eq!(
        reviews[0].changelog.as_ref().expect("changelog").entries[0].html_url,
        None
    );
    assert!(reviews[0].incomplete());
}

#[test]
fn upgrade_missing_rows_wrong_versions_or_missing_qualification_are_errors() {
    for value in [
        serde_json::json!({"total":0,"reviews":[]}),
        serde_json::json!({"total":1,"reviews":[fixture::review("minimist","1.0.0","1.2.8")]}),
        serde_json::json!({"total":1,"reviews":[{"registry":"npm","name":"minimist","current_version":"1.2.5","target_version":"1.2.8","version_delta":"patch"}]}),
    ] {
        assert!(matches!(
            decode(&serde_json::to_vec(&value).expect("JSON"), &[package()]),
            Err(ApiError::Protocol { .. })
        ));
    }
}

#[test]
fn upgrade_http_accepts_thirty_rows_and_selects_only_direct_security_and_changelog() {
    let body = serde_json::to_vec(&serde_json::json!({"total":30,"reviews":(0..30).map(|_|fixture::review("minimist","1.2.5","1.2.8")).collect::<Vec<_>>()})).expect("JSON");
    let server = MockServer::respond_with(response(
        "200 OK",
        &[("Content-Type", "application/json")],
        &body,
    ));
    let reviews = api(&server.origin())
        .review(&vec![package(); 30])
        .expect("reviews");
    assert_eq!(reviews.len(), 30);
    let request = String::from_utf8(server.request()).expect("request");
    assert!(
        request.starts_with("POST /v1/package-upgrade-reviews?fields=security.direct,changelog ")
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token")
    );
    assert!(request.contains("\"current_version\":\"1.2.5\""));
    assert!(!request.contains("security.transitive"));
}

#[test]
fn upgrade_zero_or_thirty_one_rows_fail_before_http() {
    let client = api("http://127.0.0.1:9");
    for packages in [Vec::new(), vec![package(); 31]] {
        assert!(matches!(
            client.review(&packages),
            Err(ApiError::Protocol { .. })
        ));
    }
}

#[test]
fn upgrade_registry_and_version_prefix_filter_prevents_batch_poisoning() {
    for (registry, version, supported) in [
        ("dart", "1.0.0", false),
        ("conan", "1.0.0", false),
        ("crates", "v1.0.0", false),
        ("go", "v1.0.0", true),
        ("go", "V1.0.0", false),
        ("swift", "V1.0.0", true),
        ("packagist", "v1.0.0", false),
        ("npm", "1.0.0", true),
    ] {
        let mut p = package();
        p.registry = registry.into();
        p.current_version = version.into();
        assert_eq!(p.supported(), supported, "{registry} {version}");
    }
}

#[test]
fn upgrade_does_not_follow_redirects_or_lose_retry_after() {
    for (status, headers, body, expected) in [
        (
            "302 Found",
            vec![("Location", "http://127.0.0.1:9/leak")],
            Vec::new(),
            302,
        ),
        (
            "429 Too Many Requests",
            vec![
                ("Content-Type", "application/problem+json"),
                ("Retry-After", "65"),
            ],
            br#"{"status":429,"code":"RATE_LIMITED","detail":"slow down"}"#.to_vec(),
            429,
        ),
    ] {
        let server = MockServer::respond_with(response(status, &headers, &body));
        let error = api(&server.origin())
            .review(&[package()])
            .expect_err("error");
        if expected == 302 {
            assert!(matches!(error, ApiError::Unexpected { status: 302, .. }));
        } else {
            assert!(error.to_string().contains("retry after: 65s"));
        }
        assert!(!format!("{error:?}").contains("test-token"));
        assert_ne!(server.request().len(), 0);
    }
}

#[test]
fn upgrade_caps_response_and_rejects_non_json_media() {
    for (media, body) in [
        (
            "application/json",
            vec![b' '; crate::api::MAX_RESPONSE_BYTES + 1],
        ),
        ("text/plain", b"not JSON".to_vec()),
    ] {
        let server = test_support::jobs::ScriptedServer::respond_with(vec![response(
            "200 OK",
            &[("Content-Type", media)],
            &body,
        )]);
        let error = api(&server.origin())
            .review(&[package()])
            .expect_err("invalid response");
        assert!(matches!(
            error,
            ApiError::ResponseTooLarge | ApiError::Protocol { .. }
        ));
        assert_eq!(server.requests().len(), 1);
    }
}
