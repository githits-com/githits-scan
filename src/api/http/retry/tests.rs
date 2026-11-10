use super::*;

#[test]
fn rate_limit_delay_accepts_seconds_and_http_dates_without_early_retry() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    for (header, expected) in [("0", 0), ("30", 30), ("00030", 30), (" 30 ", 30)] {
        assert_eq!(delay(header, now), Some(Duration::from_secs(expected)));
    }
    for offset in [0, 1, 60, 300] {
        let date = httpdate::fmt_http_date(now + Duration::from_secs(offset));
        assert_eq!(delay(&date, now), Some(Duration::from_secs(offset)));
    }
    let past = httpdate::fmt_http_date(now - Duration::from_secs(60));
    assert_eq!(delay(&past, now), Some(Duration::ZERO));
    let date = httpdate::fmt_http_date(now + Duration::from_secs(1));
    assert_eq!(
        delay(&date, now + Duration::from_millis(250)),
        Some(Duration::from_millis(750))
    );
}

#[test]
fn rate_limit_delay_rejects_missing_semantics_and_numeric_overflow() {
    for header in [
        "",
        " ",
        "later",
        "-1",
        "+1",
        "1.5",
        "18446744073709551616",
        "99 Nov 2026",
    ] {
        assert_eq!(delay(header, SystemTime::UNIX_EPOCH), None, "{header:?}");
    }
}

#[test]
fn rate_limit_budget_accepts_exact_total_and_rejects_excess_without_consuming_it() {
    let mut budget = RetryBudget::default();
    assert_eq!(
        budget.reserve(Duration::from_secs(301)),
        Err(RateLimitStop::WaitExceeded {
            requested: Duration::from_secs(301),
            remaining: Duration::from_secs(300)
        })
    );
    assert_eq!(budget.reserve(Duration::from_secs(299)), Ok(1));
    assert_eq!(
        budget.reserve(Duration::from_secs(2)),
        Err(RateLimitStop::WaitExceeded {
            requested: Duration::from_secs(2),
            remaining: Duration::from_secs(1)
        })
    );
    assert_eq!(budget.reserve(Duration::from_secs(1)), Ok(2));
    assert_eq!(
        budget.reserve(Duration::from_nanos(1)),
        Err(RateLimitStop::WaitExceeded {
            requested: Duration::from_nanos(1),
            remaining: Duration::ZERO
        })
    );
    for attempt in 3..=5 {
        assert_eq!(budget.reserve(Duration::ZERO), Ok(attempt));
    }
    for delay in [Duration::ZERO, Duration::MAX] {
        assert_eq!(budget.reserve(delay), Err(RateLimitStop::RetriesExhausted));
    }
}
