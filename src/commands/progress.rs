//! Flushed human progress. Counts describe the current stage, never overall completion.

use std::io::Write;

use crate::api::jobs::{Phase, Progress};
use crate::api::{MAX_RATE_LIMIT_RETRIES, ProgressEvent, RateLimitStop, RequestStage};

pub(super) fn message(text: &str, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, "{text}")?;
    out.flush()
}

/// Throttling is a material warning even when routine progress is suppressed.
pub(super) const fn visible(event: &ProgressEvent, enabled: bool) -> bool {
    enabled
        || matches!(
            event,
            ProgressEvent::RateLimited { .. } | ProgressEvent::RateLimitStopped(_)
        )
}

pub(super) fn write(event: &ProgressEvent, out: &mut dyn Write) -> std::io::Result<()> {
    match event {
        ProgressEvent::RateLimitStopped(reason) => rate_limit_stopped(reason, out),
        ProgressEvent::RateLimited {
            stage,
            attempt,
            delay,
            request_id,
        } => rate_limit(*stage, *attempt, *delay, request_id.as_deref(), out),
        ProgressEvent::Reconnecting => message("progress connection lost; reconnecting...", out),
        ProgressEvent::Downloading => message("SBOM ready; downloading...", out),
        ProgressEvent::Snapshot(progress) => snapshot(progress, false, out),
    }
}

pub(super) fn write_audit(event: &ProgressEvent, out: &mut dyn Write) -> std::io::Result<()> {
    match event {
        ProgressEvent::Downloading => message("audit report ready; downloading...", out),
        ProgressEvent::Snapshot(progress) => snapshot(progress, true, out),
        ProgressEvent::Reconnecting
        | ProgressEvent::RateLimited { .. }
        | ProgressEvent::RateLimitStopped(_) => write(event, out),
    }
}

pub(super) fn write_licenses(event: &ProgressEvent, out: &mut dyn Write) -> std::io::Result<()> {
    match event {
        ProgressEvent::Downloading => message("license report ready; downloading...", out),
        _ => write(event, out),
    }
}

pub(super) fn write_diff(event: &ProgressEvent, out: &mut dyn Write) -> std::io::Result<()> {
    match event {
        ProgressEvent::Downloading => message("dependency comparison ready; downloading...", out),
        ProgressEvent::Snapshot(progress) if progress.phase == Phase::Rendering => {
            message("rendering dependency comparison...", out)
        }
        _ => write_audit(event, out),
    }
}

fn rate_limit_stopped(reason: &RateLimitStop, out: &mut dyn Write) -> std::io::Result<()> {
    match reason {
        RateLimitStop::RetriesExhausted => {
            writeln!(
                out,
                "warning: automatic rate-limit recovery stopped after {MAX_RATE_LIMIT_RETRIES} retries"
            )?;
        }
        RateLimitStop::WaitExceeded {
            requested,
            remaining,
        } => {
            let requested = ceil_seconds(*requested);
            let remaining = remaining.as_secs();
            writeln!(
                out,
                "warning: automatic rate-limit recovery stopped: the server requested {requested}s but only {remaining}s of waiting remain"
            )?;
        }
    }
    out.flush()
}

fn rate_limit(
    stage: RequestStage,
    attempt: u8,
    delay: std::time::Duration,
    request_id: Option<&str>,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let stage = match stage {
        RequestStage::Submission => "submitting analysis",
        RequestStage::Events => "opening progress stream",
        RequestStage::Result => "downloading result",
    };
    write!(
        out,
        "warning: rate limited while {stage}; retry {attempt} of up to {MAX_RATE_LIMIT_RETRIES}"
    )?;
    if delay.is_zero() {
        write!(out, " now")?;
    } else {
        let seconds = ceil_seconds(delay);
        write!(out, " in {seconds}s")?;
    }
    if let Some(id) = request_id {
        write!(out, " (request id: {})", super::safe(id))?;
    }
    writeln!(out)?;
    out.flush()
}

fn ceil_seconds(duration: std::time::Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

fn snapshot(progress: &Progress, audit: bool, out: &mut dyn Write) -> std::io::Result<()> {
    let counts = &progress.counts;
    match progress.phase {
        Phase::Queued => write!(out, "waiting for analysis...")?,
        Phase::Resolving => {
            write!(out, "resolving dependencies")?;
            measured(
                counts.manifests_done,
                counts.manifests_total,
                "manifests",
                out,
            )?;
        }
        Phase::Enriching => {
            write!(out, "enriching package metadata")?;
            measured(
                counts.coordinates_done,
                counts.coordinates_total,
                "packages",
                out,
            )?;
            if let Some(failed) = counts.fetch_failed.filter(|n| *n > 0) {
                write!(out, "; metadata fetch failures: {failed}")?;
            }
        }
        Phase::Assessing => {
            write!(out, "assessing audit evidence")?;
            measured(
                counts.assessments_done,
                counts.assessments_total,
                "assessments",
                out,
            )?;
        }
        Phase::Unknown => write!(out, "analysis in progress...")?,
        Phase::Rendering => write!(
            out,
            "{}",
            if audit {
                "rendering audit report..."
            } else {
                "rendering SBOM..."
            }
        )?,
        // Remote success is not command completion. The transport emits Downloading
        // before fetching; failures are explained by their actionable diagnostic.
        Phase::Succeeded | Phase::Failed => return Ok(()),
    }
    if progress.attempt > 1 {
        write!(out, " (attempt {})", progress.attempt)?;
    }
    writeln!(out)?;
    out.flush()
}

fn measured(
    done: Option<u64>,
    total: Option<u64>,
    unit: &str,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    match (done, total) {
        (Some(done), Some(total)) => write!(out, ": {done} / {total} {unit}"),
        (Some(done), None) => write!(out, ": {done} {unit} processed"),
        (None, Some(total)) => write!(out, ": {total} {unit} known"),
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::jobs::Counts;

    fn render(phase: Phase, attempt: u64, counts: Counts) -> String {
        let mut out = Vec::new();
        write(
            &ProgressEvent::Snapshot(Progress {
                phase,
                attempt,
                counts,
            }),
            &mut out,
        )
        .expect("write");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn stage_counts_distinguish_measured_zero_from_unknown() {
        for (done, total, expected) in [
            (
                Some(0),
                Some(4),
                "enriching package metadata: 0 / 4 packages\n",
            ),
            (
                Some(0),
                None,
                "enriching package metadata: 0 packages processed\n",
            ),
            (
                None,
                Some(4),
                "enriching package metadata: 4 packages known\n",
            ),
            (None, None, "enriching package metadata\n"),
        ] {
            assert_eq!(
                render(
                    Phase::Enriching,
                    1,
                    Counts {
                        coordinates_done: done,
                        coordinates_total: total,
                        ..Counts::default()
                    }
                ),
                expected
            );
        }
    }

    #[test]
    fn resolving_displays_its_own_units_and_later_attempt() {
        assert_eq!(
            render(
                Phase::Resolving,
                2,
                Counts {
                    manifests_done: Some(1),
                    manifests_total: Some(3),
                    coordinates_done: Some(12),
                    ..Counts::default()
                }
            ),
            "resolving dependencies: 1 / 3 manifests (attempt 2)\n"
        );
    }

    #[test]
    fn common_enrichment_line_is_readable_without_internal_telemetry() {
        let line = render(
            Phase::Enriching,
            1,
            Counts {
                coordinates_done: Some(2256),
                coordinates_total: Some(2342),
                cached: Some(2255),
                fetched: Some(1),
                fetch_failed: Some(0),
                ..Counts::default()
            },
        );
        assert_eq!(line, "enriching package metadata: 2256 / 2342 packages\n");
        assert!(line.chars().count() < 80);
        assert_eq!(
            render(
                Phase::Enriching,
                1,
                Counts {
                    fetch_failed: Some(2),
                    ..Counts::default()
                }
            ),
            "enriching package metadata; metadata fetch failures: 2\n"
        );
    }

    #[test]
    fn readiness_and_recovery_are_transport_messages_not_command_success() {
        assert_eq!(
            render(Phase::Queued, 1, Counts::default()),
            "waiting for analysis...\n"
        );
        assert_eq!(
            render(Phase::Rendering, 1, Counts::default()),
            "rendering SBOM...\n"
        );
        for phase in [Phase::Succeeded, Phase::Failed] {
            assert!(
                render(phase, 1, Counts::default()).is_empty(),
                "{:?}",
                render(phase, 1, Counts::default())
            );
        }
        let mut out = Vec::new();
        write(&ProgressEvent::Reconnecting, &mut out).expect("write");
        write(&ProgressEvent::Downloading, &mut out).expect("write");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "progress connection lost; reconnecting...\nSBOM ready; downloading...\n"
        );
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::api::jobs::Counts;
    #[test]
    fn audit_assessing_distinguishes_zero_and_unknown_without_overall_percentage() {
        for (done, total, expected) in [
            (
                Some(0),
                Some(4),
                "assessing audit evidence: 0 / 4 assessments\n",
            ),
            (None, None, "assessing audit evidence\n"),
        ] {
            let mut out = Vec::new();
            write_audit(
                &ProgressEvent::Snapshot(Progress {
                    phase: Phase::Assessing,
                    attempt: 1,
                    counts: Counts {
                        assessments_done: done,
                        assessments_total: total,
                        ..Counts::default()
                    },
                }),
                &mut out,
            )
            .expect("write");
            assert_eq!(String::from_utf8(out).expect("utf8"), expected);
        }
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Default)]
    struct Output {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn rate_limit_warning_names_each_stage_rounds_up_escapes_and_flushes() {
        for (stage, name) in [
            (RequestStage::Submission, "submitting analysis"),
            (RequestStage::Events, "opening progress stream"),
            (RequestStage::Result, "downloading result"),
        ] {
            let event = ProgressEvent::RateLimited {
                stage,
                attempt: 2,
                delay: Duration::from_millis(1_001),
                request_id: Some("req\nforged".into()),
            };
            assert!(visible(&event, false));
            let mut out = Output::default();
            write(&event, &mut out).expect("warning");
            assert_eq!(
                String::from_utf8(out.bytes).expect("UTF-8"),
                format!(
                    "warning: rate limited while {name}; retry 2 of up to 5 in 2s (request id: req\\nforged)\n"
                )
            );
            assert_eq!(out.flushes, 1);
        }
    }

    #[test]
    fn rate_limit_stop_rounds_requested_up_and_remaining_down_to_seconds() {
        for (requested, remaining, expected_request, expected_remaining) in [
            (312_483, 0, 313, 0),
            (300_001, 299_999, 301, 299),
            (1_001, 750, 2, 0),
        ] {
            let event = ProgressEvent::RateLimitStopped(RateLimitStop::WaitExceeded {
                requested: Duration::from_millis(requested),
                remaining: Duration::from_millis(remaining),
            });
            let mut out = Output::default();
            write(&event, &mut out).expect("stop warning");
            assert_eq!(
                String::from_utf8(out.bytes).expect("UTF-8"),
                format!(
                    "warning: automatic rate-limit recovery stopped: the server requested {expected_request}s but only {expected_remaining}s of waiting remain\n"
                )
            );
            assert_eq!(out.flushes, 1);
        }
    }
}
