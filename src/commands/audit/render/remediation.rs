//! Native layout of the shared remediation presentation model.
use super::file_list;
use crate::commands::audit::{
    presentation::{self, Plan},
    view::{
        View,
        remediation::{Record, Remediation, State},
    },
};
use crate::style::Palette;
use std::io::{self, Write};
mod problems;
pub(in crate::commands::audit) use presentation::{
    ReasonDetail, context::Context as ProblemContext,
};

pub(super) fn write(view: &View, out: &mut dyn Write, palette: Palette) -> io::Result<()> {
    let data = match &view.remediation {
        State::Unavailable if !view.vulnerabilities.is_empty() => {
            for message in presentation::messages(view) {
                writeln!(out, "\n{message}")?;
            }
            return Ok(());
        }
        State::Present(data) => data,
        State::Unavailable | State::Unverified => return Ok(()),
    };
    if data.recommendations.is_empty()
        && view.vulnerabilities.is_empty()
        && data.status == "completed"
    {
        return Ok(());
    }
    writeln!(out, "\n{}", palette.bold("Fix guidance"))?;
    for message in presentation::messages(view) {
        writeln!(out, "  {message}")?;
    }
    problems::write(data, &data.status, out)?;
    shared_limits(data, out)
}

pub(in crate::commands::audit) fn guidance(
    r: &Record,
    status: &str,
    context: &ProblemContext<'_>,
    detail: ReasonDetail,
    out: &mut dyn Write,
) -> io::Result<()> {
    let plan = Plan::new(r, status, context, detail);
    if let Some(outcome) = &plan.outcome {
        writeln!(out, "\n    {outcome}")?;
    }
    if let Some(heading) = &plan.heading {
        writeln!(out, "\n    {heading}:")?;
    }
    for change in &plan.changes {
        writeln!(out, "      {}", change.summary)?;
        file_list("files", &change.files, "        ", out)?;
        lines(&change.details, "        ", out)?;
        for reason in &change.reasons {
            writeln!(out, "        {}", reason.summary)?;
            lines(&reason.evidence, "          ", out)?;
        }
    }
    file_list("Change in", &plan.files, "    ", out)?;
    lines(&plan.context, "    ", out)?;
    lines(&plan.impact, "    ", out)?;
    for constraint in &plan.constraints {
        writeln!(out, "    {}", constraint.summary)?;
        lines(&constraint.details, "      ", out)?;
    }
    lines(&plan.checks, "    ", out)?;
    lines(&plan.limitations, "    ", out)
}

pub(in crate::commands::audit) fn shared_limits(
    data: &Remediation,
    out: &mut dyn Write,
) -> io::Result<()> {
    lines(&presentation::remediation::limits(data), "  ", out)
}
fn lines(lines: &[String], indent: &str, out: &mut dyn Write) -> io::Result<()> {
    for line in lines {
        writeln!(out, "{indent}{line}")?;
    }
    Ok(())
}
