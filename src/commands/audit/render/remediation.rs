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
        writeln!(out)?;
        line(outcome, "    ", out)?;
    }
    if let Some(heading) = &plan.heading {
        writeln!(out, "\n    {heading}:")?;
    }
    for change in &plan.changes {
        line(&change.summary, "      ", out)?;
        file_list("files", &change.files, "        ", out)?;
        lines(&change.details, "        ", out)?;
        for reason in &change.reasons {
            line(&reason.summary, "        ", out)?;
            lines(&reason.evidence, "          ", out)?;
        }
    }
    file_list("Change in", &plan.files, "    ", out)?;
    lines(&plan.context, "    ", out)?;
    lines(&plan.impact, "    ", out)?;
    for constraint in &plan.constraints {
        line(&constraint.summary, "    ", out)?;
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
    for text in lines {
        line(text, indent, out)?;
    }
    Ok(())
}

// Match audit file-list width, preserving indivisible coordinates and identifiers.
// Four-space continuations stay distinct from the immediate child indentation.
fn line(text: &str, indent: &str, out: &mut dyn Write) -> io::Result<()> {
    write!(out, "{indent}")?;
    let mut width = indent.chars().count();
    for (index, word) in text.split(' ').enumerate() {
        let length = word.chars().count();
        if index > 0 && width + 1 + length > 100 {
            write!(out, "\n{indent}    ")?;
            width = indent.chars().count() + 4;
        } else if index > 0 {
            write!(out, " ")?;
            width += 1;
        }
        write!(out, "{word}")?;
        width += length;
    }
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_wraps_with_hanging_indent_without_losing_unicode_or_ids() {
        let text = format!(
            "would address: café — {}",
            (0..12)
                .map(|i| format!("GHSA-example-{i},"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let mut output = Vec::new();
        line(&text, "    ", &mut output).expect("write");
        let output = String::from_utf8(output).expect("utf8");
        assert!(output.lines().count() > 1);
        assert!(output.lines().all(|l| l.chars().count() <= 100));
        assert!(output.lines().skip(1).all(|l| l.starts_with("        ")));
        assert_eq!(
            output.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn guidance_keeps_long_indivisible_tokens_whole() {
        let token = "é".repeat(120);
        let text = format!("candidate: {token}");
        let mut output = Vec::new();
        line(&text, "    ", &mut output).expect("write");
        assert_eq!(
            String::from_utf8(output).expect("utf8"),
            format!("    candidate:\n        {token}\n")
        );
    }
}
