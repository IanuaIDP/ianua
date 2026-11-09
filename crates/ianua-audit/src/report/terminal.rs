//! The text report: findings grouped by severity and check, then a summary
//! table of counts per check.

use std::fmt::Write as _;

use crate::finding::{Check, Finding, Severity};
use crate::report::{Paint, Report, Style, Tally};

/// How the conclusions left unsaid are shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsaidLines {
    /// Counted on one line per check.
    Counted,
    /// Counted, then each listed with the point it rested on.
    Listed,
}

/// The report as text, showing at most `limit` findings per check.
pub(crate) fn render(
    report: &Report,
    style: Style,
    limit: Option<usize>,
    unsaid: UnsaidLines,
) -> String {
    let mut out = String::new();
    out.push_str(&headline(report, style));
    for severity in Severity::ALL {
        out.push_str(&severity_section(report, severity, style, limit));
    }
    out.push_str(&summary(report, style));
    if unsaid == UnsaidLines::Listed {
        out.push_str(&unsaid_list(report, style));
    }
    out
}

/// Each conclusion left unsaid, by check, with the point it rested on.
fn unsaid_list(report: &Report, style: Style) -> String {
    if report.unsaid.is_empty() {
        return String::new();
    }
    let mut out = format!("\n{}\n", style.paint("UNSAID", Paint::Heading));
    for check in Check::ALL {
        let held: Vec<_> = (report.unsaid.iter())
            .filter(|unsaid| unsaid.check == check)
            .collect();
        if held.is_empty() {
            continue;
        }
        let heading = style.paint(check.id(), Paint::Heading);
        let _ = writeln!(out, "  {heading} ({})", held.len());
        for unsaid in held {
            let at = format!("{}:{}", unsaid.place.file, unsaid.place.line);
            let _ = writeln!(out, "    {}", unsaid.subject);
            let _ = writeln!(
                out,
                "        {}  {}",
                style.paint(&at, Paint::Dim),
                unsaid.why
            );
        }
    }
    out
}

fn headline(report: &Report, style: Style) -> String {
    let tally = report.tally();
    let counts: Vec<String> = Severity::ALL
        .into_iter()
        .map(|severity| {
            style.paint(
                &format!("{} {severity}", tally.of(severity)),
                Paint::Severity(severity),
            )
        })
        .collect();
    format!(
        "{} read {} files\n{} findings: {} ({} allowed)\n",
        style.paint("ianua-audit", Paint::Heading),
        report.files_read,
        tally.total(),
        counts.join(", "),
        report.allowed.len()
    )
}

fn severity_section(
    report: &Report,
    severity: Severity,
    style: Style,
    limit: Option<usize>,
) -> String {
    let of_severity: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .collect();
    if of_severity.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{}\n",
        style.paint(&severity.as_str().to_uppercase(), Paint::Severity(severity))
    );
    for check in Check::ALL {
        let found: Vec<&&Finding> = of_severity
            .iter()
            .filter(|finding| finding.check == check)
            .collect();
        if found.is_empty() {
            continue;
        }
        out.push_str(&check_section(check, &found, style, limit));
    }
    out
}

fn check_section(check: Check, found: &[&&Finding], style: Style, limit: Option<usize>) -> String {
    let mut out = format!(
        "  {}  {} ({})\n",
        style.paint(check.id(), Paint::Heading),
        check.title(),
        found.len()
    );
    let shown = limit.unwrap_or(found.len()).min(found.len());
    for finding in &found[..shown] {
        let _ = writeln!(
            out,
            "    {}  {}",
            style.paint(&finding.location(), Paint::Dim),
            finding.message
        );
        for line in &finding.detail {
            let _ = writeln!(out, "        {line}");
        }
    }
    if shown < found.len() {
        let _ = writeln!(out, "    ... and {} more", found.len() - shown);
    }
    out
}

fn summary(report: &Report, style: Style) -> String {
    let counts = report.by_check();
    let width = Check::ALL
        .iter()
        .map(|check| check.id().len())
        .max()
        .unwrap_or(0);
    let mut out = format!("\n{}\n", style.paint("SUMMARY", Paint::Heading));
    let _ = writeln!(
        out,
        "  {:<width$}  {:>6}  {:>6}  {:>6}  {:>6}  area",
        "check", "high", "medium", "low", "info"
    );
    for check in Check::ALL {
        let Some(tally) = counts.get(&check) else {
            continue;
        };
        out.push_str(&summary_row(check.id(), tally, check.area().title(), width));
    }
    out.push_str(&summary_row("total", &report.tally(), "", width));
    out.push_str(&silenced_line(report));
    out.push_str(&parked_lines(report));
    out
}

/// One line per parked crate: what it holds back.
fn parked_lines(report: &Report) -> String {
    if report.parked.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = report
        .parked
        .iter()
        .map(|count| format!("  {}\n", count.line()))
        .collect();
    format!("\n{}", lines.concat())
}

/// How many conclusions the checks left unsaid, and which checks, when any.
fn silenced_line(report: &Report) -> String {
    let total = report.silenced_total();
    if total == 0 {
        return String::new();
    }
    let parts: Vec<String> = report
        .silenced
        .iter()
        .map(|(check, count)| format!("{} {count}", check.id()))
        .collect();
    format!(
        "\n  {total} conclusions left unsaid: each rested on something the reader marked not read ({}); --unsaid lists them\n",
        parts.join(", ")
    )
}

fn summary_row(label: &str, tally: &Tally, area: &str, width: usize) -> String {
    let row = format!(
        "  {label:<width$}  {:>6}  {:>6}  {:>6}  {:>6}  {area}",
        tally.high, tally.medium, tally.low, tally.info
    );
    format!("{}\n", row.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Place;

    fn finding(check: Check, line: usize) -> Finding {
        Finding::new(
            check,
            Place {
                file: "crates/ianua-app/src/a.rs".to_owned(),
                line,
            },
            "S",
            format!("message {line}"),
        )
    }

    fn report() -> Report {
        Report {
            findings: vec![
                finding(Check::UnimplementedPort, 1),
                finding(Check::UnwiredUseCase, 2),
                finding(Check::UnwiredUseCase, 3),
            ],
            allowed: Vec::new(),
            silenced: std::collections::BTreeMap::new(),
            unsaid: Vec::new(),
            parked: Vec::new(),
            files_read: 3,
        }
    }

    fn rendered(report: &Report, limit: Option<usize>) -> String {
        render(report, Style::new(false), limit, UnsaidLines::Counted)
    }

    #[test]
    fn each_parked_crate_has_its_line_last() {
        let mut report = report();
        report.parked.push(crate::report::ParkedCount {
            crate_name: "ianua-server".to_owned(),
            reason: "rebuilt after the infra layer".to_owned(),
            left_out: 96,
            wired_only_there: 0,
        });

        let text = rendered(&report, None);

        assert!(
            text.trim_end().ends_with(
                "96 findings in parked crate ianua-server (rebuilt after the infra layer)"
            )
        );
    }

    #[test]
    fn detail_lines_follow_their_finding_and_the_unsaid_are_counted_last() {
        let mut report = report();
        report.findings[0] = finding(Check::UnimplementedPort, 1)
            .with_detail(["why: it matters".to_owned(), "fix: do it".to_owned()]);
        report.silenced.insert(Check::MissingLimitPath, 2);

        let text = rendered(&report, None);

        assert!(text.contains("a.rs:1  message 1\n        why: it matters\n        fix: do it\n"));
        assert!(text.trim_end().ends_with(
            "2 conclusions left unsaid: each rested on something the reader marked not read (limits.path-missing 2); --unsaid lists them"
        ));
    }

    #[test]
    fn the_unsaid_are_listed_with_the_point_each_rested_on_when_asked() {
        let mut report = report();
        report.silenced.insert(Check::SuccessWithoutEvent, 1);
        report.unsaid.push(crate::finding::Unsaid::new(
            Check::SuccessWithoutEvent,
            "identity::RunUseCase",
            Place {
                file: "crates/ianua-app/src/b.rs".to_owned(),
                line: 61,
            },
            "`settle(..)`: not followed",
        ));

        let text = render(&report, Style::new(false), None, UnsaidLines::Listed);

        assert!(text.trim_end().ends_with(
            "UNSAID\n  records.success-without-event (1)\n    identity::RunUseCase\n        crates/ianua-app/src/b.rs:61  `settle(..)`: not followed"
        ));
    }

    #[test]
    fn findings_are_grouped_by_severity_then_check() {
        let text = rendered(&report(), None);

        let high = text.find("HIGH").unwrap();
        let medium = text.find("MEDIUM").unwrap();
        assert!(high < medium);
        assert!(
            text.contains(
                "adapters.use-case-unwired  use cases no adapter constructs or calls (2)"
            )
        );
        assert!(text.contains("crates/ianua-app/src/a.rs:3  message 3"));
    }

    #[test]
    fn a_limit_cuts_each_check_and_says_how_many_more() {
        let text = rendered(&report(), Some(1));

        assert!(!text.contains("message 3"));
        assert!(text.contains("... and 1 more"));
    }

    #[test]
    fn the_summary_counts_each_check_and_the_total() {
        let text = rendered(&report(), None);

        let summary = &text[text.find("SUMMARY").unwrap()..];
        assert!(summary.contains("adapters.use-case-unwired"));
        assert!(summary.lines().last().unwrap().starts_with("  total"));
        assert!(text.starts_with("ianua-audit read 3 files\n3 findings: 1 high, 2 medium"));
    }
}
