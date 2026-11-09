//! Writing what the audit found: a terminal report, JSON, or Mermaid,
//! graphs of one context, cards that explain one name, what one name's
//! change would reach, the domain's rules, and how each table's columns
//! are kept.

pub(crate) mod explain;
pub(crate) mod fields;
pub(crate) mod graph;
pub(crate) mod impact;
pub(crate) mod json;
pub(crate) mod mermaid;
pub(crate) mod rules;
pub(crate) mod terminal;

use std::collections::BTreeMap;

use serde::Serialize;

use crate::allow::Parked;
use crate::checks::adapters::wired_in_parked;
use crate::finding::{Check, Finding, Severity, Unsaid};

/// What one run found, after the allowlist.
pub(crate) struct Report {
    /// Findings left after the allowlist.
    pub(crate) findings: Vec<Finding>,
    /// Findings the allowlist allows, with its reason.
    pub(crate) allowed: Vec<(Finding, String)>,
    /// Per check, the conclusions left unsaid because they rested on what
    /// the reader marked not read.
    pub(crate) silenced: BTreeMap<Check, usize>,
    /// Each conclusion left unsaid, with the point it rested on.
    pub(crate) unsaid: Vec<Unsaid>,
    /// What each parked crate holds back.
    pub(crate) parked: Vec<ParkedCount>,
    /// How many files were read.
    pub(crate) files_read: usize,
}

/// What one parked crate holds back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ParkedCount {
    /// The crate.
    #[serde(rename = "crate")]
    pub(crate) crate_name: String,
    /// Why it is parked.
    pub(crate) reason: String,
    /// The findings in it, left out of the list.
    pub(crate) left_out: usize,
    /// The use cases only it wires, listed at info.
    pub(crate) wired_only_there: usize,
}

impl ParkedCount {
    /// Its summary line.
    pub(crate) fn line(&self) -> String {
        let wired = match self.wired_only_there {
            0 => String::new(),
            count => format!("; {count} use cases only it wires, listed at info"),
        };
        format!(
            "{} findings in parked crate {} ({}){wired}",
            self.left_out, self.crate_name, self.reason
        )
    }
}

/// `findings` without those in a `parked` crate, with what each parked
/// crate holds back.
pub(crate) fn park(findings: Vec<Finding>, parked: &[Parked]) -> (Vec<Finding>, Vec<ParkedCount>) {
    let mut counts: Vec<ParkedCount> = parked
        .iter()
        .map(|held| ParkedCount {
            crate_name: held.crate_name.clone(),
            reason: held.reason.clone(),
            left_out: 0,
            wired_only_there: 0,
        })
        .collect();
    let mut listed = Vec::new();
    for finding in findings {
        if let Some(at) = parked
            .iter()
            .position(|found| found.holds(&finding.place.file))
        {
            counts[at].left_out += 1;
            continue;
        }
        if let Some(count) = counts.iter_mut().find(|count| {
            finding.check == Check::UnwiredUseCase
                && wired_in_parked(&finding.subject, &count.crate_name)
        }) {
            count.wired_only_there += 1;
        }
        listed.push(finding);
    }
    (listed, counts)
}

/// How many findings of each severity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Tally {
    /// High.
    pub(crate) high: usize,
    /// Medium.
    pub(crate) medium: usize,
    /// Low.
    pub(crate) low: usize,
    /// Info.
    pub(crate) info: usize,
}

impl Tally {
    fn add(&mut self, severity: Severity) {
        match severity {
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    /// The count for `severity`.
    pub(crate) fn of(&self, severity: Severity) -> usize {
        match severity {
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }

    /// Every finding counted.
    pub(crate) fn total(&self) -> usize {
        self.high + self.medium + self.low + self.info
    }
}

impl Report {
    /// The count of each severity across every finding kept.
    pub(crate) fn tally(&self) -> Tally {
        let mut tally = Tally::default();
        for finding in &self.findings {
            tally.add(finding.severity);
        }
        tally
    }

    /// The count of each severity per check, for checks with findings.
    pub(crate) fn by_check(&self) -> BTreeMap<Check, Tally> {
        let mut counts: BTreeMap<Check, Tally> = BTreeMap::new();
        for finding in &self.findings {
            counts
                .entry(finding.check)
                .or_default()
                .add(finding.severity);
        }
        counts
    }

    /// Every conclusion left unsaid, across the checks.
    pub(crate) fn silenced_total(&self) -> usize {
        self.silenced.values().sum()
    }

    /// Whether a finding at `threshold` or worse is left.
    pub(crate) fn fails(&self, threshold: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity <= threshold)
    }
}

/// ANSI styles, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Style {
    colour: bool,
}

/// What a piece of text is, for colouring it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Paint {
    /// A finding of this severity.
    Severity(Severity),
    /// A heading.
    Heading,
    /// Something unreached or missing.
    Missing,
    /// Something reached.
    Present,
    /// Less important text.
    Dim,
}

impl Style {
    /// Colours when `colour` is true, plain text otherwise.
    pub(crate) fn new(colour: bool) -> Self {
        Self { colour }
    }

    /// `text` painted as `paint`.
    pub(crate) fn paint(self, text: &str, paint: Paint) -> String {
        if !self.colour {
            return text.to_owned();
        }
        let code = match paint {
            Paint::Severity(Severity::High) | Paint::Missing => "1;31",
            Paint::Severity(Severity::Medium) => "33",
            Paint::Severity(Severity::Low) => "36",
            Paint::Severity(Severity::Info) | Paint::Dim => "2",
            Paint::Heading => "1",
            Paint::Present => "32",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Place;

    fn finding(check: Check) -> Finding {
        Finding::new(
            check,
            Place {
                file: "a.rs".to_owned(),
                line: 1,
            },
            "s",
            "m",
        )
    }

    #[test]
    fn a_report_fails_on_its_threshold_or_worse() {
        let report = Report {
            findings: vec![finding(Check::UnwiredUseCase)],
            allowed: Vec::new(),
            silenced: BTreeMap::new(),
            unsaid: Vec::new(),
            parked: Vec::new(),
            files_read: 1,
        };

        assert!(report.fails(Severity::Medium));
        assert!(report.fails(Severity::Low));
        assert!(!report.fails(Severity::High));
    }

    fn at(check: Check, file: &str, subject: &str) -> Finding {
        Finding::new(
            check,
            Place {
                file: file.to_owned(),
                line: 1,
            },
            subject,
            "m",
        )
    }

    /// Two findings in the server, a use case only the server wires, and
    /// one wired nowhere.
    fn findings_beside_the_server() -> Vec<Finding> {
        vec![
            at(
                Check::UnsetPortsField,
                "crates/ianua-server/src/bootstrap.rs",
                "A.b",
            ),
            at(
                Check::UnsetPortsField,
                "crates/ianua-server/src/worker.rs",
                "C.d",
            ),
            at(
                Check::UnwiredUseCase,
                "crates/ianua-app/src/use_cases/x.rs",
                "RunUseCase (wired in parked ianua-server)",
            ),
            at(
                Check::UnwiredUseCase,
                "crates/ianua-app/src/use_cases/y.rs",
                "ListUseCase",
            ),
        ]
    }

    #[test]
    fn findings_in_a_parked_crate_are_left_out_and_counted() {
        let parked = [Parked {
            crate_name: "ianua-server".to_owned(),
            reason: "rebuilt after the infra layer".to_owned(),
        }];

        let (listed, counts) = park(findings_beside_the_server(), &parked);

        assert_eq!(listed.len(), 2);
        assert_eq!(
            counts[0].line(),
            "2 findings in parked crate ianua-server (rebuilt after the infra layer); 1 use cases only it wires, listed at info"
        );
    }

    #[test]
    fn plain_style_leaves_text_alone() {
        assert_eq!(Style::new(false).paint("x", Paint::Heading), "x");
        assert_eq!(
            Style::new(true).paint("x", Paint::Heading),
            "\x1b[1mx\x1b[0m"
        );
    }
}
