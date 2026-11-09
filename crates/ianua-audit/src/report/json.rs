//! The report as JSON, for CI and other tools.

use serde::Serialize;

use crate::finding::{Check, Finding, Unsaid};
use crate::report::{ParkedCount, Report, Tally};

#[derive(Serialize)]
struct JsonReport<'a> {
    files_read: usize,
    summary: Tally,
    allowed_count: usize,
    silenced_count: usize,
    parked: &'a [ParkedCount],
    checks: Vec<JsonCheck>,
    findings: &'a [Finding],
    allowed: Vec<JsonAllowed<'a>>,
    unsaid: &'a [Unsaid],
}

#[derive(Serialize)]
struct JsonCheck {
    id: &'static str,
    area: &'static str,
    severity: &'static str,
    title: &'static str,
    count: usize,
    silenced: usize,
}

#[derive(Serialize)]
struct JsonAllowed<'a> {
    finding: &'a Finding,
    reason: &'a str,
}

/// The report as pretty JSON.
///
/// # Errors
///
/// Fails only if serialising fails, which these plain types do not.
pub(crate) fn render(report: &Report) -> serde_json::Result<String> {
    let counts = report.by_check();
    let checks = Check::ALL
        .into_iter()
        .map(|check| JsonCheck {
            id: check.id(),
            area: check.area().title(),
            severity: check.severity().as_str(),
            title: check.title(),
            count: counts.get(&check).map_or(0, Tally::total),
            silenced: report.silenced.get(&check).copied().unwrap_or(0),
        })
        .collect();
    serde_json::to_string_pretty(&JsonReport {
        files_read: report.files_read,
        summary: report.tally(),
        allowed_count: report.allowed.len(),
        silenced_count: report.silenced_total(),
        parked: &report.parked,
        checks,
        findings: &report.findings,
        allowed: report
            .allowed
            .iter()
            .map(|(finding, reason)| JsonAllowed { finding, reason })
            .collect(),
        unsaid: &report.unsaid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Place;

    #[test]
    fn a_finding_is_written_with_its_check_id_and_place() {
        let report = Report {
            findings: vec![Finding::new(
                Check::UnwiredUseCase,
                Place {
                    file: "a.rs".to_owned(),
                    line: 4,
                },
                "ListUseCase",
                "no adapter names it",
            )],
            allowed: Vec::new(),
            silenced: std::collections::BTreeMap::new(),
            unsaid: Vec::new(),
            parked: Vec::new(),
            files_read: 1,
        };

        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();

        let finding = &value["findings"][0];
        assert_eq!(finding["check"], "adapters.use-case-unwired");
        assert_eq!(finding["severity"], "medium");
        assert_eq!(finding["file"], "a.rs");
        assert_eq!(finding["line"], 4);
        assert!(finding.get("detail").is_none());
        assert_eq!(value["summary"]["medium"], 1);
    }

    #[test]
    fn detail_and_the_unsaid_are_written_when_there_are_any() {
        let report = detailed_report();

        let value: serde_json::Value = serde_json::from_str(&render(&report).unwrap()).unwrap();

        assert_eq!(value["findings"][0]["detail"][0], "fix: check it");
        assert_eq!(value["silenced_count"], 3);
        assert_eq!(value["unsaid"][0]["check"], "limits.path-missing");
        assert_eq!(value["unsaid"][0]["line"], 9);
        assert_eq!(value["unsaid"][0]["why"], "`helper`: not followed");
        assert_eq!(value["parked"][0]["crate"], "ianua-zero");
        assert_eq!(value["parked"][0]["left_out"], 4);
        let limits = value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["id"] == "limits.path-missing")
            .unwrap();
        assert_eq!(limits["silenced"], 3);
    }

    /// A report with a finding carrying detail, a silenced count, a
    /// conclusion left unsaid and a parked crate.
    fn detailed_report() -> Report {
        let place = |file: &str, line| Place {
            file: file.to_owned(),
            line,
        };
        Report {
            findings: vec![
                Finding::new(
                    Check::MissingLimitPath,
                    place("a.rs", 4),
                    "User::create in identity::RunUseCase (Users)",
                    "it creates a user without the check",
                )
                .with_detail(["fix: check it".to_owned()]),
            ],
            allowed: Vec::new(),
            silenced: std::collections::BTreeMap::from([(Check::MissingLimitPath, 3)]),
            unsaid: vec![Unsaid::new(
                Check::MissingLimitPath,
                "User::create in identity::RunUseCase (Users)",
                place("b.rs", 9),
                "`helper`: not followed",
            )],
            parked: vec![ParkedCount {
                crate_name: "ianua-zero".to_owned(),
                reason: "the gateway is rebuilt after the server".to_owned(),
                left_out: 4,
                wired_only_there: 1,
            }],
            files_read: 1,
        }
    }
}
