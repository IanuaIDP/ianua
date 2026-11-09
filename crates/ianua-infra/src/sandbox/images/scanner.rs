//! Scanning a company's image for known vulnerabilities through a scanner
//! command the operator names, such as a small script around Trivy or
//! Grype, and the scanner of a deployment that names none, which clears
//! nothing.
//!
//! The command is run as `<command> <image>`, the image named by its
//! digest, with the registry's login, when there is one, in the
//! `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` variables and nowhere else.
//! It prints its findings as SARIF 2.1, the format both scanners write. A
//! finding is critical when its rule is tagged `CRITICAL` or its
//! `security-severity` is 9.0 or more. The command is stopped at its time
//! limit, its output read within a bound; one that fails, or prints no
//! SARIF, is a scanner that could not scan, tried again later.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::workflows::{ImageScanner, PullLogin, Scanning};
use ianua_domain::domains::workflows::sandbox::image::{
    ImageFindings, LesserFindings, PinnedImage, VulnerabilityId,
};
use ianua_domain::types::UntrustedText;
use serde_json::Value;
use tokio::process::Command;

use crate::sandbox::output::{bounded, last_of};

/// The most bytes of SARIF read from the scanner.
const MOST_SARIF: usize = 64 * 1024 * 1024;

/// The most bytes of the scanner's errors kept for the record.
const ERRORS_KEPT: usize = 4096;

/// How the scanner command is run.
#[derive(Debug, Clone)]
pub struct ScanSettings {
    /// The command, run with the image as its one argument.
    pub command: PathBuf,
    /// How long one scan may take.
    pub within: Duration,
}

/// Scans images through the operator's scanner command.
pub struct CommandImageScanner {
    settings: ScanSettings,
}

impl CommandImageScanner {
    /// A scanner running the command `settings` names.
    #[must_use]
    pub fn new(settings: ScanSettings) -> Self {
        Self { settings }
    }

    /// The SARIF the command printed for `image`, or why it printed none.
    async fn sarif(&self, image: &PinnedImage, login: &PullLogin) -> Result<Vec<u8>, String> {
        let mut command = Command::new(&self.settings.command);
        command
            .arg(image.as_str())
            .env_remove("REGISTRY_USERNAME")
            .env_remove("REGISTRY_PASSWORD")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let PullLogin::Password { username, password } = login {
            command
                .env("REGISTRY_USERNAME", username.as_str())
                .env("REGISTRY_PASSWORD", password.expose());
        }
        let ran = tokio::time::timeout(self.settings.within, run(command)).await;
        ran.unwrap_or_else(|_| Err("the scanner did not finish in time".to_owned()))
    }
}

/// Runs `command` and reads its output: the SARIF, or why there is none.
async fn run(mut command: Command) -> Result<Vec<u8>, String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("the scanner did not start: {error}"))?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err("the scanner's output was not opened".to_owned());
    };
    let (sarif, errors) = tokio::join!(bounded(stdout, MOST_SARIF), last_of(stderr, ERRORS_KEPT));
    let status = child
        .wait()
        .await
        .map_err(|error| format!("the scanner's end was not read: {error}"))?;
    let errors = String::from_utf8_lossy(&errors.unwrap_or_default()).into_owned();
    let sarif = sarif.map_err(|error| format!("the scanner's output was not read: {error}"))?;
    match (status.success(), sarif.len() > MOST_SARIF) {
        (true, false) => Ok(sarif),
        (true, true) => Err("the scanner printed more than a scan may".to_owned()),
        (false, _) => Err(format!("the scanner failed: {errors}")),
    }
}

#[async_trait]
impl ImageScanner for CommandImageScanner {
    async fn scan(&self, image: &PinnedImage, login: &PullLogin) -> Scanning {
        let found = self
            .sarif(image, login)
            .await
            .and_then(|sarif| findings_of(&sarif));
        match found {
            Ok(findings) => Scanning::Scanned(findings),
            Err(why) => Scanning::Unavailable(UntrustedText::record(&why)),
        }
    }
}

/// The scanner of a deployment that names no scanner command: it clears no
/// image, so no company image runs unscanned.
pub struct NoImageScanner;

#[async_trait]
impl ImageScanner for NoImageScanner {
    async fn scan(&self, _image: &PinnedImage, _login: &PullLogin) -> Scanning {
        Scanning::NotSetUp
    }
}

/// How severe a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// The findings `sarif` reports, by severity.
fn findings_of(sarif: &[u8]) -> Result<ImageFindings, String> {
    let sarif: Value =
        serde_json::from_slice(sarif).map_err(|_| "the scanner printed no SARIF".to_owned())?;
    let runs = sarif
        .get("runs")
        .and_then(Value::as_array)
        .ok_or("the scanner's SARIF holds no runs")?;
    let mut critical = Vec::new();
    let mut lesser = LesserFindings::default();
    for run in runs {
        for (rule, severity) in run_findings(run) {
            match severity {
                Severity::Critical => critical.push(finding_named(rule)),
                Severity::High => lesser.high = lesser.high.saturating_add(1),
                Severity::Medium => lesser.medium = lesser.medium.saturating_add(1),
                Severity::Low => lesser.low = lesser.low.saturating_add(1),
            }
        }
    }
    Ok(ImageFindings::new(critical, lesser))
}

/// Each result of `run`, by its rule's id and severity.
fn run_findings(run: &Value) -> Vec<(&str, Severity)> {
    let rules = run
        .get("tool")
        .and_then(|tool| tool.get("driver"))
        .and_then(|driver| driver.get("rules"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let results = run
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    results
        .iter()
        .map(|result| {
            let id = result
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let rule = rules
                .iter()
                .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id));
            (id, severity_of(rule, result))
        })
        .collect()
}

/// A finding's severity: its rule's tag, else its rule's
/// `security-severity`, else the result's level.
fn severity_of(rule: Option<&Value>, result: &Value) -> Severity {
    let properties = rule.and_then(|rule| rule.get("properties"));
    let tagged = properties
        .and_then(|properties| properties.get("tags"))
        .and_then(Value::as_array)
        .and_then(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .find_map(severity_named)
        });
    let scored = properties
        .and_then(|properties| properties.get("security-severity"))
        .and_then(Value::as_str)
        .and_then(|score| score.parse::<f64>().ok())
        .map(severity_scored);
    tagged
        .or(scored)
        .unwrap_or_else(|| severity_levelled(result))
}

/// The severity a tag names, such as `CRITICAL`.
fn severity_named(tag: &str) -> Option<Severity> {
    match tag.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// The severity a CVSS score puts a finding at.
fn severity_scored(score: f64) -> Severity {
    match score {
        score if score >= 9.0 => Severity::Critical,
        score if score >= 7.0 => Severity::High,
        score if score >= 4.0 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// The severity a result's level puts a finding at when its rule says none.
fn severity_levelled(result: &Value) -> Severity {
    match result.get("level").and_then(Value::as_str) {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        _ => Severity::Low,
    }
}

/// The finding `rule` names, or one unnamed when its id is not one.
fn finding_named(rule: &str) -> VulnerabilityId {
    VulnerabilityId::new(rule).unwrap_or_else(|_| VulnerabilityId::unnamed())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sarif() -> Vec<u8> {
        serde_json::to_vec(&json!({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"rules": [
                {"id": "CVE-2024-3094", "properties": {"tags": ["vulnerability", "CRITICAL"]}},
                {"id": "CVE-2023-0001", "properties": {"security-severity": "7.5"}},
                {"id": "CVE-2023-0002", "properties": {"security-severity": "9.8"}},
            ]}},
            "results": [
                {"ruleId": "CVE-2024-3094", "level": "error"},
                {"ruleId": "CVE-2023-0001", "level": "error"},
                {"ruleId": "CVE-2023-0002", "level": "error"},
                {"ruleId": "CVE-2023-0003", "level": "note"},
            ],
        }]}))
        .unwrap()
    }

    /// Findings tagged critical or scored 9.0 or more are critical and
    /// named; the rest are counted by severity.
    #[test]
    fn critical_findings_are_named_and_the_rest_counted() {
        let findings = findings_of(&sarif()).unwrap();

        let named: Vec<&str> = findings
            .critical()
            .iter()
            .map(VulnerabilityId::as_str)
            .collect();
        assert_eq!(named, ["CVE-2024-3094", "CVE-2023-0002"]);
        assert_eq!(
            findings.lesser(),
            LesserFindings {
                high: 1,
                medium: 0,
                low: 1
            }
        );
    }

    /// Output that is not SARIF is a scan that did not happen.
    #[test]
    fn output_that_is_no_sarif_is_refused() {
        assert!(findings_of(b"Scanning...").is_err());
        assert!(findings_of(b"{}").is_err());
    }

    /// The deployment with no scanner clears nothing.
    #[tokio::test]
    async fn no_scanner_clears_nothing() {
        let image = PinnedImage::parse(&format!("ghcr.io/acme/codegen@sha256:{}", "ab".repeat(32)))
            .unwrap();

        let scanned = NoImageScanner.scan(&image, &PullLogin::Anonymous).await;

        assert_eq!(scanned, Scanning::NotSetUp);
    }
}
