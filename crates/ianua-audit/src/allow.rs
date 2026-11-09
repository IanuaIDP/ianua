//! Intentional exceptions, read from a TOML file.
//!
//! ```toml
//! [[allow]]
//! check = "reach.behaviour"
//! subject = "Topic::*"
//! path = "crates/ianua-domain/src/domains/messaging/"
//! reason = "Topics are driven by the broker, not by a use case."
//! ```
//!
//! `check` and `reason` are required. `subject` matches a finding's subject
//! exactly, or every subject starting with what comes before a trailing
//! `*`. `subjects = [..]` lists several subjects under one reason; each
//! counts as an entry of its own. `path` matches findings in files whose
//! path starts with it. An entry that matches nothing is reported, so the
//! list does not keep exceptions that are gone.
//!
//! A `[[parked]]` entry (`crate`, `reason`, both required) names a crate
//! waiting for a rebuild: the report leaves its findings out and counts
//! them. One naming no crate in the workspace is reported.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::finding::{Check, Finding};
use crate::source::Place;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    #[serde(default)]
    allow: Vec<RawEntry>,
    #[serde(default)]
    parked: Vec<RawParked>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParked {
    #[serde(rename = "crate")]
    crate_name: String,
    reason: String,
}

/// A crate waiting for a rebuild: its findings are left out of the list
/// and counted instead, so they neither flood the report nor are lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parked {
    /// The crate's folder name, such as `ianua-server`.
    pub(crate) crate_name: String,
    /// Why it is parked.
    pub(crate) reason: String,
}

impl Parked {
    /// Whether `file`, a path from the workspace root, is in this crate.
    pub(crate) fn holds(&self, file: &str) -> bool {
        file.starts_with(&format!("crates/{}/", self.crate_name))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    check: String,
    subject: Option<String>,
    subjects: Option<Vec<String>>,
    path: Option<String>,
    reason: String,
}

/// One exception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AllowEntry {
    check: Check,
    subject: Option<String>,
    path: Option<String>,
    /// Why it is allowed.
    pub(crate) reason: String,
}

impl AllowEntry {
    fn matches(&self, finding: &Finding) -> bool {
        let subject = self.subject.as_deref().is_none_or(|wanted| {
            wanted
                .strip_suffix('*')
                .map_or(wanted == finding.subject, |prefix| {
                    finding.subject.starts_with(prefix)
                })
        });
        let path = self
            .path
            .as_deref()
            .is_none_or(|prefix| finding.place.file.starts_with(prefix));
        self.check == finding.check && subject && path
    }

    fn describe(&self) -> String {
        let mut parts = vec![self.check.id().to_owned()];
        parts.extend(
            self.subject
                .iter()
                .map(|subject| format!("subject {subject}")),
        );
        parts.extend(self.path.iter().map(|path| format!("path {path}")));
        parts.join(", ")
    }
}

/// The exceptions, with the file they came from.
#[derive(Clone, Debug, Default)]
pub(crate) struct Allowlist {
    entries: Vec<AllowEntry>,
    /// The parked crates.
    pub(crate) parked: Vec<Parked>,
    source: String,
}

/// Findings once the allowlist has been applied.
pub(crate) struct Applied {
    /// Findings no entry allows, and one for each entry that matched none.
    pub(crate) kept: Vec<Finding>,
    /// Findings an entry allows, with its reason.
    pub(crate) allowed: Vec<(Finding, String)>,
}

impl Allowlist {
    /// The entries in `text`, read from the file at `source`.
    ///
    /// # Errors
    ///
    /// Fails when the text is not valid TOML of this shape, names an
    /// unknown check, or gives an empty reason.
    pub(crate) fn parse(text: &str, source: &str) -> Result<Self> {
        let file: AllowFile =
            toml::from_str(text).with_context(|| format!("reading the allowlist {source}"))?;
        let entries = file
            .allow
            .into_iter()
            .enumerate()
            .map(|(index, raw)| entry(raw, index, source))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let parked = file
            .parked
            .into_iter()
            .enumerate()
            .map(|(index, raw)| parked(raw, index, source))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            entries,
            parked,
            source: source.to_owned(),
        })
    }

    /// A finding for each parked entry naming none of `crates`, the crate
    /// folders the workspace has.
    pub(crate) fn unknown_parked(&self, crates: &BTreeSet<String>) -> Vec<Finding> {
        self.parked
            .iter()
            .filter(|parked| !crates.contains(&parked.crate_name))
            .map(|parked| {
                let shown = format!("parked {}", parked.crate_name);
                Finding::new(
                    Check::UnusedAllow,
                    Place {
                        file: self.source.clone(),
                        line: 0,
                    },
                    shown.clone(),
                    format!("the entry ({shown}) names no crate in the workspace",),
                )
            })
            .collect()
    }

    /// Splits `findings` into those kept and those allowed.
    pub(crate) fn apply(&self, findings: Vec<Finding>) -> Applied {
        let mut used = vec![false; self.entries.len()];
        let mut kept = Vec::new();
        let mut allowed = Vec::new();
        for finding in findings {
            let Some(index) = self
                .entries
                .iter()
                .position(|entry| entry.matches(&finding))
            else {
                kept.push(finding);
                continue;
            };
            used[index] = true;
            allowed.push((finding, self.entries[index].reason.clone()));
        }
        kept.extend(
            self.entries
                .iter()
                .zip(used)
                .filter(|(_, used)| !used)
                .map(|(entry, _)| self.unused(entry)),
        );
        Applied { kept, allowed }
    }

    fn unused(&self, entry: &AllowEntry) -> Finding {
        Finding::new(
            Check::UnusedAllow,
            Place {
                file: self.source.clone(),
                line: 0,
            },
            entry.describe(),
            format!("the entry ({}) matches no finding", entry.describe()),
        )
    }
}

fn parked(raw: RawParked, index: usize, source: &str) -> Result<Parked> {
    if raw.crate_name.trim().is_empty() || raw.reason.trim().is_empty() {
        bail!(
            "{source}: parked entry {} needs a crate and a reason",
            index + 1
        );
    }
    Ok(Parked {
        crate_name: raw.crate_name,
        reason: raw.reason,
    })
}

/// The entries `raw` stands for: one, or one for each of its `subjects`,
/// so each subject is reported on its own once it matches nothing.
fn entry(raw: RawEntry, index: usize, source: &str) -> Result<Vec<AllowEntry>> {
    let at = format!("{source}: entry {}", index + 1);
    let Some(check) = Check::parse(&raw.check) else {
        bail!("{at} names an unknown check `{}`", raw.check);
    };
    if raw.reason.trim().is_empty() {
        bail!("{at} for `{}` gives no reason", raw.check);
    }
    if raw.subject.is_some() && raw.subjects.is_some() {
        bail!(
            "{at} for `{}` names both `subject` and `subjects`",
            raw.check
        );
    }
    let subjects = raw.subjects.map_or_else(
        || vec![raw.subject],
        |listed| listed.into_iter().map(Some).collect(),
    );
    Ok(subjects
        .into_iter()
        .map(|subject| AllowEntry {
            check,
            subject,
            path: raw.path.clone(),
            reason: raw.reason.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(check: Check, file: &str, subject: &str) -> Finding {
        Finding::new(
            check,
            Place {
                file: file.to_owned(),
                line: 1,
            },
            subject,
            "message",
        )
    }

    #[test]
    fn an_entry_allows_matching_findings_and_keeps_the_rest() {
        let list = Allowlist::parse(
            r#"
            [[allow]]
            check = "reach.behaviour"
            subject = "Topic::*"
            reason = "driven by the broker"
            "#,
            "allow.toml",
        )
        .unwrap();

        let applied = list.apply(vec![
            finding(Check::UnreachedBehaviour, "a.rs", "Topic::pause"),
            finding(Check::UnreachedBehaviour, "a.rs", "Schema::evolve"),
        ]);

        assert_eq!(applied.allowed[0].0.subject, "Topic::pause");
        assert_eq!(applied.allowed[0].1, "driven by the broker");
        assert_eq!(applied.kept[0].subject, "Schema::evolve");
    }

    /// Several subjects share one reason, and a listed subject that
    /// matches nothing is reported on its own, so the list cannot keep a
    /// name that is gone behind others still in use.
    #[test]
    fn listed_subjects_allow_each_and_report_each_gone_one() {
        let list = Allowlist::parse(
            r#"
            [[allow]]
            check = "reach.behaviour"
            subjects = ["Topic::pause", "Topic::gone"]
            reason = "driven by the broker"
            "#,
            "allow.toml",
        )
        .unwrap();

        let applied = list.apply(vec![finding(
            Check::UnreachedBehaviour,
            "a.rs",
            "Topic::pause",
        )]);

        assert_eq!(applied.allowed[0].0.subject, "Topic::pause");
        assert_eq!(applied.kept.len(), 1);
        assert!(applied.kept[0].subject.contains("Topic::gone"));
    }

    /// Stops: an entry naming both `subject` and `subjects`, whose meaning
    /// is unclear, is read as one of them. It is refused.
    #[test]
    fn an_entry_naming_subject_and_subjects_is_refused() {
        let read = Allowlist::parse(
            "[[allow]]\ncheck = \"reach.behaviour\"\nsubject = \"A::b\"\nsubjects = [\"C::d\"]\nreason = \"r\"\n",
            "allow.toml",
        );

        assert!(read.is_err());
    }

    #[test]
    fn an_entry_that_matches_nothing_is_reported() {
        let list = Allowlist::parse(
            "[[allow]]\ncheck = \"reach.proof\"\npath = \"crates/x/\"\nreason = \"gone\"\n",
            "allow.toml",
        )
        .unwrap();

        let applied = list.apply(vec![finding(Check::UnreachedProof, "crates/y/a.rs", "P")]);

        assert_eq!(applied.kept.len(), 2);
        assert_eq!(applied.kept[1].check, Check::UnusedAllow);
    }

    const PARKED: &str = r#"
        [[parked]]
        crate = "ianua-server"
        reason = "rebuilt after the infra layer"

        [[parked]]
        crate = "ianua-gone"
        reason = "removed long ago"
    "#;

    #[test]
    fn a_parked_crate_holds_the_files_below_it() {
        let list = Allowlist::parse(PARKED, "allow.toml").unwrap();

        let server = &list.parked[0];

        assert_eq!(server.reason, "rebuilt after the infra layer");
        assert!(server.holds("crates/ianua-server/src/bootstrap.rs"));
        assert!(!server.holds("crates/ianua-server-extra/src/lib.rs"));
        assert!(!server.holds("crates/ianua-api/src/lib.rs"));
    }

    #[test]
    fn a_parked_entry_naming_no_crate_is_reported() {
        let list = Allowlist::parse(PARKED, "allow.toml").unwrap();
        let crates = BTreeSet::from(["ianua-server".to_owned(), "ianua-api".to_owned()]);

        let found = list.unknown_parked(&crates);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check, Check::UnusedAllow);
        assert_eq!(
            found[0].message,
            "the entry (parked ianua-gone) names no crate in the workspace"
        );
    }

    #[test]
    fn a_parked_entry_without_a_reason_is_refused() {
        let refused = Allowlist::parse(
            "[[parked]]\ncrate = \"ianua-server\"\nreason = \" \"\n",
            "allow.toml",
        );

        assert!(refused.is_err());
    }

    #[test]
    fn an_entry_without_a_reason_is_refused() {
        let refused = Allowlist::parse(
            "[[allow]]\ncheck = \"reach.proof\"\nreason = \"  \"\n",
            "allow.toml",
        );

        assert!(refused.is_err());
    }

    #[test]
    fn an_entry_naming_an_unknown_check_is_refused() {
        let refused = Allowlist::parse(
            "[[allow]]\ncheck = \"reach.nothing\"\nreason = \"x\"\n",
            "allow.toml",
        );

        assert!(refused.is_err());
    }
}
