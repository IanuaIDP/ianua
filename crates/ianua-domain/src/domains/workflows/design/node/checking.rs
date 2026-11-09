//! An agent step that checks another agent's work, and the verdict its
//! answer is read as.
//!
//! Pat's workflow has the Triage bot propose a fix for an issue, then has
//! the Code reviewer check it before anything is posted. The reviewer is
//! another agent, given no tool, so it reads and judges and does nothing
//! else. Its answer starts with `OK` or `NOT OK`; the step hands on that
//! verdict and the reviewer's notes, and a condition after it sends a
//! disagreement to a person.

use crate::domains::workflows::design::node::NodeKey;

/// The line an agent checking another's work is asked to start with, added
/// after its instruction and the work it is given.
pub(crate) const VERDICT_INSTRUCTION: &str = "\n\nYou are checking another agent's work. Start your answer with \
     one line saying only OK if the work holds, or NOT OK if it does not, then give your reasons.";

/// Whether an agent step checks another step's work.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Checks {
    /// It does its own work.
    #[default]
    Nothing,
    /// It checks the work of this earlier agent step, another agent's.
    Step(NodeKey),
}

/// What a checking agent concluded, read from the first line of its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The work holds.
    Holds,
    /// It does not.
    Fails,
    /// The answer said neither, so a person should look.
    Unclear,
}

impl Verdict {
    /// The verdict `answer` gives on its first line that says anything.
    #[must_use]
    pub fn of(answer: &str) -> Self {
        let first = answer
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default();
        let words: Vec<String> = first
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_uppercase)
            .collect();
        match words.as_slice() {
            [not, ok, ..] if not == "NOT" && ok == "OK" => Self::Fails,
            [ok, ..] if ok == "OK" => Self::Holds,
            _ => Self::Unclear,
        }
    }

    /// The word a step's output carries: `ok`, `not_ok` or `unclear`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Holds => "ok",
            Self::Fails => "not_ok",
            Self::Unclear => "unclear",
        }
    }
}

/// The reasons after a checking agent's verdict line, or nothing when it
/// gave none.
#[must_use]
pub(crate) fn notes_of(answer: &str) -> &str {
    let trimmed = answer.trim_start();
    trimmed.split_once('\n').map_or("", |(_, rest)| rest).trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OK`, `NOT OK`, their punctuated and lower case forms, and an answer
    /// saying neither read as what they say.
    #[test]
    fn the_first_line_is_read_as_the_verdict() {
        assert_eq!(Verdict::of("OK\nThe change is small."), Verdict::Holds);
        assert_eq!(Verdict::of("\n  ok.\nfine"), Verdict::Holds);
        assert_eq!(Verdict::of("NOT OK\nIt breaks the build."), Verdict::Fails);
        assert_eq!(Verdict::of("Not OK: the test is missing"), Verdict::Fails);
        assert_eq!(Verdict::of("Looks good to me"), Verdict::Unclear);
        assert_eq!(Verdict::of("OKAY"), Verdict::Unclear);
        assert_eq!(Verdict::of(""), Verdict::Unclear);
    }

    /// The notes are what follows the verdict line.
    #[test]
    fn the_notes_follow_the_verdict_line() {
        assert_eq!(
            notes_of("NOT OK\nIt breaks the build.\n"),
            "It breaks the build."
        );
        assert_eq!(notes_of("OK"), "");
    }
}
