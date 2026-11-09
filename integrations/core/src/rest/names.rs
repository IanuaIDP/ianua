//! The names a step gives that go into a service's address: a pair such as
//! a repository's owner/name, and a path such as a file's or a branch's.
//! Each is checked part by part before it is placed, so a step can never
//! point a call outside the place it names.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;

use crate::answer::failed;

/// The two parts of the input `name`, written as `first/second`, such as
/// `acme/web`, each made of letters, digits, dots, dashes and underscores.
///
/// # Errors
///
/// A failed outcome when it is not written as two such parts.
pub fn pair<'a>(name: &str, written: &'a str) -> Result<(&'a str, &'a str), ActionOutcome> {
    let refused = || failed(&format!("the {name} is not written as two parts, a/b"));
    let (first, second) = written.trim().split_once('/').ok_or_else(refused)?;
    if !plain(first) || !plain(second) {
        return Err(refused());
    }
    Ok((first, second))
}

/// The parts of the path `written`, such as `docs/README.md` or
/// `feature/login`, each placed in the address on its own.
///
/// # Errors
///
/// A failed outcome when a part is empty, `.` or `..`, or the path holds a
/// character that is not printable, so it could climb out of the place it
/// is put or say something other than it reads.
pub(crate) fn slashed<'a>(name: &str, written: &'a str) -> Result<Vec<&'a str>, ActionOutcome> {
    let refused = || failed(&format!("the {name} is not a path inside its place"));
    let parts: Vec<&str> = written.split('/').collect();
    let sound = |part: &&str| {
        !part.is_empty() && !matches!(*part, "." | "..") && part.chars().all(|c| !c.is_control())
    };
    if parts.iter().all(sound) {
        return Ok(parts);
    }
    Err(refused())
}

/// Whether `part` is made only of letters, digits, dots, dashes and
/// underscores, and is not `.` or `..`.
fn plain(part: &str) -> bool {
    !part.is_empty()
        && !matches!(part, "." | "..")
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository identifier preserves its owner and dotted repository name.
    #[test]
    fn a_pair_reads_as_its_two_parts() {
        assert_eq!(
            pair("repository", "acme/web.site").ok(),
            Some(("acme", "web.site"))
        );
    }

    /// Repository pairs with missing parts, extra slashes, dot segments
    /// or spaces fail parsing.
    #[test]
    fn a_pair_not_written_as_two_parts_is_refused() {
        for written in [
            "acme",
            "acme/../admin",
            "acme/web/extra",
            "/web",
            "acme/..",
            "ac me/web",
        ] {
            assert!(pair("repository", written).is_err(), "{written}");
        }
    }

    /// A file's path keeps its folders, each a part of its own.
    #[test]
    fn a_path_keeps_its_parts() {
        assert_eq!(
            slashed("path", "docs/guides/README.md").ok(),
            Some(vec!["docs", "guides", "README.md"])
        );
    }

    /// Empty paths and paths containing dot segments, empty segments or
    /// line breaks fail parsing.
    #[test]
    fn a_path_that_climbs_out_or_hides_characters_is_refused() {
        for written in ["../secrets", "docs//x", "docs/\nREADME.md", "", "a/./b"] {
            assert!(slashed("path", written).is_err(), "{written:?}");
        }
    }
}
