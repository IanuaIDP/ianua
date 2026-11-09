//! Holding an operation's path against a description's path templates:
//! part by part, a fixed part with itself and an input with a
//! placeholder, a slashed input taking the template's last placeholder,
//! and, when no template matches exactly, a fixed part filling a whole
//! placeholder.

use crate::rest::operation::Segment;

/// How our path is held against a template: exactly, or with fixed parts
/// filling whole placeholders.
pub(super) type Fit = fn(&[String], &[&str]) -> bool;

/// Our path as parts to match: a fixed part as itself, an input as `{}`
/// with any fixed text around it, a pair as two inputs, and a slashed input
/// as `{..}`, which may stand for the rest of a template.
pub(super) fn our_parts(path: &[Segment]) -> Vec<String> {
    path.iter()
        .flat_map(|segment| match segment {
            Segment::Fixed(part) => vec![(*part).to_owned()],
            Segment::Pair(_) => vec!["{}".to_owned(), "{}".to_owned()],
            Segment::Input(_) => vec!["{}".to_owned()],
            Segment::Prefixed { prefix, .. } => vec![format!("{prefix}{{}}")],
            Segment::Suffixed { suffix, .. } => vec![format!("{{}}{suffix}")],
            Segment::Slashed(_) => vec!["{..}".to_owned()],
        })
        .collect()
}

/// The parts of `template`, such as `["repos", "{owner}", ...]`.
pub(super) fn parts(template: &str) -> Vec<&str> {
    template.trim_start_matches('/').split('/').collect()
}

/// The fixed text before and after the placeholder in `part`, such as
/// `("$", "")` in Azure DevOps' `${type}` or `("", ".json")` in Twilio's
/// `{Sid}.json`, when it holds one.
fn open(part: &str) -> Option<(&str, &str)> {
    let (before, rest) = part.split_once('{')?;
    let (_, after) = rest.split_once('}')?;
    Some((before, after))
}

/// Whether our `ours` path matches the `theirs` template. Their last
/// placeholder may take fixed parts of ours before a slashed input, as
/// `git/refs/{ref}` takes `heads/feature/login`.
pub(super) fn matches(ours: &[impl AsRef<str>], theirs: &[&str]) -> bool {
    let ours: Vec<&str> = ours.iter().map(AsRef::as_ref).collect();
    let (Some((&last_ours, ours_before)), Some((&last_theirs, theirs_before))) =
        (ours.split_last(), theirs.split_last())
    else {
        return ours.is_empty() && theirs.is_empty();
    };
    if last_ours == "{..}" && open(last_theirs).is_some() {
        let taken = ours_before.len().saturating_sub(theirs_before.len());
        let (kept, absorbed) = ours_before.split_at(ours_before.len() - taken);
        return absorbed.iter().all(|part| open(part).is_none()) && same(kept, theirs_before);
    }
    same(&ours, theirs)
}

/// Whether two paths agree part by part: an open part of ours with a
/// placeholder of theirs carrying the same fixed text around it, and a
/// fixed part only with itself.
fn same(ours: &[&str], theirs: &[&str]) -> bool {
    ours.len() == theirs.len()
        && ours
            .iter()
            .zip(theirs)
            .all(|(ours, theirs)| match (open(ours), open(theirs)) {
                (Some(ours), Some(theirs)) => ours == theirs,
                (None, None) => ours == theirs,
                _ => false,
            })
}

/// Whether our `ours` path matches the `theirs` template once a fixed part
/// of ours may also fill a whole placeholder of theirs, a value the step
/// always sends, as Gmail's `{userId}` takes `me`. Tried only when no
/// template matches exactly, so a template naming the part is preferred.
pub(super) fn fills(ours: &[impl AsRef<str>], theirs: &[&str]) -> bool {
    ours.len() == theirs.len()
        && ours
            .iter()
            .zip(theirs)
            .all(|(ours, theirs)| match (open(ours.as_ref()), open(theirs)) {
                (Some(ours), Some(theirs)) => ours == theirs,
                (None, None) => ours.as_ref() == *theirs,
                (None, Some(around)) => around == ("", ""),
                (Some(_), None) => false,
            })
}
