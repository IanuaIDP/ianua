//! Whether a package's own range of interpreters takes a runtime: a
//! Python package's `requires_python`, such as `>=3.9,<4`, and an npm
//! package's `engines.node`, such as `^18 || >=20`.
//!
//! A runtime is read as its latest release of that line, since the images
//! carry one: Python 3.12 is 3.12 with the highest patch, Node 22 is 22
//! with the highest minor and patch. A range written in a form not read
//! here says nothing either way, so the package is not refused over it.

/// A version as up to three numbers; a part past the last given is open.
type Version = [u64; 3];

/// Whether `requires_python` takes Python `release`. `None` when it is
/// written in a form not read here.
pub(super) fn python_allows(requires_python: &str, release: (u32, u32)) -> Option<bool> {
    let runtime: Version = [u64::from(release.0), u64::from(release.1), u64::MAX];
    let mut allows = true;
    for clause in requires_python.split(',').map(str::trim) {
        if clause.is_empty() {
            continue;
        }
        allows &= python_clause(clause, runtime)?;
    }
    Some(allows)
}

fn python_clause(clause: &str, runtime: Version) -> Option<bool> {
    let operators = ["~=", "==", "!=", "<=", ">=", "<", ">"];
    let operator = operators.into_iter().find(|op| clause.starts_with(op))?;
    let written = clause.strip_prefix(operator)?.trim();
    if let Some(prefix) = written.strip_suffix(".*") {
        let parts = numbers(prefix)?;
        let matches = runtime.starts_with(&parts);
        return match operator {
            "==" => Some(matches),
            "!=" => Some(!matches),
            _ => None,
        };
    }
    let parts = numbers(written)?;
    let version = padded(&parts);
    match operator {
        "==" => Some(runtime == version),
        "!=" => Some(runtime != version),
        "<=" => Some(runtime <= version),
        ">=" => Some(runtime >= version),
        "<" => Some(runtime < version),
        ">" => Some(runtime > version),
        _ => compatible(&parts, runtime),
    }
}

/// `~=` with `parts`: at least them, and the same up to the last but one.
fn compatible(parts: &[u64], runtime: Version) -> Option<bool> {
    let (_, kept) = parts.split_last()?;
    if kept.is_empty() {
        return None;
    }
    Some(runtime >= padded(parts) && runtime.starts_with(kept))
}

/// Whether `engines_node` takes Node `major`. `None` when it is written in
/// a form not read here.
pub(super) fn node_allows(engines_node: &str, major: u32) -> Option<bool> {
    let runtime: Version = [u64::from(major), u64::MAX, u64::MAX];
    let mut unread = false;
    for set in engines_node.split("||") {
        match node_set(set.trim(), runtime) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unread = true,
        }
    }
    (!unread).then_some(false)
}

fn node_set(set: &str, runtime: Version) -> Option<bool> {
    if set.is_empty() || set == "*" {
        return Some(true);
    }
    if let Some((low, high)) = set.split_once(" - ") {
        let low = numbers(low.trim())?;
        let high = numbers(high.trim())?;
        return Some(runtime >= padded(&low) && runtime < above(&high));
    }
    let mut allows = true;
    for comparator in set.split_whitespace() {
        allows &= node_comparator(comparator, runtime)?;
    }
    Some(allows)
}

fn node_comparator(comparator: &str, runtime: Version) -> Option<bool> {
    let operators = [">=", "<=", ">", "<", "=", "^", "~"];
    let operator = operators
        .into_iter()
        .find(|op| comparator.starts_with(op))
        .unwrap_or("");
    let written = comparator.strip_prefix(operator)?.trim_start_matches('v');
    if written == "*" || written.eq_ignore_ascii_case("x") {
        return Some(true);
    }
    let parts = numbers(written.trim_end_matches(".x").trim_end_matches(".*"))?;
    let lowest = padded(&parts);
    match operator {
        "" | "=" => Some(runtime.starts_with(&parts)),
        ">=" => Some(runtime >= lowest),
        "<" => Some(runtime < lowest),
        ">" => Some(runtime >= above(&parts)),
        "<=" => Some(runtime < above(&parts)),
        "^" => Some(runtime >= lowest && runtime < caret_ceiling(&parts)),
        _ => Some(runtime >= lowest && runtime < bumped(&parts, parts.len().min(2))),
    }
}

/// The first version past every one `parts` names at its precision: `22`
/// gives 23.0.0, `22.1` gives 22.2.0, `22.1.3` gives 22.1.4.
fn above(parts: &[u64]) -> Version {
    bumped(parts, parts.len())
}

/// The ceiling of `^parts`: the first part that is not zero is bumped.
fn caret_ceiling(parts: &[u64]) -> Version {
    let first = parts
        .iter()
        .position(|part| *part != 0)
        .unwrap_or(parts.len().saturating_sub(1));
    bumped(parts, first.saturating_add(1))
}

/// `parts` up to `keep`, its last one plus one, the rest zero.
fn bumped(parts: &[u64], keep: usize) -> Version {
    let mut version = padded(parts.get(..keep).unwrap_or(parts));
    let last = keep.checked_sub(1).and_then(|index| version.get_mut(index));
    if let Some(last) = last {
        *last = last.saturating_add(1);
    }
    version
}

/// `parts`, the missing ones zero.
fn padded(parts: &[u64]) -> Version {
    let mut version = [0; 3];
    for (slot, part) in version.iter_mut().zip(parts) {
        *slot = *part;
    }
    version
}

/// The one to three numbers `written` holds, separated by dots. `None`
/// for anything else, such as a pre-release tag.
fn numbers(written: &str) -> Option<Vec<u64>> {
    let parts = written
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    (1..=3).contains(&parts.len()).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A package for Python 3.9 and later takes 3.11; one for 3.13 and
    /// later does not; one below 3.12 takes 3.11 but not 3.12.
    #[test]
    fn python_ranges_read_as_pip_reads_them() {
        assert_eq!(python_allows(">=3.9", (3, 11)), Some(true));
        assert_eq!(python_allows(">=3.13", (3, 11)), Some(false));
        assert_eq!(python_allows(">=3.8, <3.12", (3, 11)), Some(true));
        assert_eq!(python_allows(">=3.8, <3.12", (3, 12)), Some(false));
        assert_eq!(python_allows("~=3.10", (3, 13)), Some(true));
        assert_eq!(python_allows("==3.12.*", (3, 12)), Some(true));
        assert_eq!(python_allows("!=3.12.*", (3, 12)), Some(false));
        assert_eq!(python_allows("", (3, 12)), Some(true));
    }

    /// A Python range in a form not read here says nothing.
    #[test]
    fn an_unread_python_range_says_nothing() {
        assert_eq!(python_allows("===3.12.1", (3, 12)), None);
        assert_eq!(python_allows(">=3.12rc1", (3, 12)), None);
    }

    /// Node ranges as npm writes them: `^18 || >=20` takes 22 but not 19;
    /// `>=14 <20` refuses 22; `22.x` takes 22; `<=20` takes 20.
    #[test]
    fn node_ranges_read_as_npm_reads_them() {
        assert_eq!(node_allows("^18 || >=20", 22), Some(true));
        assert_eq!(node_allows("^18 || >=20", 19), Some(false));
        assert_eq!(node_allows(">=14 <20", 22), Some(false));
        assert_eq!(node_allows("22.x", 22), Some(true));
        assert_eq!(node_allows("<=20", 20), Some(true));
        assert_eq!(node_allows("~20.1", 20), Some(false));
        assert_eq!(node_allows("18 - 20", 20), Some(true));
        assert_eq!(node_allows("*", 24), Some(true));
    }

    /// A Node range in a form not read here says nothing, unless another
    /// set of it takes the runtime.
    #[test]
    fn an_unread_node_range_says_nothing() {
        assert_eq!(node_allows(">=20.0.0-beta", 22), None);
        assert_eq!(node_allows(">=20.0.0-beta || >=22", 22), Some(true));
    }
}
