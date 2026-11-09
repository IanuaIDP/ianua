//! The names shared test containers run under.

/// `base`, followed by the CI runner's name when `RUNNER_NAME` is set, so
/// runners sharing a machine do not share a container.
#[must_use]
pub fn on_this_runner(base: &str) -> String {
    for_runner(base, std::env::var("RUNNER_NAME").ok().as_deref())
}

/// `base` for the runner named `runner`, in the characters Docker accepts in
/// a container name.
fn for_runner(base: &str, runner: Option<&str>) -> String {
    let Some(runner) = runner.map(str::trim).filter(|name| !name.is_empty()) else {
        return base.to_owned();
    };
    let safe: String = runner
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '.' | '-' => c,
            _ => '-',
        })
        .collect();
    format!("{base}-{safe}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub names its hosted runners with spaces, which Docker refuses.
    #[test]
    fn a_runner_name_with_spaces_becomes_a_valid_container_name() {
        let name = for_runner("ianua-test-postgres", Some("GitHub Actions 1000001670"));

        assert_eq!(name, "ianua-test-postgres-GitHub-Actions-1000001670");
    }

    #[test]
    fn no_runner_leaves_the_base_name() {
        assert_eq!(for_runner("ianua-test-bus", None), "ianua-test-bus");
        assert_eq!(for_runner("ianua-test-bus", Some("  ")), "ianua-test-bus");
    }
}
