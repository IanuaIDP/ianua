//! The hosts a version's code may reach. None at all unless the version
//! names them: each by its exact DNS name, reached only over an encrypted
//! connection to its standard port, through the platform's filter.
//!
//! An address written as numbers is refused, so a host is always one the
//! platform looks up itself, and refuses when it leads somewhere private.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};

/// The most hosts one version may reach.
pub(crate) const MAX_ALLOWED_HOSTS: usize = 20;

text_value! {
    /// A host a version's code may reach, by its exact DNS name in lower
    /// case, such as `api.github.com`: at least two labels, no wildcard,
    /// and never an address written as numbers.
    pub struct AllowedHost;
}

impl TextValue for AllowedHost {
    const FIELD: &'static str = "allowed_host";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(3..=253)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::DOT)
            .domain_labels()
            .rule(&NamedNotNumbered)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

/// Every host a version's code may reach, each named once; none for code
/// that reaches no network, which is every version that names none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkAccess(Vec<AllowedHost>);

impl NetworkAccess {
    /// No network at all.
    #[must_use]
    pub fn closed() -> Self {
        Self::default()
    }

    /// Code reaching `hosts`, and nothing else.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there are more than
    ///   `MAX_ALLOWED_HOSTS`.
    /// - [`DomainError::Validation`] when a host is named twice.
    pub fn new(hosts: Vec<AllowedHost>) -> Result<Self, DomainError> {
        validate_count("allowed_hosts", hosts.len(), 0..=MAX_ALLOWED_HOSTS)?;
        if let Some(twice) = first_repeat(hosts.iter()) {
            return Err(DomainError::invalid(message!(
                "workflows-the-host-is-allowed-twice",
                format!("the host {twice} is allowed twice")
            )));
        }
        Ok(Self(hosts))
    }

    /// The hosts, in the order they were given.
    #[must_use]
    pub fn hosts(&self) -> &[AllowedHost] {
        &self.0
    }

    /// Whether the code reaches no network at all.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.is_empty()
    }

    /// The hosts, comma-separated, for a record; `None` when the code
    /// reaches no network.
    #[must_use]
    pub fn listed(&self) -> Option<String> {
        let hosts: Vec<&str> = self.0.iter().map(AllowedHost::as_str).collect();
        (!hosts.is_empty()).then(|| hosts.join(","))
    }

    /// Whether the code may reach `host`, compared as DNS names are.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().any(|allowed| allowed.as_str() == host)
    }
}

/// A host's last label holds a letter, so the host is a name looked up,
/// not an address written as numbers.
struct NamedNotNumbered;

impl Rule for NamedNotNumbered {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let last = value.rsplit('.').next().unwrap_or_default();
        let numbered = last.bytes().all(|byte| byte.is_ascii_digit());
        numbered.then(|| ValidationError::Custom {
            field,
            code: "numbered_host".to_owned(),
            message: message!(
                "workflows-a-host-is-named-by-its",
                "a host is named by its DNS name, not by an address"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(names: &[&str]) -> Vec<AllowedHost> {
        names
            .iter()
            .map(|name| AllowedHost::new(*name).unwrap())
            .collect()
    }

    /// A host is kept by its DNS name in lower case.
    #[test]
    fn a_host_is_kept_in_lower_case() {
        assert_eq!(
            AllowedHost::new("API.GitHub.com").unwrap().as_str(),
            "api.github.com"
        );
    }

    /// Allowed hosts reject IP literals, wildcards, single-label names and
    /// hostnames carrying ports or paths.
    #[test]
    fn only_an_exact_name_is_a_host() {
        for refused in [
            "10.0.0.1",
            "169.254.169.254",
            "*.github.com",
            "localhost",
            "api.github.com:443",
            "api.github.com/repos",
            "[::1]",
        ] {
            assert!(AllowedHost::new(refused).is_err(), "{refused} was taken");
        }
    }

    /// No hosts is no network; a host named twice, or more hosts than a
    /// version may reach, is refused.
    #[test]
    fn hosts_are_named_once_and_within_the_most() {
        let many: Vec<String> = (0..=MAX_ALLOWED_HOSTS)
            .map(|index| format!("h{index}.example.com"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();

        assert!(NetworkAccess::closed().is_closed());
        assert!(NetworkAccess::new(hosts(&["api.github.com", "api.github.com"])).is_err());
        assert!(NetworkAccess::new(hosts(&many)).is_err());
    }

    /// Code reaches exactly the hosts named, whatever their case or a
    /// trailing dot, and nothing beneath or beside them.
    #[test]
    fn only_the_hosts_named_are_reached() {
        let access = NetworkAccess::new(hosts(&["api.github.com"])).unwrap();

        assert!(access.allows("API.github.com."));
        assert!(!access.allows("evil.api.github.com"));
        assert!(!access.allows("github.com"));
    }
}
