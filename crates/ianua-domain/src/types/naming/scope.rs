use crate::shared::validation::{Charset, TextValue, Validator, text_value};

/// The longest scope accepted.
const MAX_SCOPE_LENGTH: usize = 128;

text_value! {
    /// An OAuth or API key scope, the level of access a token or key gets.
    ///
    /// OAuth clients and API keys share scopes. A scope narrows access and
    /// never grants it. A key with `["idp:users:view"]` reaches only that,
    /// however much authority the user who made it holds.
    ///
    /// It has the form `"resource:action"`, like
    /// [`CustomPermission`](crate::domains::authorization::permission::CustomPermission),
    /// but it scopes machine-to-machine and OAuth tokens. An API key's
    /// scopes must also name a
    /// [`SystemPermission`](crate::domains::authorization::permission::SystemPermission),
    /// and that is where the narrowing is checked. An OAuth client's scopes
    /// need not.
    ///
    /// # Validation
    ///
    /// - Not empty, at most 128 characters.
    /// - Lowercase ASCII letters, digits, hyphens, underscores, colons and
    ///   `*`.
    /// - No control characters.
    pub struct Scope;
}

impl TextValue for Scope {
    const FIELD: &'static str = "scope";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=MAX_SCOPE_LENGTH,
            Charset::LOWERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::COLON
                | Charset::ASTERISK,
        )
    }
}

impl Scope {
    /// Whether this scope permits `permission`.
    ///
    /// It compares segment by segment against the permission's own form,
    /// `idp:<domain>:<action>`, where `*` stands for exactly one segment. A
    /// scope with a different number of segments matches nothing.
    /// `idp:users` is not shorthand for every action on users, because a
    /// scope that quietly widened could not be read at a glance.
    #[must_use]
    pub fn permits(&self, permission: &str) -> bool {
        let mut granted = self.0.split(':');
        let mut wanted = permission.split(':');

        loop {
            match (granted.next(), wanted.next()) {
                (None, None) => return true,
                (Some(g), Some(w)) if g == "*" || g == w => {}
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `projects_read` is accepted and kept as written.
    #[test]
    fn accepts_simple_scope() {
        let s = Scope::new("projects_read").unwrap();
        assert_eq!(s.as_str(), "projects_read");
    }

    /// The scope grammar permits a wildcard without a resource prefix.
    #[test]
    fn a_bare_wildcard_scope_is_valid() {
        assert!(Scope::new("*").is_ok());
    }

    /// `my-resource_read` with a hyphen and an underscore is accepted.
    #[test]
    fn accepts_hyphens_and_underscores() {
        assert!(Scope::new("my-resource_read").is_ok());
    }

    /// Empty text is refused instead of becoming an access scope.
    #[test]
    fn an_empty_scope_is_refused() {
        assert!(Scope::new("").is_err());
    }

    /// `Projects_Read` with capitals is refused.
    #[test]
    fn uppercase_scopes_are_refused() {
        assert!(Scope::new("Projects_Read").is_err());
    }

    /// `projects read` with a space is refused, since scopes are sent as a
    /// space-separated list.
    #[test]
    fn scopes_with_spaces_are_refused() {
        assert!(Scope::new("projects read").is_err());
    }

    /// `projeçts` holds a non-ASCII letter and is refused.
    #[test]
    fn non_ascii_scopes_are_refused() {
        assert!(Scope::new("projeçts").is_err());
    }

    /// A scope with a NUL byte inside it is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(Scope::new("scope\x00name").is_err());
    }

    /// A 129-character scope is refused.
    #[test]
    fn rejects_over_max_length() {
        assert!(Scope::new("a".repeat(129)).is_err());
    }

    /// `webhooks_write` prints as `webhooks_write`.
    #[test]
    fn display_returns_value() {
        let s = Scope::new("webhooks_write").unwrap();
        assert_eq!(s.to_string(), "webhooks_write");
    }

    fn scope(s: &str) -> Scope {
        Scope::new(s).unwrap()
    }

    /// A key scoped to `idp:domains:create` may create domains, but not
    /// delete them or create API keys.
    #[test]
    fn an_exact_scope_permits_only_that_permission() {
        let granted = scope("idp:domains:create");

        assert!(granted.permits("idp:domains:create"));
        assert!(!granted.permits("idp:domains:delete"));
        assert!(!granted.permits("idp:api_keys:create"));
    }

    /// `idp:domains:*` permits any action on domains but nothing on API
    /// keys. `idp:*:view` permits viewing agents, and `*:*:*` permits any
    /// three-part permission.
    #[test]
    fn a_star_stands_for_one_segment() {
        assert!(scope("idp:domains:*").permits("idp:domains:delete"));
        assert!(!scope("idp:domains:*").permits("idp:api_keys:delete"));
        assert!(scope("idp:*:view").permits("idp:agents:view"));
        assert!(scope("*:*:*").permits("idp:domains:create"));
    }

    /// Two-part and one-part scope prefixes do not permit a three-part delete
    /// permission; omitted segments never widen access.
    #[test]
    fn a_shorter_scope_is_not_a_prefix() {
        assert!(!scope("idp:domains").permits("idp:domains:delete"));
        assert!(!scope("idp").permits("idp:domains:delete"));
    }

    /// A scope with an extra fourth segment does not permit the three-part
    /// `idp:domains:create`.
    #[test]
    fn a_longer_scope_permits_nothing_shorter() {
        assert!(!scope("idp:domains:create:extra").permits("idp:domains:create"));
    }
}
