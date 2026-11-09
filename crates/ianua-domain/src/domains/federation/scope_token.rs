//! A scope an OIDC connection asks its identity provider for.

use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// One scope an identity provider defines, as RFC 6749 allows it: any
    /// printable ASCII but space, `"` and `\`. Some providers name scopes by
    /// URL, so this is looser than this platform's own [`Scope`](crate::types::Scope).
    pub struct ScopeToken;
}

impl TextValue for ScopeToken {
    const FIELD: &'static str = "scope";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256).no_backslash().rule(&NoQuote)
    }
}

/// No `"`, which RFC 6749 leaves out of a scope token.
struct NoQuote;

impl Rule for NoQuote {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if !value.contains('"') {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_characters".to_owned(),
            message: message!(
                "federation-must-not-contain-a-quotation-mark",
                format!("{field} must not contain a quotation mark.")
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openid` and a URL scope such as Microsoft's `.default` are both
    /// accepted, since providers name scopes either way.
    #[test]
    fn a_well_formed_scope_token_is_accepted() {
        for value in ["openid", "https://graph.microsoft.com/.default"] {
            assert!(ScopeToken::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty scope, or one with a space, a quote or a backslash, is
    /// refused. RFC 6749 leaves these out of a scope token.
    #[test]
    fn a_malformed_scope_token_is_refused() {
        for value in ["", "open id", "a\"b", "a\\b"] {
            assert!(ScopeToken::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
