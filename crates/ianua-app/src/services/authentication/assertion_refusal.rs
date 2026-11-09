//! Refusing a SAML assertion without saying why, for every sign-in that
//! checks one: a tenant's connection and an organization's own provider.
//!
//! The validator's message names the check that failed, which is a free
//! oracle for anyone iterating on a forged assertion. The reason is logged
//! for operators; the caller learns only that it was refused.

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::error::AppError;

/// A refusal that says nothing about why the response failed.
pub(crate) fn rejected_assertion(error: &DomainError) -> AppError {
    tracing::warn!(%error, "SAML assertion rejected");
    AppError::Forbidden(message!(
        "authentication-saml-assertion-rejected",
        "SAML assertion rejected"
    ))
}

/// A refusal for an assertion whose reuse could not be checked: a ledger
/// that cannot answer counts as a replay.
pub(crate) fn unchecked_assertion(error: &DomainError) -> AppError {
    tracing::warn!(%error, "SAML assertion ledger could not answer");
    AppError::Forbidden(message!(
        "authentication-this-assertion-could-not-be-checked",
        "this assertion could not be checked for reuse"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature verification error becomes a forbidden response whose
    /// message omits the signature detail.
    #[test]
    fn a_rejected_assertion_names_no_check() {
        let refused = rejected_assertion(&DomainError::invalid("the signature does not verify"));

        let AppError::Forbidden(message) = refused else {
            panic!("an assertion is refused as forbidden");
        };
        assert!(!message.as_str().contains("signature"));
    }

    /// The ledger that remembers spent assertions is down. The assertion is
    /// refused, as a replay would be.
    #[test]
    fn an_assertion_whose_reuse_is_unchecked_is_refused() {
        let refused = unchecked_assertion(&DomainError::infra_msg("ledger unreachable"));

        assert!(matches!(refused, AppError::Forbidden(_)));
    }
}
