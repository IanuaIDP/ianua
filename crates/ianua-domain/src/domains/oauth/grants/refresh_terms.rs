//! What a client brings to start or use a refresh token, and why a use is
//! refused.

use crate::domains::oauth::clients::lifetimes::RefreshLifetimes;
use crate::domains::oauth::grants::token_binding::PresentedProof;
use crate::shared::errors::DomainError;
use crate::types::{Lifetime, Scope, TokenHash};

/// What the first token of a family is issued with.
#[derive(Debug, Clone)]
pub struct RefreshIssue {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// How long it and its family last.
    pub lifetimes: RefreshLifetimes,
    /// What the request proved about its holder. A public client's token is
    /// bound to the `DPoP` key it proved.
    pub proof: PresentedProof,
}

/// The scopes a refresh asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshScopes {
    /// The same as the grant.
    AsGranted,
    /// Fewer than the grant: the new tokens carry only these.
    Narrowed(Vec<Scope>),
}

/// What a client asks when it uses a refresh token.
#[derive(Debug, Clone)]
pub struct RefreshRequest {
    /// The scopes the new tokens carry.
    pub scopes: RefreshScopes,
    /// How long the next refresh token lasts unless used.
    pub idle: Lifetime,
    /// What the request proved about its holder.
    pub proof: PresentedProof,
}

/// Why a refresh token was not swapped for new tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefreshRefusal {
    /// It was issued to another client.
    #[error("this refresh token was issued to another client")]
    OtherClient,
    /// The client is revoked or may no longer refresh.
    #[error("this client may not refresh tokens")]
    ClientRefused,
    /// It is bound to a key the request did not prove.
    #[error("this refresh token is bound to a key the request did not prove")]
    UnprovedKey,
    /// It was used already: someone else holds a copy, and its family must
    /// be revoked.
    #[error("this refresh token was used already")]
    Reused,
    /// It was revoked.
    #[error("this refresh token was revoked")]
    Revoked,
    /// It ran out.
    #[error("this refresh token has expired")]
    Expired,
    /// It asked for a scope the grant does not cover.
    #[error("a refresh cannot ask for more than the grant gave")]
    ScopeWidened,
}

impl From<RefreshRefusal> for DomainError {
    fn from(refusal: RefreshRefusal) -> Self {
        match refusal {
            RefreshRefusal::ScopeWidened => Self::invalid(refusal.to_string()),
            RefreshRefusal::OtherClient | RefreshRefusal::ClientRefused => {
                Self::forbidden(refusal.to_string())
            }
            RefreshRefusal::UnprovedKey => Self::unauthorized(refusal.to_string()),
            RefreshRefusal::Reused | RefreshRefusal::Revoked | RefreshRefusal::Expired => {
                Self::invalid_transition(refusal.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refresh refused for a missing key proof is an authentication
    /// failure, and one asking for more scopes is a bad request.
    #[test]
    fn refusals_convert_to_the_matching_domain_errors() {
        assert!(matches!(
            DomainError::from(RefreshRefusal::UnprovedKey),
            DomainError::Unauthorized(_)
        ));
        assert!(matches!(
            DomainError::from(RefreshRefusal::ScopeWidened),
            DomainError::Validation(_)
        ));
    }
}
