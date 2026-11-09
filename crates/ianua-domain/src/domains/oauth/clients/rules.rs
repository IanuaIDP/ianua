//! The rules every client keeps, however it was registered and whoever
//! changes it.

use crate::domains::oauth::clients::client::GrantType;
use crate::domains::oauth::clients::credential::ClientCredential;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::RedirectUri;

/// A client needs at least one grant, and one using the authorization code
/// flow needs somewhere to send the code.
pub(crate) fn ensure_usable(
    grant_types: &[GrantType],
    redirect_uris: &[RedirectUri],
) -> Result<(), DomainError> {
    validate_count("grant_types", grant_types.len(), 1..=usize::MAX)?;
    ensure_redirects_for(grant_types, redirect_uris)
}

/// Whether `grant_types` let a client act as itself rather than for a
/// person: client credentials and token exchange.
pub(crate) fn acts_as_itself(grant_types: &[GrantType]) -> bool {
    grant_types.iter().any(|grant| {
        matches!(
            grant,
            GrantType::ClientCredentials | GrantType::TokenExchange
        )
    })
}

/// Refuses client credentials and token exchange for a public client.
///
/// Both hand out tokens on the client's own proof. A public client has
/// none, so anyone who copied its id from an app would get those tokens.
pub(crate) fn ensure_grants_fit(
    credential: &ClientCredential,
    grant_types: &[GrantType],
) -> Result<(), DomainError> {
    if credential.is_public() && acts_as_itself(grant_types) {
        return Err(DomainError::invalid(message!(
            "oauth-a-public-client-proves-nothing-so",
            "a public client proves nothing, so it cannot use client credentials or token exchange"
        )));
    }
    Ok(())
}

/// Refuses a new client's credential that already holds an old secret:
/// only a rotation leaves one, so a registration cannot slip in a second
/// secret that works beside the one shown.
pub(crate) fn ensure_fresh_credential(credential: &ClientCredential) -> Result<(), DomainError> {
    if credential.has_previous_secret() {
        return Err(DomainError::invalid(message!(
            "oauth-a-new-client-holds-one-secret",
            "a new client holds one secret; an old one is kept only by a rotation"
        )));
    }
    Ok(())
}

/// Refuses a list naming the same `what` twice.
pub(crate) fn ensure_named_once<T: Eq + std::hash::Hash + std::fmt::Display>(
    what: &str,
    listed: &[T],
) -> Result<(), DomainError> {
    let Some(twice) = first_repeat(listed.iter()) else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "oauth-the-is-listed-twice",
        format!("the {what} {twice} is listed twice")
    )))
}

/// Refuses the authorization code flow with no redirect URI to send the
/// code to.
pub(crate) fn ensure_redirects_for(
    grant_types: &[GrantType],
    redirect_uris: &[RedirectUri],
) -> Result<(), DomainError> {
    if grant_types.contains(&GrantType::AuthorizationCode) && redirect_uris.is_empty() {
        return Err(DomainError::invalid(message!(
            "oauth-a-client-using-the-authorization-code",
            "a client using the authorization code flow needs at least one redirect URI"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::credential::{ClientSecret, PreviousSecret, SecretSentBy};
    use crate::types::TokenHash;

    /// Token exchange fails grant validation for a public client, which has
    /// no credential with which to prove itself.
    #[test]
    fn a_public_client_cannot_exchange_tokens() {
        let result = ensure_grants_fit(&ClientCredential::Public, &[GrantType::TokenExchange]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A registration credential containing an accepted previous secret is
    /// refused. A credential holding only its current secret is valid.
    #[test]
    fn a_new_client_holds_no_old_secret() {
        let hash = |value: &str| TokenHash::from_stored(value.to_owned());
        let two = ClientCredential::Secret(ClientSecret::from_stored(
            hash("shown"),
            PreviousSecret::AcceptedUntil {
                hash: hash("hidden"),
                until: crate::shared::clock::now() + time::Duration::days(30),
            },
            SecretSentBy::Basic,
        ));

        assert!(ensure_fresh_credential(&two).is_err());
        assert!(ensure_fresh_credential(&ClientCredential::secret(hash("shown"))).is_ok());
    }
}
