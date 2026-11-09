//! Loading the connection a single sign-on goes through, and opening its
//! OIDC client secret for the provider.

use ianua_domain::domains::federation::connection::{FederatedIdpConnection, OidcConfig};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::ConnectionId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::federation::{ConnectionStore, OidcClientConfig};
use crate::services::sealing::opened_text;
use crate::tenancy::ScopedTenant;

/// Where `tenant`'s connection `connection_id` keeps its OIDC client
/// secret.
pub(in crate::use_cases) fn client_secret_place(
    tenant: &ScopedTenant,
    connection_id: &ConnectionId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::FederationClientSecret,
        connection_id,
    )
}

/// The tenant's federation connection with `connection_id`, provided it is
/// turned on.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such connection.
/// - `AppError::Forbidden` if the connection is turned off.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::authentication) async fn existing_active_connection(
    store: &dyn ConnectionStore,
    tenant: &ScopedTenant,
    connection_id: &ConnectionId,
) -> Result<FederatedIdpConnection<ResolvedTenant>, AppError> {
    let connection = store
        .find_by_id(tenant, connection_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-connection-not-found",
            "connection not found"
        ))?;
    if !connection.is_active() {
        return Err(AppError::Forbidden(message!(
            "authentication-connection-is-disabled",
            "connection is disabled"
        )));
    }
    Ok(connection)
}

/// `config` with its client secret opened, for the provider to be
/// authenticated to.
///
/// The connection keeps the secret sealed, so every path that talks to the
/// identity provider opens it here rather than handing over the ciphertext,
/// a tenant's connection and an organization's own provider alike. The
/// opened credential has its own type; the stored config stays sealed.
///
/// The secret is opened for `place`, where the connection or provider
/// keeps it.
///
/// # Errors
///
/// Returns `AppError::Internal` when the secret cannot be opened there or
/// is not text.
pub(in crate::use_cases) async fn opened_oidc_config(
    encryptor: &dyn SecretEncryptor,
    config: &OidcConfig,
    place: &SealedFor,
) -> Result<OidcClientConfig, AppError> {
    let client_secret = opened_text(encryptor, &config.encrypted_client_secret, place)
        .await
        .or_internal()?;
    Ok(OidcClientConfig {
        issuer: config.issuer.clone(),
        client_id: config.client_id.clone(),
        client_secret,
        scopes: config.scopes.clone(),
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::scope_token::ScopeToken;
    use ianua_domain::types::{HttpsUrl, Label};

    use super::*;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::{block_on, test_ctx};

    fn config(secret: impl AsRef<[u8]>, place: &SealedFor) -> OidcConfig {
        OidcConfig {
            issuer: HttpsUrl::new("https://idp.acme.test").unwrap(),
            client_id: Label::new("client_id", "acme").unwrap(),
            encrypted_client_secret: FakeEncryptor::sealed_for(secret, place),
            scopes: vec![ScopeToken::new("openid").unwrap()],
        }
    }

    /// Ann's provider issued a secret with spaces and punctuation. Opening
    /// it preserves every character and leaves the stored settings sealed.
    #[test]
    fn an_opened_client_secret_keeps_spaces_and_punctuation() {
        let secret = " Provider secret with spaces +%:&= ";
        let place = client_secret_place(&test_ctx().tenant(), &ConnectionId::new());
        let stored = config(secret, &place);
        let before = stored.clone();

        let opened = block_on(opened_oidc_config(&FakeEncryptor, &stored, &place)).unwrap();

        assert_eq!(opened.client_secret.expose(), secret);
        assert_eq!(opened.issuer, stored.issuer);
        assert_eq!(opened.client_id, stored.client_id);
        assert_eq!(opened.scopes, stored.scopes);
        assert_eq!(stored, before);
        assert!(!format!("{:?}", opened.client_secret).contains(secret));
    }

    /// A secret sealed for one connection cannot be opened for another connection.
    #[test]
    fn a_client_secret_cannot_be_opened_for_another_connection() {
        let tenant = test_ctx().tenant();
        let own = client_secret_place(&tenant, &ConnectionId::new());
        let other = client_secret_place(&tenant, &ConnectionId::new());

        let opened = block_on(opened_oidc_config(
            &FakeEncryptor,
            &config("Provider secret", &own),
            &other,
        ));

        assert!(matches!(opened, Err(AppError::Internal(_))));
    }

    /// Non-text credential bytes produce an internal error whose debug output
    /// exposes neither the plaintext fragment nor the invalid byte value.
    #[test]
    fn a_non_text_client_secret_is_refused_without_exposing_it() {
        let place = client_secret_place(&test_ctx().tenant(), &ConnectionId::new());
        let mut bytes = b"Private provider credential".to_vec();
        bytes.push(0xff);

        let opened = block_on(opened_oidc_config(
            &FakeEncryptor,
            &config(bytes, &place),
            &place,
        ));

        let Err(AppError::Internal(error)) = opened else {
            panic!("non-text credentials are corrupt storage")
        };
        assert!(!format!("{error:?}").contains("Private provider credential"));
        assert!(!format!("{error:?}").contains("255"));
    }
}
