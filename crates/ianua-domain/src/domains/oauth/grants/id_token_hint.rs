//! What a verified `id_token_hint` says: an ID token this server issued
//! earlier, sent back by an app to name the person and session it means
//! (OIDC Core 3.1.2.1, RP-Initiated Logout 2).
//!
//! The hint is trusted only for what its signature covers. An adapter
//! checks the signature against the tenant's keys and the issuer, then the
//! application makes the hint from the claims. Its expiry is not checked:
//! an app signing a person out often holds an ID token that ran out long
//! ago.

use crate::domains::oauth::clients::client::OAuthClient;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ClientId, SessionId, UserId};

/// What a verified `id_token_hint` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenHint {
    audience: ClientId,
    subject: UserId,
    session: SessionId,
}

impl IdTokenHint {
    /// The hint an ID token for `audience` names, about `subject` signed in
    /// to `session`. The caller makes one only after the signature and the
    /// issuer were checked.
    #[must_use]
    pub fn verified(audience: ClientId, subject: UserId, session: SessionId) -> Self {
        Self {
            audience,
            subject,
            session,
        }
    }

    /// The client the ID token was issued to (`aud`).
    #[must_use]
    pub fn audience(&self) -> &ClientId {
        &self.audience
    }

    /// The person it is about (`sub`).
    #[must_use]
    pub fn subject(&self) -> &UserId {
        &self.subject
    }

    /// The session it was issued in (`sid`).
    #[must_use]
    pub fn session(&self) -> &SessionId {
        &self.session
    }

    /// Whether it was issued to `client`.
    #[must_use]
    pub fn names_client<T: TenantScope>(&self, client: &OAuthClient<T>) -> bool {
        self.audience == *client.client_id_value()
    }

    /// Whether it is about `person`: for `prompt=none`, the person signed
    /// in must be the one the app means, or the app is told to send them
    /// through sign-in.
    #[must_use]
    pub fn is_about(&self, person: &UserId) -> bool {
        self.subject == *person
    }

    /// Refuses a hint sent with a client it was not issued to: a sign-out
    /// request naming one app with another app's ID token is not what it
    /// seems.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the hint was issued to another
    ///   client.
    pub fn ensure_issued_to<T: TenantScope>(
        &self,
        client: &OAuthClient<T>,
    ) -> Result<(), DomainError> {
        if self.names_client(client) {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "oauth-the-id-token-hint-was-issued",
            "the id_token_hint was issued to another client"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::types::{OAuthClientId, RedirectUri};

    /// An app registered as `client_id`.
    fn app(client_id: &str) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new(client_id).unwrap(),
                credential: ClientCredential::Public,
                name: label(client_id),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: Vec::new(),
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// A hint from Ann's ID token for the web app.
    fn anns_hint(ann: UserId) -> IdTokenHint {
        IdTokenHint::verified(ClientId::new("web_app").unwrap(), ann, SessionId::new())
    }

    /// Ann's hint names the web app and Ann, and nobody else.
    #[test]
    fn a_hint_names_its_client_and_person() {
        let ann = UserId::new();
        let hint = anns_hint(ann);

        assert!(hint.names_client(&app("web_app")));
        assert!(hint.is_about(&ann));
        assert!(!hint.is_about(&UserId::new()));
    }

    /// A hint issued to the web app fails validation when checked against
    /// another client.
    #[test]
    fn a_hint_for_another_client_is_refused() {
        let hint = anns_hint(UserId::new());

        let result = hint.ensure_issued_to(&app("mallory_app"));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
