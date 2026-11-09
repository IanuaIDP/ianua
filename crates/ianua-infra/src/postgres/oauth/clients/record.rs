//! An OAuth client as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient, OAuthClientRow};
use ianua_domain::domains::oauth::clients::credential::ClientCredential;
use ianua_domain::domains::oauth::clients::registration::ClientManagement;
use ianua_domain::domains::oauth::clients::settings::ClientSettings;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ClientId, InitialAccessTokenId, Label, OAuthClientId, RedirectUri, TokenHash,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::oauth::clients::credential::StoredCredential;
use crate::postgres::oauth::clients::settings::StoredSettings;
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};

/// What a client row is, so a refusal names it.
pub(super) const CLIENT: Stored = Stored("OAuth client");

const CREDENTIAL: Kept = Kept {
    entity: CLIENT.0,
    column: "credential",
    shape: 1,
};

const SETTINGS: Kept = Kept {
    entity: CLIENT.0,
    column: "settings",
    shape: 1,
};

/// A client as it is read. The store's checked queries fill it.
pub(super) struct OAuthClientRecord {
    pub(super) id: Uuid,
    pub(super) client_id_value: String,
    pub(super) credential: Value,
    pub(super) name: String,
    pub(super) redirect_uris: Vec<String>,
    pub(super) post_logout_redirect_uris: Vec<String>,
    pub(super) grant_types: Vec<String>,
    pub(super) scopes: Vec<String>,
    pub(super) settings: Value,
    pub(super) registration_token_hash: Option<String>,
    pub(super) admitted_with_id: Option<Uuid>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
}

impl OAuthClientRecord {
    /// The client the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the client
    /// keeps.
    pub(super) fn into_client(self) -> Result<OAuthClient<ResolvedTenant>, DomainError> {
        let credential =
            ClientCredential::from(CREDENTIAL.open::<StoredCredential>(self.credential)?);
        let settings = ClientSettings::try_from(SETTINGS.open::<StoredSettings>(self.settings)?)?;
        OAuthClient::reconstitute(OAuthClientRow {
            id: OAuthClientId::from_uuid(self.id),
            client_id_value: CLIENT.value("client id", ClientId::new(self.client_id_value))?,
            credential,
            name: CLIENT.value("name", Label::new("name", self.name))?,
            redirect_uris: redirects_from(self.redirect_uris)?,
            post_logout_redirect_uris: redirects_from(self.post_logout_redirect_uris)?,
            grant_types: grants_from(&self.grant_types)?,
            scopes: scopes_from(CLIENT, self.scopes)?,
            settings,
            management: management_from(self.registration_token_hash, self.admitted_with_id)?,
            status: CLIENT.choice(&self.status)?,
            created_at: self.created_at,
        })
    }
}

/// The redirect addresses a stored column holds.
fn redirects_from(stored: Vec<String>) -> Result<Vec<RedirectUri>, DomainError> {
    stored
        .into_iter()
        .map(|uri| CLIENT.value("redirect URI", RedirectUri::new(uri)))
        .collect()
}

/// The grants a stored column holds.
fn grants_from(stored: &[String]) -> Result<Vec<GrantType>, DomainError> {
    stored.iter().map(|word| CLIENT.choice(word)).collect()
}

/// Who manages the client, from its registration columns: both empty for
/// one the admins manage, both set for one that registered itself.
fn management_from(
    registration_token_hash: Option<String>,
    admitted_with_id: Option<Uuid>,
) -> Result<ClientManagement, DomainError> {
    match (registration_token_hash, admitted_with_id) {
        (None, None) => Ok(ClientManagement::ByAdmins),
        (Some(hash), Some(admitted_with)) => Ok(ClientManagement::ByItself {
            registration_token: TokenHash::from_stored(hash),
            admitted_with: InitialAccessTokenId::from_uuid(admitted_with),
        }),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            CLIENT.0,
            "half of a self-registration",
        )),
    }
}

/// A client's columns, as they are written.
pub(super) struct OAuthClientColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) client_id_value: &'a str,
    pub(super) credential: Value,
    pub(super) name: &'a str,
    pub(super) redirect_uris: Vec<String>,
    pub(super) post_logout_redirect_uris: Vec<String>,
    pub(super) grant_types: Vec<String>,
    pub(super) scopes: Vec<String>,
    pub(super) settings: Value,
    pub(super) registration_token_hash: Option<&'a str>,
    pub(super) admitted_with_id: Option<Uuid>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> OAuthClientColumns<'a> {
    /// The columns `client` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON.
    pub(super) fn of(client: &'a OAuthClient<ResolvedTenant>) -> Result<Self, DomainError> {
        let (registration_token_hash, admitted_with_id) = match client.management() {
            ClientManagement::ByAdmins => (None, None),
            ClientManagement::ByItself {
                registration_token,
                admitted_with,
            } => (
                Some(registration_token.as_str()),
                Some(*admitted_with.as_uuid()),
            ),
        };
        Ok(Self {
            id: client.id().as_uuid(),
            client_id_value: client.client_id_value().as_str(),
            credential: CREDENTIAL.seal(&StoredCredential::from(client.credential()))?,
            name: client.name().as_str(),
            redirect_uris: uris_column(client.redirect_uris()),
            post_logout_redirect_uris: uris_column(client.post_logout_redirect_uris()),
            grant_types: client
                .grant_types()
                .iter()
                .map(|grant| grant.word().to_owned())
                .collect(),
            scopes: scopes_column(client.scopes()),
            settings: SETTINGS.seal(&StoredSettings::from(client.settings()))?,
            registration_token_hash,
            admitted_with_id,
            status: client.status().word(),
            created_at: client.created_at(),
        })
    }
}

fn uris_column(uris: &[RedirectUri]) -> Vec<String> {
    uris.iter().map(|uri| uri.as_str().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::oauth::clients::credential::{
        ClientJwks, ClientKeys, ClientSecret, PreviousSecret, SecretSentBy,
    };
    use ianua_domain::domains::oauth::clients::lifetimes::{
        ClientTokenLifetimes, RefreshLifetimes, TokenTerms,
    };
    use ianua_domain::domains::oauth::clients::settings::{
        AccessTokenFormat, ChannelLogout, ClientLinks, ClientLogout, ClientUri, ConsentPrompt,
        SessionRequired,
    };
    use ianua_domain::domains::oauth::grants::token_binding::SenderConstraint;
    use ianua_domain::types::{HttpsUrl, Lifetime};
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::pinned;

    /// A rotated secret is written as its two hashes and when the old one
    /// stops, in the shape pinned here, and reads back the same.
    #[test]
    fn a_secret_is_stored_in_its_pinned_shape() {
        let credential = ClientCredential::Secret(ClientSecret::from_stored(
            TokenHash::from_stored("hash:new".to_owned()),
            PreviousSecret::AcceptedUntil {
                hash: TokenHash::from_stored("hash:old".to_owned()),
                until: pinned(0),
            },
            SecretSentBy::Post,
        ));
        let stored = json!({"v": 1, "value": {
            "method": "secret",
            "current": "hash:new",
            "previous": {"hash": "hash:old", "until": "2027-01-15T08:00:00Z"},
            "sent_by": "post"
        }});

        assert_eq!(
            CREDENTIAL
                .seal(&StoredCredential::from(&credential))
                .unwrap(),
            stored
        );
        let read = ClientCredential::from(CREDENTIAL.open::<StoredCredential>(stored).unwrap());
        assert_eq!(read, credential);
    }

    /// The other ways a client proves itself are written in the shapes
    /// pinned here.
    #[test]
    fn keys_and_public_clients_are_stored_in_their_pinned_shapes() {
        let listed = ClientCredential::PrivateKeyJwt(ClientKeys::Listed(
            ClientJwks::new("{\"keys\":[]}").unwrap(),
        ));
        let published = ClientCredential::PrivateKeyJwt(ClientKeys::Published(
            HttpsUrl::new("https://app.example.com/jwks").unwrap(),
        ));

        assert_eq!(
            CREDENTIAL.seal(&StoredCredential::from(&listed)).unwrap(),
            json!({"v": 1, "value": {"method": "private_key_jwt", "keys": {"listed": "{\"keys\":[]}"}}})
        );
        assert_eq!(
            CREDENTIAL
                .seal(&StoredCredential::from(&published))
                .unwrap(),
            json!({"v": 1, "value": {"method": "private_key_jwt",
                "keys": {"published": "https://app.example.com/jwks"}}})
        );
        assert_eq!(
            CREDENTIAL
                .seal(&StoredCredential::from(&ClientCredential::Public))
                .unwrap(),
            json!({"v": 1, "value": {"method": "public"}})
        );
    }

    /// Uses custom lifetimes, branding, logout and sender constraints to cover every settings field.
    fn custom_settings() -> ClientSettings {
        let seconds = |n| Lifetime::seconds(n).unwrap();
        ClientSettings {
            lifetimes: ClientTokenLifetimes::Own(
                TokenTerms::new(
                    seconds(300),
                    seconds(600),
                    RefreshLifetimes::new(seconds(3600), seconds(86_400)).unwrap(),
                )
                .unwrap(),
            ),
            links: ClientLinks {
                logo: ClientUri::At(HttpsUrl::new("https://app.example.com/logo.png").unwrap()),
                ..ClientLinks::none()
            },
            consent: ConsentPrompt::FirstParty,
            token_format: AccessTokenFormat::Jwt,
            logout: ClientLogout {
                back_channel: ChannelLogout::At {
                    uri: HttpsUrl::new("https://app.example.com/logout").unwrap(),
                    session: SessionRequired::Required,
                },
                front_channel: ChannelLogout::NotRegistered,
            },
            sender_constraint: SenderConstraint::DpopRequired,
        }
    }

    /// A client's own settings are written in the shape pinned here, and
    /// read back the same.
    #[test]
    fn the_settings_are_stored_in_their_pinned_shape() {
        let settings = custom_settings();
        let stored = json!({"v": 1, "value": {
            "lifetimes": {
                "access_secs": 300,
                "id_token_secs": 600,
                "refresh_idle_secs": 3600,
                "refresh_family_secs": 86400
            },
            "logo_uri": "https://app.example.com/logo.png",
            "policy_uri": null,
            "tos_uri": null,
            "consent": "first_party",
            "token_format": "jwt",
            "back_channel_logout": {"uri": "https://app.example.com/logout", "session": "required"},
            "front_channel_logout": null,
            "sender_constraint": "dpop_required"
        }});

        assert_eq!(
            SETTINGS.seal(&StoredSettings::from(&settings)).unwrap(),
            stored
        );
        let read = ClientSettings::try_from(SETTINGS.open::<StoredSettings>(stored).unwrap());
        assert_eq!(read.unwrap(), settings);
    }

    /// Stored client settings with a week-long access-token lifetime fail
    /// reconstitution as an infrastructure error.
    #[test]
    fn settings_with_terms_out_of_bounds_are_refused() {
        let stored = json!({"v": 1, "value": {
            "lifetimes": {
                "access_secs": 604_800,
                "id_token_secs": 600,
                "refresh_idle_secs": 3600,
                "refresh_family_secs": 86400
            },
            "logo_uri": null,
            "policy_uri": null,
            "tos_uri": null,
            "consent": "ask_person",
            "token_format": "opaque",
            "back_channel_logout": null,
            "front_channel_logout": null,
            "sender_constraint": "bearer_allowed"
        }});

        let read = ClientSettings::try_from(SETTINGS.open::<StoredSettings>(stored).unwrap());

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
