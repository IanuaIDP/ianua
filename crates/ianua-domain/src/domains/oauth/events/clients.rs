//! Events about the OAuth clients and API keys a tenant registers.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{ApiKeyId, CountryCode, InitialAccessTokenId, Label, OAuthClientId};

/// An OAuth client was created for a third-party integration or a machine.
///
/// The client can now use the grants it was given in its tenant.
#[derive(Debug)]
pub(crate) struct OAuthClientCreated {
    /// The new client.
    pub(crate) client_id: OAuthClientId,
    /// The client's name at the time of the event.
    pub(crate) name: Label,
    /// When the client was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthClientCreated => crate::types::event_type::OAuthEvent::ClientCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// An OAuth client was revoked for good.
///
/// Tokens the client already holds should be refused. The revoke cannot be
/// undone.
#[derive(Debug)]
pub(crate) struct OAuthClientRevoked {
    /// The client that was revoked.
    pub(crate) client_id: OAuthClientId,
    /// The client's name when it was revoked, for the audit trail.
    pub(crate) name: Label,
    /// When the revoke happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthClientRevoked => crate::types::event_type::OAuthEvent::ClientRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// An API key was created for a machine to sign in with.
///
/// The raw key was shown once to the admin who created it. Only its hash is
/// stored.
#[derive(Debug)]
pub struct ApiKeyCreated {
    /// The new key.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it was created.
    pub(crate) name: Label,
    /// When the key was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyCreated => crate::types::event_type::OAuthEvent::ApiKeyCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An API key was revoked for good.
///
/// From here on the key signs in no request. The revoke cannot be undone.
#[derive(Debug)]
pub struct ApiKeyRevoked {
    /// The key that was revoked.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it was revoked, for the audit trail.
    pub(crate) name: Label,
    /// When the revoke happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyRevoked => crate::types::event_type::OAuthEvent::ApiKeyRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An API key was paused: it signs in no request until it is resumed.
#[derive(Debug)]
pub struct ApiKeyPaused {
    /// The key that was paused.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it was paused, for the audit trail.
    pub(crate) name: Label,
    /// When it was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyPaused => crate::types::event_type::OAuthEvent::ApiKeyPaused,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// A paused API key was resumed and signs in again.
#[derive(Debug)]
pub struct ApiKeyResumed {
    /// The key that was resumed.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it was resumed, for the audit trail.
    pub(crate) name: Label,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyResumed => crate::types::event_type::OAuthEvent::ApiKeyResumed,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An OAuth client's settings changed.
///
/// Covers its name, redirect URIs and allowed scopes.
#[derive(Debug)]
pub struct OAuthClientUpdated {
    /// The client that was changed.
    pub(crate) client_id: OAuthClientId,
    /// The client's name at the time of the change.
    pub(crate) name: Label,
    /// When the change happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthClientUpdated => crate::types::event_type::OAuthEvent::ClientUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// An API key passed its `expires_at` time and stopped working.
#[derive(Debug)]
pub struct ApiKeyExpired {
    /// The expired key.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it expired, for the audit trail.
    pub(crate) name: Label,
    /// When the expiry was recorded.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyExpired => crate::types::event_type::OAuthEvent::ApiKeyExpired,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An API key's name or scopes changed.
#[derive(Debug)]
pub struct ApiKeyUpdated {
    /// The key that was changed.
    pub(crate) key_id: ApiKeyId,
    /// The key's name at the time of the change.
    pub(crate) name: Label,
    /// When the change happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyUpdated => crate::types::event_type::OAuthEvent::ApiKeyUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An OAuth client's secret was replaced.
///
/// The old secret may keep working for an overlap, so the app's servers
/// can move over; an admin rotating after a leak gives none.
#[derive(Debug)]
pub(crate) struct OAuthClientSecretRotated {
    /// The client whose secret was replaced.
    pub(crate) client_id: OAuthClientId,
    /// The client's name at the time of the rotation.
    pub(crate) name: Label,
    /// When the rotation happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthClientSecretRotated => crate::types::event_type::OAuthEvent::ClientSecretRotated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// An app registered itself as an OAuth client (RFC 7591), with an initial
/// access token the tenant handed out.
#[derive(Debug)]
pub(crate) struct OAuthClientRegistered {
    /// The new client.
    pub(crate) client_id: OAuthClientId,
    /// The name it registered with.
    pub(crate) name: Label,
    /// When it registered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OAuthClientRegistered => crate::types::event_type::OAuthEvent::ClientRegistered,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// An initial access token was issued, so apps may register themselves as
/// clients with it.
///
/// The raw token was shown once to the admin who issued it. Only its hash
/// is stored.
#[derive(Debug)]
pub struct InitialAccessTokenIssued {
    /// The new token.
    pub(crate) token_id: InitialAccessTokenId,
    /// The purpose label captured when the registration credential was issued.
    pub(crate) name: Label,
    /// When it was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InitialAccessTokenIssued => crate::types::event_type::OAuthEvent::InitialAccessTokenIssued,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.token_id.to_string(), self.name.as_str()),
        )
    }
}

/// An initial access token was revoked, so no app registers with it again.
#[derive(Debug)]
pub struct InitialAccessTokenRevoked {
    /// The revoked token.
    pub(crate) token_id: InitialAccessTokenId,
    /// The purpose label captured when further registrations were disabled.
    pub(crate) name: Label,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    InitialAccessTokenRevoked => crate::types::event_type::OAuthEvent::InitialAccessTokenRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.token_id.to_string(), self.name.as_str()),
        )
    }
}

/// An API key signed in from a country it never signed in from before.
///
/// Ann's deploy key always runs from one country. A sign-in from another
/// may be a leak: a workflow can pause the key until someone looks.
#[derive(Debug)]
pub struct ApiKeyUsedFromNewCountry {
    /// The key that signed in.
    pub(crate) key_id: ApiKeyId,
    /// The key's name when it signed in, for the audit trail.
    pub(crate) name: Label,
    /// The country it signed in from.
    pub(crate) country: CountryCode,
    /// When it signed in.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ApiKeyUsedFromNewCountry => crate::types::event_type::OAuthEvent::ApiKeyUsedFromNewCountry,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "key",
                Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
            )
            .field("country", self.country.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::test_support::builders::label;

    fn client_reference(payload: &EventData) -> (String, String) {
        match payload.value("client") {
            Some(FieldValue::Reference(reference)) => {
                assert_eq!(reference.kind(), RefKind::CLIENT);
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("client is not an entity reference: {other:?}"),
        }
    }

    /// "Northwind CLI" is created. The event refers to it as a client, by
    /// its id and name.
    #[test]
    fn client_created_payload_references_the_client_by_name() {
        let client_id = OAuthClientId::new();
        let event = OAuthClientCreated {
            client_id,
            name: label("Northwind CLI"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(client)) = payload.value("client") else {
            panic!("expected a client reference");
        };
        assert_eq!(client.kind(), RefKind::CLIENT);
        assert_eq!(client.id(), client_id.to_string());
        assert_eq!(client.label(), "Northwind CLI");
    }

    /// Ann creates "CI deploy key". The payload holds only the key, not Ann.
    /// The audit record's actor already names her, and a bare id there could
    /// not say whether she is a tenant user or an org user.
    #[test]
    fn api_key_created_payload_omits_the_creating_actor() {
        let event = ApiKeyCreated {
            key_id: ApiKeyId::new(),
            name: label("CI deploy key"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("created_by"), None);
        assert_eq!(payload.len(), 1);
    }

    /// An admin revokes "CI deploy key". The event refers to the key by id
    /// and leaves the admin out of the payload.
    #[test]
    fn api_key_revoked_payload_references_the_key_by_name() {
        let key_id = ApiKeyId::new();
        let event = ApiKeyRevoked {
            key_id,
            name: label("CI deploy key"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(key)) = payload.value("key") else {
            panic!("expected a key reference");
        };
        assert_eq!(key.kind(), RefKind::KEY);
        assert_eq!(key.id(), key_id.to_string());
        assert_eq!(payload.get("revoked_by"), None);
    }

    /// Registration and lifecycle records for the same named client.
    fn client_events(client: OAuthClientId) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(OAuthClientCreated {
                client_id: client,
                name: label("Northwind CLI"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(OAuthClientUpdated {
                client_id: client,
                name: label("Northwind CLI"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(OAuthClientRevoked {
                client_id: client,
                name: label("Northwind CLI"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(OAuthClientSecretRotated {
                client_id: client,
                name: label("Northwind CLI"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(OAuthClientRegistered {
                client_id: client,
                name: label("Northwind CLI"),
                occurred_at: crate::shared::clock::now(),
            }),
        ]
    }

    /// "Northwind CLI" is created, changed and revoked. Each event refers to
    /// the client by id and name.
    #[test]
    fn every_client_event_names_the_client() {
        let client = OAuthClientId::new();
        for event in client_events(client) {
            let kind = event.event_type();
            assert_eq!(
                client_reference(&event.payload()),
                (client.to_string(), "Northwind CLI".to_owned()),
                "{kind}"
            );
        }
    }

    /// Lifecycle records for one deployment credential, without its secret.
    fn key_events(key: ApiKeyId) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(ApiKeyCreated {
                key_id: key,
                name: label("CI deploy key"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(ApiKeyUpdated {
                key_id: key,
                name: label("CI deploy key"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(ApiKeyRevoked {
                key_id: key,
                name: label("CI deploy key"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(ApiKeyExpired {
                key_id: key,
                name: label("CI deploy key"),
                occurred_at: crate::shared::clock::now(),
            }),
        ]
    }

    /// "CI deploy key" is created, changed, revoked and expires. Each event
    /// refers to the key by id and name.
    #[test]
    fn every_api_key_event_names_the_key() {
        let key = ApiKeyId::new();
        for event in key_events(key) {
            let kind = event.event_type();
            let payload = event.payload();
            let Some(FieldValue::Reference(reference)) = payload.value("key") else {
                panic!("{kind} does not name the key");
            };
            assert_eq!(reference.kind(), RefKind::KEY, "{kind}");
            assert_eq!(reference.id(), key.to_string(), "{kind}");
            assert_eq!(reference.label(), "CI deploy key", "{kind}");
        }
    }

    /// The "MCP clients" initial access token is issued and revoked. Each
    /// event refers to it as a key, by id and name, never by its value.
    #[test]
    fn every_initial_access_token_event_names_the_token() {
        let token = InitialAccessTokenId::new();

        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(InitialAccessTokenIssued {
                token_id: token,
                name: label("MCP clients"),
                occurred_at: crate::shared::clock::now(),
            }),
            Box::new(InitialAccessTokenRevoked {
                token_id: token,
                name: label("MCP clients"),
                occurred_at: crate::shared::clock::now(),
            }),
        ];

        for event in events {
            let kind = event.event_type();
            let payload = event.payload();
            let Some(FieldValue::Reference(reference)) = payload.value("key") else {
                panic!("{kind} does not name the token");
            };
            assert_eq!(reference.id(), token.to_string(), "{kind}");
            assert_eq!(reference.label(), "MCP clients", "{kind}");
            assert_eq!(payload.len(), 1, "{kind}");
        }
    }
}
