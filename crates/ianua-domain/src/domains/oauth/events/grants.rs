//! Events about what OAuth hands out: authorization codes, device authorizations and tokens.

use time::OffsetDateTime;

use crate::domains::oauth::grants::logout_delivery::LogoutDelivery;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, OAuthClientId};

/// An authorization code was issued after user consent.
///
/// The user who approved is the record's actor, so the payload leaves them
/// out.
#[derive(Debug)]
pub struct AuthorizationCodeIssued {
    /// The client that requested authorization.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at issue time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the code was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuthorizationCodeIssued => crate::types::event_type::OAuthEvent::AuthorizationCodeIssued,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// An authorization code was swapped for tokens.
///
/// The user whose code was swapped is the record's actor, so the payload
/// leaves them out.
#[derive(Debug)]
pub struct AuthorizationCodeExchanged {
    /// The client that swapped the code.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at exchange time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the exchange occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuthorizationCodeExchanged => crate::types::event_type::OAuthEvent::AuthorizationCodeExchanged,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// An access token was issued to a client to act for a user.
///
/// The token itself never enters the record. Only the client it went to and
/// how many scopes it carries do. The user the token acts for is the
/// record's actor, so the payload leaves them out.
#[derive(Debug)]
pub struct AccessTokenIssued {
    /// The client the token was issued to.
    pub(crate) client_id: OAuthClientId,
    /// How many scopes the token carries.
    pub(crate) scope_count: usize,
    /// When the token was issued.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessTokenIssued => crate::types::event_type::OAuthEvent::AccessTokenIssued,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("client_id", self.client_id.to_string())
            .field("scope_count", self.scope_count.to_string())
    }
}

/// A device authorization was requested.
#[derive(Debug)]
pub struct DeviceAuthorizationRequested {
    /// The client that requested device authorization.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at request time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the request was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceAuthorizationRequested => crate::types::event_type::OAuthEvent::DeviceAuthorizationRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "client",
                Reference::new(
                    RefKind::CLIENT,
                    self.client_id.to_string(),
                    self.client_label.as_str(),
                ),
            )
    }
}

/// A device authorization was approved by the user.
///
/// The user who approved is the record's actor, so the payload leaves them
/// out.
#[derive(Debug)]
pub struct DeviceAuthorizationApproved {
    /// The client whose request was approved.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at approval time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the approval happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceAuthorizationApproved => crate::types::event_type::OAuthEvent::DeviceAuthorizationApproved,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A device authorization was denied by the user.
#[derive(Debug)]
pub struct DeviceAuthorizationDenied {
    /// The client whose request was denied.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at denial time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the denial occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceAuthorizationDenied => crate::types::event_type::OAuthEvent::DeviceAuthorizationDenied,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A device collected the approval of its request: the poll that hands the
/// approving person's grant to the client, once.
///
/// From here the client acts for that person. So it is recorded, with the
/// person as actor, as an exchanged authorization code is, and the payload
/// leaves them out.
#[derive(Debug)]
pub struct DeviceAuthorizationCollected {
    /// The client that collected the approval.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label at collection time, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the approval was collected.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceAuthorizationCollected => crate::types::event_type::OAuthEvent::DeviceAuthorizationCollected,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A refresh token that was already rotated was presented again.
///
/// Only one copy of a refresh token should exist, so a second use means
/// someone else holds it. Every token of its family was revoked, and this
/// records why. The person the family belongs to is the record's actor.
#[derive(Debug)]
pub struct RefreshTokenReused {
    /// The client the family was issued to.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When the reuse was caught.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RefreshTokenReused => crate::types::event_type::OAuthEvent::RefreshTokenReused,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A client revoked one of its own tokens, as a person signing out of it
/// does.
#[derive(Debug)]
pub struct TokenRevoked {
    /// The client that revoked it.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When it was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TokenRevoked => crate::types::event_type::OAuthEvent::TokenRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A client exchanged a token it was handed for a new one, for another
/// client's audience (RFC 8693).
///
/// The person or client the token acts for is the record's actor, so the
/// payload names only the client that asked and the audience.
#[derive(Debug)]
pub struct TokenExchanged {
    /// The client that asked.
    pub(crate) client_id: OAuthClientId,
    /// That client's display label, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// The client the new token is for.
    pub(crate) audience_id: OAuthClientId,
    /// That client's display label, for the audit trail.
    pub(crate) audience_label: EventLabel,
    /// When the exchange happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TokenExchanged => crate::types::event_type::OAuthEvent::TokenExchanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "client",
                Reference::new(
                    RefKind::CLIENT,
                    self.client_id.to_string(),
                    self.client_label.as_str(),
                ),
            )
            .reference(
                "audience",
                Reference::new(
                    RefKind::CLIENT,
                    self.audience_id.to_string(),
                    self.audience_label.as_str(),
                ),
            )
    }
}

/// A client pushed an authorization request (RFC 9126), to send a browser
/// on with only its `request_uri`.
///
/// The client is the record's actor. The parameters stay out of the
/// record: the `state` and nonce are the client's own, and the scopes are
/// recorded when a code is issued for them.
#[derive(Debug)]
pub struct AuthorizationRequestPushed {
    /// The client that pushed it.
    pub(crate) client_id: OAuthClientId,
    /// The client's display label, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// When it was pushed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuthorizationRequestPushed => crate::types::event_type::OAuthEvent::AuthorizationRequestPushed,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "client",
            Reference::new(
                RefKind::CLIENT,
                self.client_id.to_string(),
                self.client_label.as_str(),
            ),
        )
    }
}

/// A logout token was posted to an app's server after a person signed out,
/// and the server took it or could not be reached.
///
/// The token itself never enters the record, only the app and how its
/// server answered, so an administrator sees which apps may still hold a
/// session.
#[derive(Debug)]
pub struct BackChannelLogoutSent {
    /// The app told.
    pub(crate) client_id: OAuthClientId,
    /// The app's display label, for the audit trail.
    pub(crate) client_label: EventLabel,
    /// How its server took the token.
    pub(crate) delivery: LogoutDelivery,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    BackChannelLogoutSent => crate::types::event_type::OAuthEvent::BackChannelLogoutSent,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "client",
                Reference::new(
                    RefKind::CLIENT,
                    self.client_id.to_string(),
                    self.client_label.as_str(),
                ),
            )
            .field("delivery", self.delivery.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::events::consent::OAuthConsentRevoked;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn client_reference(payload: &EventData) -> (String, String) {
        match payload.value("client") {
            Some(FieldValue::Reference(reference)) => {
                assert_eq!(reference.kind(), RefKind::CLIENT);
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("client is not an entity reference: {other:?}"),
        }
    }

    /// A client gets an access token with two scopes. The payload holds the
    /// client id and the count "2", and nothing else, so no token value is
    /// recorded.
    #[test]
    fn access_token_issued_payload_names_the_client_and_scope_count_only() {
        let client_id = OAuthClientId::new();
        let expected_id = client_id.to_string();
        let event = AccessTokenIssued {
            client_id,
            scope_count: 2,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("client_id"), Some(expected_id.as_str()));
        assert_eq!(payload.get("scope_count"), Some("2"));
        assert_eq!(payload.len(), 2);
    }

    /// Issuing and exchanging a code both retain the requesting client's name.
    fn code_events(client: OAuthClientId, now: OffsetDateTime) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(AuthorizationCodeIssued {
                client_id: client,
                client_label: EventLabel::of("Northwind CLI"),
                occurred_at: now,
            }),
            Box::new(AuthorizationCodeExchanged {
                client_id: client,
                client_label: EventLabel::of("Northwind CLI"),
                occurred_at: now,
            }),
        ]
    }

    /// Each outcome of the device flow retains the requesting client's name.
    fn device_events(client: OAuthClientId, now: OffsetDateTime) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(DeviceAuthorizationApproved {
                client_id: client,
                client_label: EventLabel::of("Northwind CLI"),
                occurred_at: now,
            }),
            Box::new(DeviceAuthorizationDenied {
                client_id: client,
                client_label: EventLabel::of("Northwind CLI"),
                occurred_at: now,
            }),
            Box::new(DeviceAuthorizationCollected {
                client_id: client,
                client_label: EventLabel::of("Northwind CLI"),
                occurred_at: now,
            }),
        ]
    }

    /// "Northwind CLI" goes through the code flow and the device flow, and
    /// consent is withdrawn. Each event names the client that would hold
    /// the token. The user is the actor.
    #[test]
    fn every_authorization_flow_event_names_the_client() {
        let client = OAuthClientId::new();
        let now = crate::shared::clock::now();
        let mut events = code_events(client, now);
        events.extend(device_events(client, now));
        events.push(Box::new(OAuthConsentRevoked {
            client_id: client,
            client_label: EventLabel::of("Northwind CLI"),
            occurred_at: now,
        }));
        events.push(Box::new(TokenExchanged {
            client_id: client,
            client_label: EventLabel::of("Northwind CLI"),
            audience_id: OAuthClientId::new(),
            audience_label: EventLabel::of("Billing API"),
            occurred_at: now,
        }));

        for event in events {
            let kind = event.event_type();
            assert_eq!(
                client_reference(&event.payload()),
                (client.to_string(), "Northwind CLI".to_owned()),
                "{kind}"
            );
        }
    }

    /// A device-authorization request event includes a client reference and
    /// omits the user code used to approve the device.
    #[test]
    fn device_authorization_requested_payload_carries_no_user_code() {
        let event = DeviceAuthorizationRequested {
            client_id: OAuthClientId::new(),
            client_label: EventLabel::of("Living-room TV"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert!(payload.get("user_code").is_none());
        assert!(matches!(
            payload.value("client"),
            Some(FieldValue::Reference(_))
        ));
    }
}
