use time::OffsetDateTime;

use crate::domains::federation::connection::FederationProtocol;
use crate::domains::federation::link::{LinkSource, UnlinkSource};
use crate::domains::federation::saml::logout::LogoutStatus;
use crate::domains::federation::scim::{ScimActivation, ScimRemoval};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{
    ConnectionId, Email, EventLabel, HttpsUrl, Label, RoleId, SamlEntityId, SamlRequestId,
    SamlServiceProviderId, Setting, UserId,
};

/// The kind of reference a SAML app is named by in the audit trail.
const SERVICE_PROVIDER: RefKind = RefKind::new("saml_service_provider");

/// Builds the audit reference for a federated connection, labelled with the
/// provider name it carried when the event fired.
fn connection_reference(connection_id: &ConnectionId, label: impl Into<String>) -> Reference {
    Reference::new(RefKind::CONNECTION, connection_id.to_string(), label)
}

/// Builds the audit reference for a SAML app, labelled with its name when
/// the event fired.
fn service_provider_reference(id: &SamlServiceProviderId, name: &Label) -> Reference {
    Reference::new(SERVICE_PROVIDER, id.to_string(), name.to_string())
}

/// A SAML app was added: this platform now signs people in to it as the
/// identity provider.
#[derive(Debug)]
pub struct ServiceProviderCreated {
    /// The new app.
    pub(crate) provider_id: SamlServiceProviderId,
    /// The display label captured when the SAML application was added.
    pub(crate) name: Label,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceProviderCreated => crate::types::event_type::FederationEvent::ServiceProviderCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "service_provider",
            service_provider_reference(&self.provider_id, &self.name),
        )
    }
}

/// A SAML app's settings or status changed: where its assertions go, what
/// it is sent, how it is signed or sealed, or whether it is on.
#[derive(Debug)]
pub struct ServiceProviderUpdated {
    /// The app.
    pub(crate) provider_id: SamlServiceProviderId,
    /// Its name as saved.
    pub(crate) name: Label,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceProviderUpdated => crate::types::event_type::FederationEvent::ServiceProviderUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "service_provider",
            service_provider_reference(&self.provider_id, &self.name),
        )
    }
}

/// A SAML app was deleted. People can no longer sign in to it through
/// this platform.
#[derive(Debug)]
pub struct ServiceProviderDeleted {
    /// The app.
    pub(crate) provider_id: SamlServiceProviderId,
    /// Its name when it was deleted.
    pub(crate) name: Label,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ServiceProviderDeleted => crate::types::event_type::FederationEvent::ServiceProviderDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "service_provider",
            service_provider_reference(&self.provider_id, &self.name),
        )
    }
}

/// A new federated `IdP` connection was created.
///
/// The tenant can now sign users in through this external identity
/// provider, such as Okta, Azure AD or Google Workspace.
#[derive(Debug)]
pub struct ConnectionCreated {
    /// The newly created connection.
    pub(crate) connection_id: ConnectionId,
    /// Provider name, such as `"Okta"`.
    pub(crate) provider_name: Label,
    /// Whether the connection uses SAML or OIDC.
    pub(crate) protocol: FederationProtocol,
    /// When the connection was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConnectionCreated => crate::types::event_type::FederationEvent::ConnectionCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "connection",
                connection_reference(&self.connection_id, self.provider_name.to_string()),
            )
            .field("protocol", self.protocol.as_str())
    }
}

/// A federated `IdP` connection was disabled.
///
/// Users cannot sign in through this provider until the connection is
/// turned back on.
#[derive(Debug)]
pub struct ConnectionDisabled {
    /// The connection that was disabled.
    pub(crate) connection_id: ConnectionId,
    /// The provider name when it was disabled, for the audit record.
    pub(crate) provider_name: Label,
    /// When the connection was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConnectionDisabled => crate::types::event_type::FederationEvent::ConnectionDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "connection",
            connection_reference(&self.connection_id, self.provider_name.to_string()),
        )
    }
}

/// A user was created by just-in-time provisioning during a federated
/// sign-in.
///
/// The user did not exist in the tenant before this sign-in. They were
/// created from the external `IdP`'s assertion or claims and given the
/// connection's default role.
#[derive(Debug)]
pub struct JitUserProvisioned {
    /// The federated connection that triggered provisioning.
    pub(crate) connection_id: ConnectionId,
    /// The connection's provider name at the time of provisioning.
    pub(crate) connection_label: EventLabel,
    /// The newly created user's ID.
    pub(crate) user_id: UserId,
    /// The user's email from the external `IdP`.
    pub(crate) email: Email,
    /// When the provisioning occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    JitUserProvisioned => crate::types::event_type::FederationEvent::JitUserProvisioned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "connection",
                connection_reference(&self.connection_id, self.connection_label.as_str()),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.email.to_string()),
            )
    }
}

/// An existing account was linked to who its owner is at a connection's
/// provider: on a first sign-in, by an admin, or by the holder.
///
/// From then on the provider signs the account in by that link. It is a new
/// way into the account, so the record names the account, the connection
/// that may now sign it in and how the link was made, and the person is
/// told, so they can remove a link they did not make.
#[derive(Debug)]
pub struct AccountLinked {
    /// The connection the account is now linked through.
    pub(crate) connection_id: ConnectionId,
    /// The connection's provider name at the time of linking.
    pub(crate) connection_label: EventLabel,
    /// The linked account.
    pub(crate) user_id: UserId,
    /// The account's email address.
    pub(crate) email: Email,
    /// How the link was made.
    pub(crate) linked_by: LinkSource,
    /// When the link was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountLinked => crate::types::event_type::FederationEvent::AccountLinked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "connection",
                connection_reference(&self.connection_id, self.connection_label.as_str()),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.email.as_str()),
            )
            .field("linked_by", self.linked_by.as_str())
    }
}

/// A link from an account to who its owner is at a connection's provider
/// was removed, by the holder or an admin.
///
/// The provider no longer signs the account in. The person is told, since
/// it may be the way they usually sign in.
#[derive(Debug)]
pub struct AccountUnlinked {
    /// The connection the account is no longer linked through.
    pub(crate) connection_id: ConnectionId,
    /// The connection's provider name at the time of removal.
    pub(crate) connection_label: EventLabel,
    /// The account the link was removed from.
    pub(crate) user_id: UserId,
    /// The account's email address.
    pub(crate) email: Email,
    /// Who removed the link.
    pub(crate) unlinked_by: UnlinkSource,
    /// When the link was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountUnlinked => crate::types::event_type::FederationEvent::AccountUnlinked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "connection",
                connection_reference(&self.connection_id, self.connection_label.as_str()),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.email.as_str()),
            )
            .field("unlinked_by", self.unlinked_by.as_str())
    }
}

/// An account holder confirmed their federated link again, with a fresh
/// sign-in of their own, after the provider's signing key changed. Until
/// then the link would not sign them in, since whoever holds the new key
/// could sign in as anyone linked.
#[derive(Debug)]
pub struct LinkReconfirmed {
    /// The connection the link goes through.
    pub(crate) connection_id: ConnectionId,
    /// The connection's provider name at the time.
    pub(crate) connection_label: EventLabel,
    /// The account whose link was confirmed.
    pub(crate) user_id: UserId,
    /// The account's email address.
    pub(crate) email: Email,
    /// When the link was confirmed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LinkReconfirmed => crate::types::event_type::FederationEvent::LinkReconfirmed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "connection",
                connection_reference(&self.connection_id, self.connection_label.as_str()),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.email.as_str()),
            )
    }
}

/// A federated `IdP` connection was re-enabled after being disabled.
///
/// Users can now authenticate through this provider again.
#[derive(Debug)]
pub struct ConnectionActivated {
    /// The connection that was activated.
    pub(crate) connection_id: ConnectionId,
    /// Provider name at the time of activation.
    pub(crate) provider_name: Label,
    /// When the activation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConnectionActivated => crate::types::event_type::FederationEvent::ConnectionActivated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "connection",
            connection_reference(&self.connection_id, self.provider_name.to_string()),
        )
    }
}

/// A federated `IdP` connection's configuration was updated.
///
/// Covers changes to the SSO URL, certificate, attribute mapping, JIT
/// provisioning settings or domain hints.
#[derive(Debug)]
pub struct ConnectionUpdated {
    /// The connection that was updated.
    pub(crate) connection_id: ConnectionId,
    /// Provider name at the time of the update.
    pub(crate) provider_name: Label,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConnectionUpdated => crate::types::event_type::FederationEvent::ConnectionUpdated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "connection",
            connection_reference(&self.connection_id, self.provider_name.to_string()),
        )
    }
}

/// A federated `IdP` connection was permanently deleted.
///
/// Users made through this connection keep their accounts. They can no
/// longer sign in through this provider.
#[derive(Debug)]
pub struct ConnectionDeleted {
    /// The connection that was deleted.
    pub(crate) connection_id: ConnectionId,
    /// Provider name when it was deleted, for the audit record.
    pub(crate) provider_name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ConnectionDeleted => crate::types::event_type::FederationEvent::ConnectionDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "connection",
            connection_reference(&self.connection_id, self.provider_name.to_string()),
        )
    }
}

/// SCIM provisioning was enabled for a tenant.
///
/// The tenant's HR system or external directory can now push
/// user changes via the SCIM API.
#[derive(Debug)]
pub struct ScimEnabled {
    /// When SCIM was enabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ScimEnabled => crate::types::event_type::FederationEvent::ScimEnabled,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// SCIM provisioning was disabled for a tenant.
///
/// The SCIM API refuses every request until it is enabled again. Users
/// SCIM already created are not affected.
#[derive(Debug)]
pub struct ScimDisabled {
    /// When SCIM was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ScimDisabled => crate::types::event_type::FederationEvent::ScimDisabled,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A SCIM bearer token was rotated.
///
/// The old token is immediately invalid. The external directory
/// must be reconfigured with the new token.
#[derive(Debug)]
pub struct ScimTokenRotated {
    /// When the rotation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ScimTokenRotated => crate::types::event_type::FederationEvent::ScimTokenRotated,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// What SCIM does with the users it creates and removes was changed.
#[derive(Debug)]
pub struct ScimSettingsUpdated {
    /// The role new SCIM users now start with, if any.
    pub(crate) default_role_id: Setting<RoleId>,
    /// Whether new SCIM users are now active at once.
    pub(crate) auto_activate: ScimActivation,
    /// Whether removing a user now deactivates rather than deletes them.
    pub(crate) deactivate_on_remove: ScimRemoval,
    /// When the change was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ScimSettingsUpdated => crate::types::event_type::FederationEvent::ScimSettingsUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("auto_activate", bool::from(self.auto_activate).to_string())
            .field(
                "deactivate_on_remove",
                bool::from(self.deactivate_on_remove).to_string(),
            )
            .optional(
                "default_role_id",
                self.default_role_id.value().map(ToString::to_string),
            )
    }
}

/// This platform, as identity provider, signed a person in to one of the
/// tenant's SAML apps: it sent the app an assertion about them.
#[derive(Debug)]
pub struct SamlAssertionIssued {
    /// The app.
    pub(crate) provider_id: SamlServiceProviderId,
    /// The app's display label captured when the assertion was issued.
    pub(crate) provider_name: Label,
    /// The person the assertion is about.
    pub(crate) user_id: UserId,
    /// How the person is named in the record, their address.
    pub(crate) user_label: EventLabel,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SamlAssertionIssued => crate::types::event_type::FederationEvent::SamlAssertionIssued,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "service_provider",
                service_provider_reference(&self.provider_id, &self.provider_name),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, self.user_id.to_string(), self.user_label.as_str()),
            )
    }
}

/// A person's sign-out sent a logout request to a peer, an app or a
/// connection's provider, asking it to end their session there.
#[derive(Debug)]
pub struct LogoutRequestSent {
    /// The request's id, which the answer names.
    pub(crate) request_id: SamlRequestId,
    /// The peer it went to.
    pub(crate) peer: SamlEntityId,
    /// The peer's logout address.
    pub(crate) destination: HttpsUrl,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogoutRequestSent => crate::types::event_type::FederationEvent::LogoutRequestSent,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("request_id", self.request_id.as_str())
            .field("issuer", self.peer.as_str())
            .field("destination", self.destination.as_str())
    }
}

/// A peer answered a logout request sent from here, saying how the logout
/// went at its side.
#[derive(Debug)]
pub struct LogoutResponseTaken {
    /// The request it answers.
    pub(crate) request_id: SamlRequestId,
    /// The peer that answered.
    pub(crate) peer: SamlEntityId,
    /// How the logout went there.
    pub(crate) status: LogoutStatus,
    /// When the answer was taken.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogoutResponseTaken => crate::types::event_type::FederationEvent::LogoutResponseTaken,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("request_id", self.request_id.as_str())
            .field("issuer", self.peer.as_str())
            .field("status", self.status.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn provider_name() -> Label {
        Label::new("provider_name", "Okta").unwrap()
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Acme's Okta connection is created, activated, disabled, updated and
    /// deleted. Each record names the connection as "Okta", so an auditor
    /// sees which provider changed.
    #[test]
    fn every_connection_event_names_the_connection() {
        let connection = ConnectionId::new();

        for event in connection_events(connection) {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "connection"),
                (
                    RefKind::CONNECTION,
                    connection.to_string(),
                    "Okta".to_owned()
                ),
                "{kind}"
            );
        }
    }

    /// Every lifecycle record for one Okta connection.
    fn connection_events(connection: ConnectionId) -> Vec<Box<dyn DomainEventCore>> {
        vec![
            Box::new(ConnectionCreated {
                connection_id: connection,
                provider_name: provider_name(),
                protocol: FederationProtocol::Saml,
                occurred_at: now(),
            }),
            Box::new(ConnectionActivated {
                connection_id: connection,
                provider_name: provider_name(),
                occurred_at: now(),
            }),
            Box::new(ConnectionDisabled {
                connection_id: connection,
                provider_name: provider_name(),
                occurred_at: now(),
            }),
            Box::new(ConnectionUpdated {
                connection_id: connection,
                provider_name: provider_name(),
                occurred_at: now(),
            }),
            Box::new(ConnectionDeleted {
                connection_id: connection,
                provider_name: provider_name(),
                occurred_at: now(),
            }),
        ]
    }

    /// Acme's "Salesforce" SAML app is added, changed and deleted. Each
    /// record names the app by its name, so an auditor sees which app
    /// changed.
    #[test]
    fn every_service_provider_event_names_the_app() {
        let provider_id = SamlServiceProviderId::new();

        for event in service_provider_events(provider_id) {
            let kind = event.event_type();
            assert_eq!(
                entity(&event.payload(), "service_provider"),
                (
                    SERVICE_PROVIDER,
                    provider_id.to_string(),
                    "Salesforce".to_owned()
                ),
                "{kind}"
            );
        }
    }

    /// Creation, update and deletion records for one Salesforce SAML app.
    fn service_provider_events(
        provider_id: SamlServiceProviderId,
    ) -> Vec<Box<dyn DomainEventCore>> {
        let name = Label::new("name", "Salesforce").unwrap();

        vec![
            Box::new(ServiceProviderCreated {
                provider_id,
                name: name.clone(),
                occurred_at: now(),
            }),
            Box::new(ServiceProviderUpdated {
                provider_id,
                name: name.clone(),
                occurred_at: now(),
            }),
            Box::new(ServiceProviderDeleted {
                provider_id,
                name,
                occurred_at: now(),
            }),
        ]
    }

    /// One connection is created over SAML and one over OIDC. Their records
    /// say `saml` and `oidc`.
    #[test]
    fn creating_a_connection_records_the_protocol_it_speaks() {
        let connection = ConnectionId::new();
        let saml = ConnectionCreated {
            connection_id: connection,
            provider_name: provider_name(),
            protocol: FederationProtocol::Saml,
            occurred_at: now(),
        };
        let oidc = ConnectionCreated {
            connection_id: connection,
            provider_name: provider_name(),
            protocol: FederationProtocol::Oidc,
            occurred_at: now(),
        };

        assert_eq!(text(&saml.payload(), "protocol"), "saml");
        assert_eq!(text(&oidc.payload(), "protocol"), "oidc");
    }

    /// Ada's account is made on her first sign-in through Okta. The record
    /// names her by address and the Okta connection, since nobody made the
    /// account by hand.
    #[test]
    fn a_jit_provisioned_user_names_the_user_and_the_connection() {
        let connection = ConnectionId::new();
        let user_id = UserId::new();

        let event = JitUserProvisioned {
            connection_id: connection,
            connection_label: EventLabel::of("Okta"),
            user_id,
            email: Email::new("ada@acme.com").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "connection"),
            (
                RefKind::CONNECTION,
                connection.to_string(),
                "Okta".to_owned()
            )
        );
        assert_eq!(
            entity(&payload, "user"),
            (
                RefKind::USER,
                user_id.to_string(),
                "ada@acme.com".to_owned()
            )
        );
    }

    /// Ada links her own Okta subject to her account. The record names her
    /// account, the connection that may now sign her in, and that she made
    /// the link herself.
    #[test]
    fn a_linked_account_names_the_user_the_connection_and_how() {
        let connection = ConnectionId::new();
        let user_id = UserId::new();

        let event = AccountLinked {
            connection_id: connection,
            connection_label: EventLabel::of("Okta"),
            user_id,
            email: Email::new("ada@acme.com").unwrap(),
            linked_by: LinkSource::Holder,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "connection"),
            (
                RefKind::CONNECTION,
                connection.to_string(),
                "Okta".to_owned()
            )
        );
        assert_eq!(
            entity(&payload, "user"),
            (
                RefKind::USER,
                user_id.to_string(),
                "ada@acme.com".to_owned()
            )
        );
        assert_eq!(text(&payload, "linked_by"), "holder");
    }

    /// An admin removes Ada's Okta link. The record names her account, the
    /// connection that no longer signs her in, and that an admin removed it.
    #[test]
    fn an_unlinked_account_names_the_user_the_connection_and_who() {
        let connection = ConnectionId::new();
        let user_id = UserId::new();

        let event = AccountUnlinked {
            connection_id: connection,
            connection_label: EventLabel::of("Okta"),
            user_id,
            email: Email::new("ada@acme.com").unwrap(),
            unlinked_by: UnlinkSource::Admin,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(
            entity(&payload, "connection"),
            (
                RefKind::CONNECTION,
                connection.to_string(),
                "Okta".to_owned()
            )
        );
        assert_eq!(
            entity(&payload, "user"),
            (
                RefKind::USER,
                user_id.to_string(),
                "ada@acme.com".to_owned()
            )
        );
        assert_eq!(text(&payload, "unlinked_by"), "admin");
    }

    /// SCIM is enabled, disabled and its token rotated. Each record carries
    /// no payload, so the token never lands in the audit log.
    #[test]
    fn the_scim_switches_carry_no_payload() {
        let events: Vec<Box<dyn DomainEventCore>> = vec![
            Box::new(ScimEnabled { occurred_at: now() }),
            Box::new(ScimDisabled { occurred_at: now() }),
            Box::new(ScimTokenRotated { occurred_at: now() }),
        ];

        for event in events {
            let kind = event.event_type();
            assert!(event.payload().is_empty(), "{kind}");
        }
    }

    /// Ann confirms her Okta link again after Okta's key changed. The record
    /// names the connection and her account.
    #[test]
    fn reconfirming_a_link_names_the_connection_and_the_account() {
        let (connection_id, user_id) = (ConnectionId::new(), UserId::new());

        let event = LinkReconfirmed {
            connection_id,
            connection_label: EventLabel::of("Okta"),
            user_id,
            email: Email::new("ann@acme.com").unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("the account is not referenced");
        };
        assert_eq!(user.id(), user_id.to_string());
        let Some(FieldValue::Reference(connection)) = payload.value("connection") else {
            panic!("the connection is not referenced");
        };
        assert_eq!(connection.id(), connection_id.to_string());
    }
}
