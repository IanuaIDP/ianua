//! Events about members signing in to the management plane and the credentials they use.

mod credentials;
pub mod identity_provider;
mod sign_in;

pub use credentials::*;
pub use sign_in::*;

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::domains::authentication::risk_engine::attack::{
        AccountAttack, AttackMark, AttackSigns, FailingNetworks,
    };
    use crate::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
    use crate::domains::organization::access::session::SessionPlace;
    use crate::domains::organization::events::members::{OrgUserDeleted, OrgUserEmailVerified};
    use crate::domains::organization::events::organization::{
        OrganizationCreated, OrganizationRenamed, OrganizationStatusChanged,
    };
    use crate::domains::organization::status::OrganizationStatus;
    use crate::shared::events::data::{EventData, FieldValue, RefKind};
    use crate::shared::events::event::{DomainEventCore, OrganizationDomainEvent};
    use crate::test_support::builders::label;
    use crate::types::{
        EventLabel, Label, OrgApiKeyId, OrgUserId, OrganizationId, SessionId, TenantId, UserId,
    };

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Ada's password sign-in is refused because her account is locked.
    /// The record names her organization and her, the way she tried, and
    /// why it was refused.
    #[test]
    fn a_refused_sign_in_is_observed_with_its_reason() {
        let ada = crate::test_support::builders::org_user(OrgUserId::new(), "ada@acme.com");

        let event =
            OrgLoginFailed::observed(&ada, OrgSignInMethod::Password, OrgSignInRefusal::Locked);

        let payload = event.payload();
        assert_eq!(event.organization_id(), Some(ada.organization_id()));
        assert_eq!(
            entity(&payload, "org_user"),
            (
                RefKind::ORG_USER,
                ada.id().to_string(),
                ada.id().to_string()
            )
        );
        assert_eq!(payload.get("method"), Some("password"));
        assert_eq!(payload.get("reason"), Some("locked"));
    }

    /// A botnet's failures from ten networks put Ada's account under
    /// attack. The record names her organization, her and how many networks
    /// failed, and is an alert rather than a colleague's feed notice.
    #[test]
    fn an_attack_on_a_member_is_observed_with_its_networks() {
        let ada = crate::test_support::builders::org_user(OrgUserId::new(), "ada@acme.com");
        let signs = AttackSigns::new(FailingNetworks::from(10), AttackMark::Unmarked);
        let begun = AccountAttack::of(signs, &RateLimitPolicy::DEFAULT, now())
            .begun()
            .unwrap();

        let event = OrgAccountUnderAttack::observed(&ada, begun);

        assert_eq!(event.organization_id(), Some(ada.organization_id()));
        assert_eq!(event.payload().get("networks"), Some("10"));
        assert!(!event.event_type().is_notifiable());
    }

    /// Ada asks for a sign-in link and one is mailed to her. The record
    /// names her organization and her, and stays out of her colleagues'
    /// feeds.
    #[test]
    fn a_mailed_sign_in_link_is_observed_for_the_member() {
        let ada = crate::test_support::builders::org_user(OrgUserId::new(), "ada@acme.com");

        let event = OrgMagicLinkRequested::observed(&ada);

        assert_eq!(event.organization_id(), Some(ada.organization_id()));
        assert_eq!(
            entity(&event.payload(), "org_user"),
            (
                RefKind::ORG_USER,
                ada.id().to_string(),
                ada.id().to_string()
            )
        );
        assert!(!event.event_type().is_notifiable());
    }

    /// Ada's single sign-on through her organization's provider records
    /// how she signed in, under its own name.
    #[test]
    fn a_single_sign_on_is_recorded_by_its_name() {
        let ada = crate::test_support::builders::org_user(OrgUserId::new(), "ada@acme.com");

        let event = OrgLoginSucceeded::observed(&ada, OrgSignInMethod::SingleSignOn);

        assert_eq!(event.payload().get("method"), Some("single_sign_on"));
    }

    /// A discoverable passkey challenge is issued before anyone is known.
    /// Its record names no organization and no tenant.
    #[test]
    fn a_discoverable_challenge_is_a_platform_record() {
        let event = OrgPasskeyChallengeIssued::observed();

        assert_eq!(event.organization_id(), None);
        assert_eq!(event.tenant_id(), None);
        assert!(event.payload().is_empty());
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

    /// Ann changes her own password. The event carries no payload, since the
    /// audit record already names her as the actor.
    #[test]
    fn self_service_password_change_omits_the_actor() {
        let event = OrgUserPasswordChanged {
            organization_id: OrganizationId::new(),
            occurred_at: crate::shared::clock::now(),
        };

        assert!(
            event.payload().is_empty(),
            "the actor is on the audit record, not in the payload"
        );
    }

    /// Lifecycle, profile, sign-in and credential events all report the
    /// organization ID supplied when they were created.
    #[test]
    fn every_organization_event_is_scoped_to_its_own_organization() {
        let org = OrganizationId::new();

        let mut events: Vec<Box<dyn OrganizationDomainEvent>> = vec![
            Box::new(OrganizationCreated {
                organization_id: org,
                name: label("Acme"),
                occurred_at: now(),
            }),
            Box::new(OrganizationStatusChanged {
                organization_id: org,
                from: OrganizationStatus::Active,
                to: OrganizationStatus::Suspended,
                occurred_at: now(),
            }),
            Box::new(OrganizationRenamed {
                organization_id: org,
                old_name: label("Acme"),
                new_name: label("Acme Corp"),
                occurred_at: now(),
            }),
        ];
        events.extend(self_service_events(org));

        for event in events {
            assert_eq!(event.organization_id(), &org, "{}", event.event_type());
        }
    }

    /// Self-service and sign-in settings events carrying only their organization.
    fn self_service_events(org: OrganizationId) -> Vec<Box<dyn OrganizationDomainEvent>> {
        vec![
            Box::new(OrganizationAuthConfigUpdated {
                organization_id: org,
                occurred_at: now(),
            }),
            Box::new(OrgUserEmailVerified {
                organization_id: org,
                occurred_at: now(),
            }),
            Box::new(OrgUserPasswordResetRequested {
                organization_id: org,
                occurred_at: now(),
            }),
            Box::new(OrgMfaEnrolled {
                organization_id: org,
                occurred_at: now(),
            }),
            Box::new(OrgDeviceTrusted {
                organization_id: org,
                occurred_at: now(),
            }),
            Box::new(OrgDeviceRevoked {
                organization_id: org,
                occurred_at: now(),
            }),
        ]
    }

    /// Ann verifies her email, asks for a reset, enrols MFA and trusts and
    /// revokes a device. None of these events carries a payload, since the
    /// type and the actor say it all.
    #[test]
    fn the_self_service_events_carry_no_payload() {
        let org = OrganizationId::new();
        for event in self_service_events(org) {
            assert!(event.payload().is_empty(), "{}", event.event_type());
        }
    }

    /// Ada switches from Staging to Production and gets a new session there.
    /// The record names both tenants, her account in Production, and the new
    /// session.
    #[test]
    fn switching_tenants_names_both_tenants_the_identity_and_the_session() {
        let event = switched_to_production();
        let source = event.source_tenant_id;
        let target = event.target_tenant_id;
        let target_user = event.target_user_id;
        let session = event.new_session_id;
        let payload = event.payload();
        assert_eq!(event.organization_id(), &event.organization_id);
        assert_eq!(
            entity(&payload, "source_tenant"),
            (RefKind::TENANT, source.to_string(), "Staging".to_owned())
        );
        assert_eq!(
            entity(&payload, "target_tenant"),
            (RefKind::TENANT, target.to_string(), "Production".to_owned())
        );
        assert_eq!(
            entity(&payload, "target_user"),
            (
                RefKind::USER,
                target_user.to_string(),
                "ada@acme.com".to_owned()
            )
        );
        assert_id_reference(
            &payload,
            "new_session",
            RefKind::SESSION,
            session.to_string(),
        );
    }

    /// Ada switches from Staging to Production and receives a new session.
    fn switched_to_production() -> TenantSwitched {
        TenantSwitched {
            organization_id: OrganizationId::new(),
            source_tenant_id: TenantId::new(),
            source_tenant_label: EventLabel::of("Staging"),
            target_tenant_id: TenantId::new(),
            target_tenant_label: EventLabel::of("Production"),
            target_user_id: UserId::new(),
            target_user_label: EventLabel::of("ada@acme.com"),
            new_session_id: SessionId::new(),
            occurred_at: now(),
        }
    }

    /// Ada moves her organization session from Staging to Production. The
    /// record names her, both tenants and the new session.
    #[test]
    fn moving_a_session_names_the_member_both_tenants_and_the_new_session() {
        let org = OrganizationId::new();
        let ada = OrgUserId::new();
        let source = TenantId::new();
        let target = TenantId::new();
        let session = SessionId::new();

        let event = OrgSessionMoved {
            organization_id: org,
            org_user_id: ada,
            source: SessionPlace::Tenant(source),
            target_tenant_id: target,
            new_session_id: session,
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(event.organization_id(), &org);
        assert_id_reference(&payload, "org_user", RefKind::ORG_USER, ada.to_string());
        assert_session_tenants(&payload, source, target);
        assert_id_reference(
            &payload,
            "new_session",
            RefKind::SESSION,
            session.to_string(),
        );
    }

    /// Both ends of a session move retain their tenant identifiers as reference labels.
    fn assert_session_tenants(payload: &EventData, source: TenantId, target: TenantId) {
        assert_id_reference(
            payload,
            "source_tenant",
            RefKind::TENANT,
            source.to_string(),
        );
        assert_id_reference(
            payload,
            "target_tenant",
            RefKind::TENANT,
            target.to_string(),
        );
    }

    /// An unlabelled reference uses the identifier both as its key and visible label.
    fn assert_id_reference(payload: &EventData, key: &str, kind: RefKind, id: String) {
        assert_eq!(entity(payload, key), (kind, id.clone(), id));
    }

    /// An owner deletes Ada's account, or resets her password. Each record
    /// names Ada's account, since the actor is the owner, not her.
    #[test]
    fn the_administrative_member_events_name_the_account_acted_on() {
        let org = OrganizationId::new();
        let member = OrgUserId::new();
        let label = "Ada Lovelace (ada@acme.com)";

        let deleted = OrgUserDeleted {
            organization_id: org,
            org_user_id: member,
            org_user_label: EventLabel::of(label),
            occurred_at: now(),
        };
        let reset = OrgUserPasswordReset {
            organization_id: org,
            org_user_id: member,
            org_user_label: EventLabel::of(label),
            occurred_at: now(),
        };

        for event in [&deleted as &dyn OrganizationDomainEvent, &reset] {
            let kind = event.event_type();
            assert_eq!(event.organization_id(), &org, "{kind}");
            assert_eq!(
                entity(&event.payload(), "org_user"),
                (RefKind::ORG_USER, member.to_string(), label.to_owned()),
                "{kind}"
            );
        }
    }

    /// An org API key named "terraform" is created and later revoked. Both
    /// records name it as "terraform", so an operator knows which key it was.
    #[test]
    fn the_org_api_key_events_name_the_key() {
        let org = OrganizationId::new();
        let key = OrgApiKeyId::new();

        let created = OrgApiKeyCreated {
            organization_id: org,
            key_id: key,
            name: Label::new("name", "terraform").unwrap(),
            occurred_at: now(),
        };
        let revoked = OrgApiKeyRevoked {
            organization_id: org,
            key_id: key,
            key_label: EventLabel::of("terraform"),
            occurred_at: now(),
        };

        for event in [&created as &dyn OrganizationDomainEvent, &revoked] {
            let kind = event.event_type();
            assert_eq!(event.organization_id(), &org, "{kind}");
            assert_eq!(
                entity(&event.payload(), "key"),
                (RefKind::KEY, key.to_string(), "terraform".to_owned()),
                "{kind}"
            );
        }
    }
}
