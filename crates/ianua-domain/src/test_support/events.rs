//! Whole events for tests outside the domain, which can no longer build an
//! event themselves, and a way to read what an aggregate raised.

use time::OffsetDateTime;

use crate::domains::agents::events::identity::AllAgentsSuspended;
use crate::domains::authentication::events::login::{
    AccountLockedOut, AccountUnderAttack, LockedAddress, LoginFailed, LoginFailureReason,
    LoginSucceeded,
};
use crate::domains::authentication::events::session::{RevocationReason, SessionRevoked};
use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
use crate::domains::authorization::events::roles::RoleAssigned;
use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::events::account::{UserDeleted, UserEmailChanged, UserStatusChanged};
use crate::domains::messaging::events::{MessagePublished, TopicPaused};
use crate::domains::messaging::topic_name::TopicName;
use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::channel::NotificationChannel;
use crate::domains::notifications::events::NotificationPreferencesUpdated;
use crate::domains::oauth::events::grants::RefreshTokenReused;
use crate::domains::operator::events::OperatorCreated;
use crate::domains::organization::events::access::{OrgLoginSucceeded, OrgSignInMethod};
use crate::domains::tenant::events::lifecycle::{TenantDeleted, TenantProvisioned};
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::config::SlugLimits;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, RaisesComplete, scoped};
use crate::types::{
    ActorRef, Email, EventLabel, Expiry, Fact, OAuthClientId, OperatorId, OrgUserId,
    OrganizationId, PrincipalRef, RoleId, SessionId, TenantId, TenantSlug, TopicId, UntrustedText,
    UserId,
};

/// A tenant event of `tenant_id`: the topic `orders.created` was paused.
/// For adapters' tests that carry, store or publish some tenant event.
///
/// # Panics
///
/// Never: the topic name is a valid literal.
#[must_use]
pub fn sample_tenant_event(tenant_id: TenantId) -> DomainEvent {
    scoped(
        tenant_id,
        TopicPaused {
            topic_id: TopicId::new(),
            topic_name: TopicName::new("orders.created").expect("a valid topic name"),
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// The announcement that `tenant` was provisioned, as its creation raised
/// it, for tests of what a new tenant starts.
#[must_use]
pub fn sample_tenant_provisioned(tenant: &Tenant) -> DomainEvent {
    scoped(
        *tenant.id(),
        TenantProvisioned {
            tenant_id: *tenant.id(),
            slug: tenant.slug().clone(),
            display_name: tenant.display_name().clone(),
            occurred_at: tenant.created_at(),
        },
    )
}

/// The announcement that `tenant_id` was deleted, for tests of what its
/// deletion starts.
#[must_use]
pub fn sample_tenant_deleted(tenant_id: TenantId) -> DomainEvent {
    scoped(
        tenant_id,
        TenantDeleted {
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id`: a message was published to the topic
/// `topic`. For tests of what a publication pushes.
///
/// # Panics
///
/// When `topic` is not a valid topic name. Tests pass one that is.
#[must_use]
pub fn sample_message_published(tenant_id: TenantId, topic: &str) -> DomainEvent {
    scoped(
        tenant_id,
        MessagePublished {
            topic_name: TopicName::new(topic).expect("a valid topic name"),
            payload_size: 42,
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id` recorded at `at`: someone stopped every
/// agent of the tenant at once, and the store suspended three. For tests
/// of what a tenant-wide stop tells receivers.
#[must_use]
pub fn sample_fleet_suspension(tenant_id: TenantId, at: OffsetDateTime) -> DomainEvent {
    scoped(
        tenant_id,
        AllAgentsSuspended {
            suspended_count: 3,
            occurred_at: at,
        },
    )
}

/// A tenant event of `tenant_id`: an admin revoked `session`, a session of
/// the user `user_id`. For tests of what a revoked session tells the apps
/// it reached.
#[must_use]
pub fn sample_session_revoked(
    tenant_id: TenantId,
    user_id: UserId,
    session: SessionId,
) -> DomainEvent {
    scoped(
        tenant_id,
        SessionRevoked {
            session_id: session,
            user_id,
            user_label: Some(EventLabel::of("ann@acme.test")),
            reason: RevocationReason::AdminAction,
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id`: the account of the user `user_id` was
/// deleted for good. For tests of what a deletion tells the apps the
/// person reached.
///
/// # Panics
///
/// Never: the address is a valid literal.
#[must_use]
pub fn sample_user_deleted(tenant_id: TenantId, user_id: UserId) -> DomainEvent {
    scoped(
        tenant_id,
        UserDeleted {
            user_id,
            email: Email::new("ann@acme.test").expect("a valid address"),
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id`: the platform gave `holder` the role
/// `role`, until nobody takes it away. For tests of what a change to what
/// someone holds tells the apps they reach.
#[must_use]
pub fn sample_role_assigned(
    tenant_id: TenantId,
    holder: PrincipalRef,
    role: RoleId,
) -> DomainEvent {
    scoped(
        tenant_id,
        RoleAssigned {
            holder,
            holder_label: EventLabel::of("ann@acme.test"),
            role_id: role,
            role_label: EventLabel::of("viewer"),
            assigned_by: ActorRef::System,
            granted_by_label: None,
            until: Expiry::Never,
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id` about the user `user_id`: an admin locked
/// their account. Its payload names the user, for tests of what an event
/// about one person does for that person.
///
/// # Panics
///
/// Never: the label is a valid literal.
#[must_use]
pub fn sample_event_about(tenant_id: TenantId, user_id: UserId) -> DomainEvent {
    scoped(
        tenant_id,
        UserStatusChanged {
            user_id,
            user_label: EventLabel::of("carol@acme.test"),
            from: UserStatus::Active,
            to: UserStatus::Locked,
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id` that is never worth a notification: a
/// user turned audit notifications off. For tests of what reacts only to
/// notifiable events.
#[must_use]
pub fn sample_unnotifiable_event(tenant_id: TenantId) -> DomainEvent {
    scoped(
        tenant_id,
        NotificationPreferencesUpdated {
            category: NotificationCategory::Audit,
            new_channel: NotificationChannel::Disabled,
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A tenant event of `tenant_id` that is a security alert: a spent refresh
/// token of the client "billing" was presented again. For tests of how
/// alerts are told.
#[must_use]
pub fn sample_refresh_token_reused(tenant_id: TenantId) -> DomainEvent {
    scoped(
        tenant_id,
        RefreshTokenReused {
            client_id: OAuthClientId::new(),
            client_label: EventLabel::of("billing"),
            occurred_at: crate::shared::clock::now(),
        },
    )
}

/// A platform event: the operator `ops@example.com` was created. For
/// adapters' tests that carry, store or publish some platform event.
///
/// # Panics
///
/// Never: the address is a valid literal.
#[must_use]
pub fn sample_platform_event() -> DomainEvent {
    DomainEvent::platform(Box::new(OperatorCreated {
        operator_id: OperatorId::new(),
        email: Email::new("ops@example.com").expect("a valid address"),
        occurred_at: crate::shared::clock::now(),
    }))
}

/// A tenant event of `tenant_id` at `at`: someone signed in by password,
/// the sign-in timed at `auth_duration_ms`. For tests of the audit trail
/// and of the sign-in figures read from it.
#[must_use]
pub fn sample_login_succeeded(
    tenant_id: TenantId,
    auth_duration_ms: u32,
    at: OffsetDateTime,
) -> DomainEvent {
    scoped(
        tenant_id,
        LoginSucceeded {
            session_id: SessionId::new(),
            auth_method: AuthMethod::Password,
            ip_address: Fact::Unknown,
            auth_duration_ms: Fact::Known(auth_duration_ms),
            occurred_at: at,
        },
    )
}

/// A tenant event of `tenant_id` at `at`: a sign-in with a wrong password
/// failed. For tests of the audit trail and of the sign-in figures read
/// from it.
#[must_use]
pub fn sample_login_failed(tenant_id: TenantId, at: OffsetDateTime) -> DomainEvent {
    scoped(
        tenant_id,
        LoginFailed {
            email: UntrustedText::record("ann@acme.test"),
            reason: LoginFailureReason::BadPassword,
            ip_address: Fact::Unknown,
            occurred_at: at,
        },
    )
}

/// A tenant event of `tenant_id` at `at`: a sign-in typed with `email`
/// failed on a wrong password, as the sign-in records it, made by nobody
/// signed in.
///
/// # Panics
///
/// Never for the addresses tests type: any text is recorded.
#[must_use]
pub fn sample_login_failed_at(tenant_id: TenantId, email: &str, at: OffsetDateTime) -> DomainEvent {
    scoped(
        tenant_id,
        LoginFailed {
            email: UntrustedText::record(email),
            reason: LoginFailureReason::BadPassword,
            ip_address: Fact::Unknown,
            occurred_at: at,
        },
    )
    .system()
}

/// A tenant event of `tenant_id` at `at`: the account `user_id` moved from
/// the address `from` to `to`.
///
/// # Panics
///
/// When `from` or `to` is not an address, which is a mistake in the test.
#[must_use]
pub fn sample_email_changed(
    tenant_id: TenantId,
    user_id: UserId,
    (from, to): (&str, &str),
    at: OffsetDateTime,
) -> DomainEvent {
    scoped(
        tenant_id,
        UserEmailChanged {
            user_id,
            user_label: EventLabel::of(to),
            old_email: Email::new(from).expect("a valid address"),
            new_email: Email::new(to).expect("a valid address"),
            occurred_at: at,
        },
    )
}

/// A tenant event of `tenant_id` at `at`: the account `user_id`, signed in
/// to as `ann@acme.test`, was locked after five failed sign-ins. For tests
/// of the records kept about a person they did not make themselves.
#[must_use]
pub fn sample_account_locked_out(
    tenant_id: TenantId,
    user_id: UserId,
    at: OffsetDateTime,
) -> DomainEvent {
    scoped(
        tenant_id,
        AccountLockedOut {
            user_id: LockedAddress::Account(user_id),
            user_label: EventLabel::of("ann@acme.test"),
            failed_attempts: 5,
            locked_until: at + time::Duration::minutes(15),
            origin: AttemptOrigin::of(Fact::Unknown),
            ip_address: Fact::Unknown,
            occurred_at: at,
        },
    )
}

/// A tenant event of `tenant_id`, now: failures from twenty networks put
/// the account at `ann@acme.test` under attack for an hour. For tests of
/// how an attack on an account is told.
#[must_use]
pub fn sample_account_under_attack(tenant_id: TenantId) -> DomainEvent {
    let now = crate::shared::clock::now();
    scoped(
        tenant_id,
        AccountUnderAttack {
            user_id: LockedAddress::NoAccount,
            user_label: EventLabel::of("ann@acme.test"),
            networks: 20,
            until: now + time::Duration::HOUR,
            occurred_at: now,
        },
    )
}

/// An organization event of `organization_id` at `at`: one of its members
/// signed in by password. For adapters' tests that keep or read some
/// organization event.
#[must_use]
pub fn sample_organization_event(
    organization_id: OrganizationId,
    at: OffsetDateTime,
) -> DomainEvent {
    DomainEvent::organization(Box::new(OrgLoginSucceeded {
        organization_id,
        org_user_id: OrgUserId::new(),
        method: OrgSignInMethod::Password,
        occurred_at: at,
    }))
}

/// The events `aggregate` raised, in order, as saved for a tenant made up
/// for the test. Taking them leaves none.
///
/// # Panics
///
/// Never: the tenant slug is a valid literal.
pub fn raised(aggregate: &mut impl Raises) -> Vec<DomainEvent> {
    let tenant = ResolvedTenant::new(
        TenantId::new(),
        TenantSlug::new("acme", &SlugLimits::default()).expect("a valid slug"),
    );
    aggregate.take_events(&tenant)
}

/// The names of the events `aggregate` raised, in order, as the audit trail
/// stores them, such as `messaging.topic_paused`. Taking them leaves none.
pub fn raised_names(aggregate: &mut impl Raises) -> Vec<String> {
    raised(aggregate)
        .iter()
        .map(|event| event.event_type().to_string())
        .collect()
}

/// The names of the events an aggregate that knows its scope raised, in
/// order, such as `operator.operator_disabled`. Taking them leaves none.
pub fn raised_complete_names(aggregate: &mut impl RaisesComplete) -> Vec<String> {
    aggregate
        .take_events()
        .iter()
        .map(|event| event.event_type().to_string())
        .collect()
}
