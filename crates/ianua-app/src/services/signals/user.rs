//! The security signals a person's account, sessions and holdings events
//! mean, so a relying party hears at once that a session ended, a
//! credential changed, an account was locked or deleted, or what someone
//! may do changed, and cuts access in step with the identity provider.
//!
//! The signals planner asks this for every event that is not an agents
//! event, and queues one signal job for each stream that takes what comes
//! back. Each event goes out under the CAEP or RISC event types a receiver
//! knows; see the signals page of the docs for the full table.
//!
//! An event names the account it happened to when someone other than its
//! holder acted: an admin, a directory sync or the platform. When the
//! holder acted, the record's actor names them instead. Role and group
//! events name their holder or member, which may be a person or an agent.

use ianua_domain::domains::audit::builder::{AuditActor, AuditContext};
use ianua_domain::domains::authentication::credentials::passkey::AuthenticatorType;
use ianua_domain::domains::authentication::events::session::{RevocationReason, SuspensionReason};
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::signals::report::ReportedSignal;
use ianua_domain::domains::signals::signal::{
    CredentialChangeType, CredentialKind, SignalAssuranceLevel, SignalEvent, SignalSubject,
};
use ianua_domain::shared::events::data::{EventData, FieldValue, RefKind};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::event_type::{
    AuthenticationEvent, AuthorizationEvent, EventType, IdentityEvent, SignalsEvent,
};
use ianua_domain::types::{ActorRef, AgentId, Fact, UserId};
use uuid::Uuid;

/// What an event says happened to one user or agent of the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectChange {
    /// Whom it happened to.
    pub subject: SignalSubject,
    /// What happened, as the signals say it.
    pub change: Change,
}

/// What happened to a subject, as the signals say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// It goes out as these signals, the most precise first: a stream is
    /// sent the first it takes.
    Signals(Vec<SignalEvent>),
    /// What the subject holds changed. The signal carries what they hold
    /// now, which the planner reads when it plans.
    Holdings,
}

/// What `event`, recorded in `context`, says happened to one of the
/// tenant's users or agents, or `None` when it is not an event a relying
/// party must hear about, or names nobody it happened to.
#[must_use]
pub fn user_change(event: &DomainEvent, context: &AuditContext) -> Option<SubjectChange> {
    let payload = event.payload();
    match event.event_type() {
        EventType::Authentication(kind) => {
            let change = authentication_change(kind, &payload)?;
            let account = account_of(event, context, &payload, naming_of(kind))?;
            Some(change.about(SignalSubject::User(account)))
        }
        EventType::Identity(kind) => {
            let change = identity_change(kind, &payload)?;
            let account = named_user(&payload, "user")?;
            Some(change.about(SignalSubject::User(account)))
        }
        EventType::Authorization(kind) => holding_change(kind, &payload),
        EventType::Signals(SignalsEvent::SignalReported) => {
            let reported = ReportedSignal::read(&payload)?;
            let account = named_user(&payload, "user")?;
            Some(Change::Signals(vec![reported.event()]).about(SignalSubject::User(account)))
        }
        _ => None,
    }
}

impl Change {
    /// The security signals or changed holdings, paired with the affected `subject`.
    fn about(self, subject: SignalSubject) -> SubjectChange {
        SubjectChange {
            subject,
            change: self,
        }
    }
}

/// How an event names the account it happened to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// Its payload always names the account.
    Always,
    /// Its payload names the account only when someone other than the
    /// holder acted. When it names none, the holder acted.
    UnlessTheHolderActed,
}

/// How an authentication event names its account. Only the events a
/// holder makes about their own account leave it out; every other event
/// that names none is about nobody, never about whoever acted.
fn naming_of(kind: AuthenticationEvent) -> Naming {
    match kind {
        AuthenticationEvent::SessionRevoked
        | AuthenticationEvent::PasswordChanged
        | AuthenticationEvent::PasswordResetCompleted
        | AuthenticationEvent::PasskeyRegistered
        | AuthenticationEvent::PasskeyRemoved
        | AuthenticationEvent::MfaEnrolled
        | AuthenticationEvent::MfaUnenrolled
        | AuthenticationEvent::MfaVerified => Naming::UnlessTheHolderActed,
        _ => Naming::Always,
    }
}

/// The account `event`, carrying `payload`, happened to, as `naming` says
/// to find it.
fn account_of(
    event: &DomainEvent,
    context: &AuditContext,
    payload: &EventData,
    naming: Naming,
) -> Option<UserId> {
    let named = named_user(payload, "user");
    match naming {
        Naming::Always => named,
        Naming::UnlessTheHolderActed => named.or_else(|| acting_user(event, context)),
    }
}

/// The credential change an authentication event reports, if it reports
/// one: a password set, a passkey added or removed, a second factor turned
/// on or off.
fn credential_changed(kind: AuthenticationEvent, payload: &EventData) -> Option<SignalEvent> {
    let (credential_kind, change) = match kind {
        AuthenticationEvent::PasswordChanged | AuthenticationEvent::PasswordResetCompleted => {
            (CredentialKind::Password, CredentialChangeType::Update)
        }
        AuthenticationEvent::PasskeyRegistered => (passkey(payload), CredentialChangeType::Create),
        AuthenticationEvent::PasskeyRemoved => (passkey(payload), CredentialChangeType::Delete),
        AuthenticationEvent::MfaEnrolled => (CredentialKind::App, CredentialChangeType::Create),
        AuthenticationEvent::MfaUnenrolled => (CredentialKind::App, CredentialChangeType::Delete),
        _ => return None,
    };
    Some(credential(credential_kind, change))
}

/// What an authentication event means, for the account it is about.
///
/// A second factor goes out as an authenticator app, the factor CAEP names
/// that every method here stands closest to. An admin's reset of every
/// factor is told through each factor and passkey it removed, so it is not
/// told again as a whole.
fn authentication_change(kind: AuthenticationEvent, payload: &EventData) -> Option<Change> {
    if let Some(changed) = credential_changed(kind, payload) {
        return Some(Change::Signals(vec![changed]));
    }
    let signals = match kind {
        AuthenticationEvent::SessionRevoked => revoked(payload),
        AuthenticationEvent::SessionSuspended => suspended(payload),
        AuthenticationEvent::PasswordBreachDetected => vec![SignalEvent::CredentialCompromised {
            credential: CredentialKind::Password,
        }],
        AuthenticationEvent::MfaVerified => vec![assurance(payload)?],
        AuthenticationEvent::BreakGlassGranted | AuthenticationEvent::BreakGlassRevoked => {
            return Some(Change::Holdings);
        }
        _ => return None,
    };
    Some(Change::Signals(signals))
}

/// What an identity event means, for the account it is about.
fn identity_change(kind: IdentityEvent, payload: &EventData) -> Option<Change> {
    let signals = match kind {
        IdentityEvent::UserStatusChanged => vec![status_signal(payload)?],
        IdentityEvent::PasswordReset => {
            vec![credential(
                CredentialKind::Password,
                CredentialChangeType::Update,
            )]
        }
        IdentityEvent::EmailChanged => vec![SignalEvent::IdentifierChanged],
        IdentityEvent::UserDeleted => {
            vec![SignalEvent::AccountPurged, SignalEvent::AccountDisabled]
        }
        _ => return None,
    };
    Some(Change::Signals(signals))
}

/// The holder whose roles or groups an authorization event changed, when
/// it is a person or an agent. A group's own roles reach everyone in it, so
/// a change to them names no one subject and is not signalled.
fn holding_change(kind: AuthorizationEvent, payload: &EventData) -> Option<SubjectChange> {
    let key = match kind {
        AuthorizationEvent::RoleAssigned
        | AuthorizationEvent::RoleRevoked
        | AuthorizationEvent::RoleAssignmentExpired => "holder",
        AuthorizationEvent::GroupMemberAdded
        | AuthorizationEvent::GroupMemberRemoved
        | AuthorizationEvent::GroupMembershipExpired => "member",
        _ => return None,
    };
    Some(SubjectChange {
        subject: named_holder(payload, key)?,
        change: Change::Holdings,
    })
}

/// A revoked session, and first that its token may be stolen when a used
/// refresh token was used again, or its use stopped looking like the person
/// who signed in.
fn revoked(payload: &EventData) -> Vec<SignalEvent> {
    let reason = payload.get("reason");
    let stolen = reason == Some(RevocationReason::TokenTheft.as_str())
        || reason == Some(RevocationReason::SuspectedTakeover.as_str());
    if stolen {
        return vec![SignalEvent::TokenCompromised, SignalEvent::SessionRevoked];
    }
    vec![SignalEvent::SessionRevoked]
}

/// A suspended session, and first that its token may be stolen when a
/// request broke what the session is bound to, or two uses of it could not
/// have been the same person.
fn suspended(payload: &EventData) -> Vec<SignalEvent> {
    let reason = payload.get("reason");
    let stolen = reason == Some(SuspensionReason::BindingViolation.as_str())
        || reason == Some(SuspensionReason::FastTravel.as_str());
    if stolen {
        return vec![SignalEvent::TokenCompromised, SignalEvent::SessionSuspended];
    }
    vec![SignalEvent::SessionSuspended]
}

/// A change of `change` to a credential of kind `credential`.
fn credential(credential: CredentialKind, change: CredentialChangeType) -> SignalEvent {
    SignalEvent::CredentialChanged { credential, change }
}

/// The kind of passkey `payload` names: on the device it was made on, or
/// on a key of its own. One the browser said nothing about counts as a
/// key of its own.
fn passkey(payload: &EventData) -> CredentialKind {
    if payload.get("authenticator") == Some(AuthenticatorType::Platform.as_str()) {
        return CredentialKind::Fido2Platform;
    }
    CredentialKind::Fido2Roaming
}

/// The level a session reached after proving a second factor, as
/// `payload` names it.
fn assurance(payload: &EventData) -> Option<SignalEvent> {
    let current = match AssuranceLevel::from_acr(payload.get("assurance")?)? {
        AssuranceLevel::Aal1 => SignalAssuranceLevel::Aal1,
        AssuranceLevel::Aal2 => SignalAssuranceLevel::Aal2,
        AssuranceLevel::Aal3 => SignalAssuranceLevel::Aal3,
    };
    Some(SignalEvent::AssuranceChanged { current })
}

/// What a status change means: a lock, or an account switched off or
/// waiting to be erased. Opening or reopening an account cuts no access,
/// so it is no signal.
fn status_signal(payload: &EventData) -> Option<SignalEvent> {
    let to = payload.get("status")?;
    if to == UserStatus::Locked.to_string() {
        return Some(SignalEvent::AccountLocked);
    }
    let disabled = [UserStatus::Deactivated, UserStatus::Closing];
    disabled
        .iter()
        .any(|status| to == status.to_string())
        .then_some(SignalEvent::AccountDisabled)
}

/// The tenant user `payload` references under `key`.
fn named_user(payload: &EventData, key: &str) -> Option<UserId> {
    referenced(payload, key, RefKind::USER).map(UserId::from_uuid)
}

/// The tenant user or agent `payload` references under `key`.
fn named_holder(payload: &EventData, key: &str) -> Option<SignalSubject> {
    let agent = || referenced(payload, key, RefKind::AGENT).map(AgentId::from_uuid);
    named_user(payload, key)
        .map(SignalSubject::User)
        .or_else(|| agent().map(SignalSubject::Agent))
}

/// The id of the record of `kind` that `payload` references under `key`.
fn referenced(payload: &EventData, key: &str, kind: RefKind) -> Option<Uuid> {
    let FieldValue::Reference(reference) = payload.value(key)? else {
        return None;
    };
    if reference.kind() != kind {
        return None;
    }
    Uuid::parse_str(reference.id()).ok()
}

/// The tenant user who acted: the request's caller, which the audit record
/// trusts, or else the actor the event names.
fn acting_user(event: &DomainEvent, context: &AuditContext) -> Option<UserId> {
    let actor = match (context.actor(), event.performed_by()) {
        (AuditActor::Caller(caller), _) => caller,
        (_, Fact::Known(named)) => named,
        (_, Fact::Unknown) => return None,
    };
    let ActorRef::User(user) = actor else {
        return None;
    };
    Some(*user)
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::events::data::Reference;
    use ianua_domain::shared::events::event::{DomainEventCore, TenantDomainEvent};
    use ianua_domain::types::TenantId;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::test_ctx;

    /// An event of `kind` in the test tenant, carrying `payload`.
    struct EventOf {
        kind: EventType,
        payload: EventData,
        tenant_id: TenantId,
    }

    impl DomainEventCore for EventOf {
        fn event_type(&self) -> EventType {
            self.kind
        }

        fn occurred_at(&self) -> OffsetDateTime {
            ianua_domain::shared::clock::now()
        }

        fn payload(&self) -> EventData {
            self.payload.clone()
        }
    }

    impl TenantDomainEvent for EventOf {
        fn tenant_id(&self) -> &TenantId {
            &self.tenant_id
        }
    }

    /// The event `kind` carrying `payload`, recorded with no caller.
    fn recorded(kind: impl Into<EventType>, payload: EventData) -> DomainEvent {
        DomainEvent::tenant(Box::new(EventOf {
            kind: kind.into(),
            payload,
            tenant_id: test_ctx().tenant_id(),
        }))
    }

    /// A payload naming `user` under `key`.
    fn naming(key: &str, user: UserId) -> EventData {
        EventData::new().reference(key, Reference::new(RefKind::USER, user.to_string(), "Ann"))
    }

    /// What `event` means, recorded by the platform.
    fn change_of(event: &DomainEvent) -> Option<SubjectChange> {
        user_change(event, &AuditContext::system())
    }

    /// The signals `event` means about `user`.
    fn signals_about(event: &DomainEvent, user: UserId) -> Vec<SignalEvent> {
        let Some(SubjectChange {
            subject,
            change: Change::Signals(signals),
        }) = change_of(event)
        else {
            panic!("expected signals");
        };
        assert_eq!(subject, SignalSubject::User(user));
        signals
    }

    /// Pat's workflow reports Ann's risk as high. Receivers are told Ann's
    /// risk level changed to high.
    #[test]
    fn a_reported_risk_is_signalled_about_the_person_reported() {
        let ann = UserId::new();
        let event = recorded(
            SignalsEvent::SignalReported,
            naming("user", ann)
                .field("signal", "risk_level")
                .field("level", "HIGH"),
        );

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::RiskLevelChanged {
                current: ianua_domain::domains::signals::signal::SignalRiskLevel::High
            }]
        );
    }

    /// An admin revokes Ann's session. Receivers are told the session was
    /// revoked, about Ann, not about the admin.
    #[test]
    fn a_revoked_session_is_signalled_about_its_holder() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::SessionRevoked,
            naming("user", ann).field("reason", RevocationReason::AdminAction.as_str()),
        )
        .with_actor(ActorRef::User(UserId::new()));

        assert_eq!(signals_about(&event, ann), [SignalEvent::SessionRevoked]);
    }

    /// Ann's rotated refresh token is used again, and her session is
    /// revoked. A stream that asked for stolen tokens hears that first; one
    /// that asked only for revoked sessions still hears the session ended.
    #[test]
    fn a_reused_refresh_token_goes_out_as_a_stolen_token_then_a_revoked_session() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::SessionRevoked,
            naming("user", ann).field("reason", RevocationReason::TokenTheft.as_str()),
        );

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::TokenCompromised, SignalEvent::SessionRevoked]
        );
    }

    /// Ann logs out. The record names her only as its actor, and receivers
    /// are told her session was revoked.
    #[test]
    fn a_logout_is_signalled_about_the_person_who_logged_out() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::SessionRevoked,
            EventData::new().field("reason", RevocationReason::Logout.as_str()),
        )
        .with_actor(ActorRef::User(ann));

        assert_eq!(signals_about(&event, ann), [SignalEvent::SessionRevoked]);
    }

    /// A request on Ann's session breaks what the session is bound to, and
    /// it is suspended. Receivers hear its token may be stolen, or else
    /// that it was suspended.
    #[test]
    fn a_binding_violation_goes_out_as_a_stolen_token_then_a_suspension() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::SessionSuspended,
            naming("user", ann).field("reason", SuspensionReason::BindingViolation.as_str()),
        );

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::TokenCompromised, SignalEvent::SessionSuspended]
        );
    }

    /// Ann changes her password. Receivers hear her password was updated.
    #[test]
    fn a_password_change_is_a_credential_change() {
        let ann = UserId::new();
        let event = recorded(AuthenticationEvent::PasswordChanged, EventData::new())
            .with_actor(ActorRef::User(ann));

        assert_eq!(
            signals_about(&event, ann),
            [credential(
                CredentialKind::Password,
                CredentialChangeType::Update
            )]
        );
    }

    /// An admin removes Ann's laptop passkey. Receivers hear Ann lost a
    /// passkey kept on her device, about Ann, though the admin acted.
    #[test]
    fn a_passkey_removed_by_an_admin_is_signalled_about_its_holder() {
        let ann = UserId::new();
        let payload =
            naming("user", ann).field("authenticator", AuthenticatorType::Platform.as_str());
        let event = recorded(AuthenticationEvent::PasskeyRemoved, payload)
            .with_actor(ActorRef::User(UserId::new()));

        assert_eq!(
            signals_about(&event, ann),
            [credential(
                CredentialKind::Fido2Platform,
                CredentialChangeType::Delete
            )]
        );
    }

    /// Ann turns her authenticator off. Receivers hear she removed an app
    /// factor.
    #[test]
    fn a_factor_turned_off_is_a_credential_change() {
        let ann = UserId::new();
        let event = recorded(AuthenticationEvent::MfaUnenrolled, EventData::new())
            .with_actor(ActorRef::User(ann));

        assert_eq!(
            signals_about(&event, ann),
            [credential(
                CredentialKind::App,
                CredentialChangeType::Delete
            )]
        );
    }

    /// A network lockout naming Ann produces no account-lock signal for receivers.
    #[test]
    fn a_networks_lockout_locks_no_account_at_receivers() {
        let ann = UserId::new();
        let event = recorded(AuthenticationEvent::AccountLockedOut, naming("user", ann));

        assert!(change_of(&event).is_none());
    }

    /// A lockout naming only an email produces no signal, even when its actor is a user.
    #[test]
    fn a_lockout_of_no_account_is_no_signal() {
        let event = recorded(
            AuthenticationEvent::AccountLockedOut,
            EventData::new().field("email", "nobody@acme.test"),
        )
        .with_actor(ActorRef::User(UserId::new()));

        assert!(change_of(&event).is_none());
    }

    /// Ann signs in with a password found in a breach. Receivers hear her
    /// password is compromised.
    #[test]
    fn a_breached_password_is_a_compromised_credential() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::PasswordBreachDetected,
            naming("user", ann),
        );

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::CredentialCompromised {
                credential: CredentialKind::Password
            }]
        );
    }

    /// Ann proves her authenticator on a session. Receivers hear the
    /// session now stands at AAL2.
    #[test]
    fn a_proved_factor_raises_the_sessions_assurance() {
        let ann = UserId::new();
        let event = recorded(
            AuthenticationEvent::MfaVerified,
            EventData::new().field("assurance", AssuranceLevel::Aal2.acr()),
        )
        .with_actor(ActorRef::User(ann));

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::AssuranceChanged {
                current: SignalAssuranceLevel::Aal2
            }]
        );
    }

    /// An admin locks Ann's account, and later switches it off. Receivers
    /// hear it locked, then disabled.
    #[test]
    fn a_lock_or_a_switch_off_is_signalled() {
        let ann = UserId::new();
        let locked = recorded(
            IdentityEvent::UserStatusChanged,
            naming("user", ann).change("status", "active", UserStatus::Locked.to_string()),
        );
        let switched_off = recorded(
            IdentityEvent::UserStatusChanged,
            naming("user", ann).change("status", "locked", UserStatus::Deactivated.to_string()),
        );

        assert_eq!(signals_about(&locked, ann), [SignalEvent::AccountLocked]);
        assert_eq!(
            signals_about(&switched_off, ann),
            [SignalEvent::AccountDisabled]
        );
    }

    /// An admin unlocks Ann's account. That cuts no access, so it is no
    /// signal.
    #[test]
    fn an_unlocked_account_is_no_signal() {
        let event = recorded(
            IdentityEvent::UserStatusChanged,
            naming("user", UserId::new()).change("status", "locked", "active"),
        );

        assert!(change_of(&event).is_none());
    }

    /// An admin resets Ann's password. Receivers hear her password changed.
    #[test]
    fn an_admin_password_reset_is_a_credential_change() {
        let ann = UserId::new();
        let event = recorded(IdentityEvent::PasswordReset, naming("user", ann));

        assert_eq!(
            signals_about(&event, ann),
            [credential(
                CredentialKind::Password,
                CredentialChangeType::Update
            )]
        );
    }

    /// Ann's address changes. Receivers that key accounts by it hear it
    /// changed.
    #[test]
    fn a_changed_address_is_a_changed_identifier() {
        let ann = UserId::new();
        let event = recorded(IdentityEvent::EmailChanged, naming("user", ann));

        assert_eq!(signals_about(&event, ann), [SignalEvent::IdentifierChanged]);
    }

    /// Ann's account is deleted. A stream that asked for purged accounts
    /// hears that; one that asked only for disabled ones still hears it.
    #[test]
    fn a_deleted_account_goes_out_as_purged_then_disabled() {
        let ann = UserId::new();
        let event = recorded(IdentityEvent::UserDeleted, naming("user", ann));

        assert_eq!(
            signals_about(&event, ann),
            [SignalEvent::AccountPurged, SignalEvent::AccountDisabled]
        );
    }

    /// A password-reset event without an affected account produces no signal
    /// about the user who acted.
    #[test]
    fn an_identity_event_naming_no_account_is_no_signal() {
        let event = recorded(IdentityEvent::PasswordReset, EventData::new())
            .with_actor(ActorRef::User(UserId::new()));

        assert!(change_of(&event).is_none());
    }

    /// An admin gives Ann a role, naming herself as the granter. The change
    /// is to what Ann holds, not to the admin.
    #[test]
    fn a_role_given_changes_what_its_holder_holds() {
        let (ann, admin) = (UserId::new(), UserId::new());
        let payload = naming("holder", ann).reference(
            "granted_by",
            Reference::new(RefKind::USER, admin.to_string(), "Admin"),
        );
        let event = recorded(AuthorizationEvent::RoleAssigned, payload);

        assert_eq!(
            change_of(&event),
            Some(SubjectChange {
                subject: SignalSubject::User(ann),
                change: Change::Holdings,
            })
        );
    }

    /// The billing agent is added to a group. What the agent holds changed.
    #[test]
    fn an_agent_joining_a_group_changes_what_it_holds() {
        let agent = AgentId::new();
        let payload = EventData::new().reference(
            "member",
            Reference::new(RefKind::AGENT, agent.to_string(), "billing agent"),
        );
        let event = recorded(AuthorizationEvent::GroupMemberAdded, payload);

        assert_eq!(
            change_of(&event).map(|change| change.subject),
            Some(SignalSubject::Agent(agent))
        );
    }

    /// Ann gives herself break-glass access. What she holds changed.
    #[test]
    fn break_glass_changes_what_its_holder_holds() {
        let ann = UserId::new();
        let event = recorded(AuthenticationEvent::BreakGlassGranted, naming("user", ann));

        assert_eq!(
            change_of(&event).map(|change| change.change),
            Some(Change::Holdings)
        );
    }

    /// A sign-in succeeded. That is nothing a receiver must act on, so it
    /// is no signal.
    #[test]
    fn a_sign_in_is_no_signal() {
        let event = recorded(
            AuthenticationEvent::LoginSucceeded,
            naming("user", UserId::new()),
        );

        assert!(change_of(&event).is_none());
    }
}
