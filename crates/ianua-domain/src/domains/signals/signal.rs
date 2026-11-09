//! CAEP/SSE security signals, pushed to relying parties as events happen.
//!
//! Based on:
//! - CAEP (Continuous Access Evaluation Protocol)
//! - SSE (Shared Signals and Events Framework)
//! - SET (Security Event Token, RFC 8417)

use time::OffsetDateTime;

use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{AgentId, PermissionName, SignalId, TenantId, UserId};

/// Whom a security signal is about: a person's account or an agent.
///
/// Signals sits below the agents context, so an agent is named only by its
/// id. A receiver that let an agent in learns it was suspended or had its
/// credential revoked the same way it learns about a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalSubject {
    /// A user of the tenant.
    User(UserId),
    /// An agent of the tenant.
    Agent(AgentId),
}

/// The type of security signal being emitted.
///
/// Each type maps to a Shared Signals event type, see
/// [`as_urn`](Self::as_urn). Relying parties use it to decide whether to
/// revoke tokens, ask the user to sign in again, or block access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SecuritySignalType {
    /// A session was revoked. Relying parties should drop any cached tokens
    /// for it.
    SessionRevoked,

    /// A session was suspended. Relying parties should block requests until
    /// it is resumed or revoked.
    SessionSuspended,

    /// A password, passkey or other credential of the user changed. Relying
    /// parties may ask the user to sign in again.
    CredentialChanged,

    /// The user's account was locked, after too many failures or by an
    /// admin. Relying parties should refuse every request for this user.
    AccountLocked,

    /// The user's account was deactivated or deleted. Relying parties should
    /// revoke all access for good.
    AccountDisabled,

    /// A role was added to or removed from the user. Relying parties should
    /// check what the user may do again.
    PermissionsChanged,

    /// A device stopped being trusted. Relying parties should end sessions
    /// from it.
    DeviceCompromised,

    /// A session binding was broken, so the session may be stolen. Relying
    /// parties should revoke its tokens.
    TokenCompromised,

    /// The user's risk level changed. Relying parties should ask for a
    /// stronger sign-in or block access as needed.
    RiskLevelChanged,

    /// A session proved a second factor, so it now stands at a higher
    /// assurance level. Relying parties may let it reach what needs one.
    AssuranceChanged,

    /// A credential of the user is known to be in other hands, such as a
    /// password found in a breach. Relying parties should stop trusting it.
    CredentialCompromised,

    /// The address the user is known by changed. Relying parties that key
    /// accounts by it should not hand the old one to someone else.
    IdentifierChanged,

    /// The user's account was deleted for good. Relying parties should
    /// delete or close what they keep for it.
    AccountPurged,
}

impl SecuritySignalType {
    /// The Shared Signals event type a receiver acts on for this signal.
    ///
    /// It is always a name CAEP 1.0 or RISC defines. A receiver ignores a
    /// name it does not know, and an ignored revocation leaves the session
    /// open. Where the specifications have no exact name, the signal goes out
    /// as the nearest one that still cuts access:
    ///
    /// - a suspended session or a stolen token as a revoked session
    /// - a locked account as a disabled one
    // One arm per signal, with no catch-all: a new signal must name its
    // event type's URN before it builds. Splitting the table would bring a
    // catch-all back.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn as_urn(&self) -> &'static str {
        match self {
            Self::SessionRevoked | Self::SessionSuspended | Self::TokenCompromised => {
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            }
            Self::CredentialChanged => {
                "https://schemas.openid.net/secevent/caep/event-type/credential-change"
            }
            Self::AccountLocked | Self::AccountDisabled => {
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
            }
            Self::PermissionsChanged => {
                "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
            }
            Self::DeviceCompromised => {
                "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
            }
            Self::RiskLevelChanged => {
                "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
            }
            Self::AssuranceChanged => {
                "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
            }
            Self::CredentialCompromised => {
                "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
            }
            Self::IdentifierChanged => {
                "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
            }
            Self::AccountPurged => {
                "https://schemas.openid.net/secevent/risc/event-type/account-purged"
            }
        }
    }
}

/// What a security signal reports, with what its event type requires.
///
/// Each kind carries the fields the specification makes mandatory for it,
/// so a signal cannot be raised that a receiver would have to reject.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalEvent {
    /// A session was revoked.
    SessionRevoked,
    /// A session was suspended.
    SessionSuspended,
    /// One of the user's credentials changed.
    CredentialChanged {
        /// Which kind of credential.
        credential: CredentialKind,
        /// What happened to it.
        change: CredentialChangeType,
    },
    /// The account was locked.
    AccountLocked,
    /// The account was deactivated or deleted.
    AccountDisabled,
    /// The user's permissions changed.
    PermissionsChanged {
        /// The permissions the user holds now, as tokens name them.
        permissions: Vec<PermissionName>,
    },
    /// A device the user signed in from stopped being trusted.
    DeviceCompromised,
    /// A session binding was broken, so its token may be in other hands.
    TokenCompromised,
    /// The user's risk level changed.
    RiskLevelChanged {
        /// The level now.
        current: SignalRiskLevel,
    },
    /// A session reached a higher assurance level.
    AssuranceChanged {
        /// The level the session stands at now.
        current: SignalAssuranceLevel,
    },
    /// One of the user's credentials is known to be in other hands.
    CredentialCompromised {
        /// Which kind of credential.
        credential: CredentialKind,
    },
    /// The address the user is known by changed.
    IdentifierChanged,
    /// The account was deleted for good.
    AccountPurged,
}

impl SignalEvent {
    /// The type streams subscribe to.
    #[must_use]
    pub fn signal_type(&self) -> SecuritySignalType {
        match self {
            Self::AssuranceChanged { .. } => SecuritySignalType::AssuranceChanged,
            Self::CredentialCompromised { .. } => SecuritySignalType::CredentialCompromised,
            Self::IdentifierChanged => SecuritySignalType::IdentifierChanged,
            Self::AccountPurged => SecuritySignalType::AccountPurged,
            Self::SessionRevoked => SecuritySignalType::SessionRevoked,
            Self::SessionSuspended => SecuritySignalType::SessionSuspended,
            Self::CredentialChanged { .. } => SecuritySignalType::CredentialChanged,
            Self::AccountLocked => SecuritySignalType::AccountLocked,
            Self::AccountDisabled => SecuritySignalType::AccountDisabled,
            Self::PermissionsChanged { .. } => SecuritySignalType::PermissionsChanged,
            Self::DeviceCompromised => SecuritySignalType::DeviceCompromised,
            Self::TokenCompromised => SecuritySignalType::TokenCompromised,
            Self::RiskLevelChanged { .. } => SecuritySignalType::RiskLevelChanged,
        }
    }
}

/// A credential kind, as CAEP's `credential_type` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialKind {
    /// The account's reusable secret, as named in a credential-change event.
    Password,
    /// A passkey kept on the device it was made on.
    Fido2Platform,
    /// A passkey on a separate security key.
    Fido2Roaming,
    /// A client certificate.
    X509,
    /// An authenticator app.
    App,
}

impl CredentialKind {
    /// The specification's name for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Fido2Platform => "fido2-platform",
            Self::Fido2Roaming => "fido2-roaming",
            Self::X509 => "x509",
            Self::App => "app",
        }
    }
}

/// What happened to a credential, as CAEP's `change_type` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CredentialChangeType {
    /// It was added.
    Create,
    /// It was revoked.
    Revoke,
    /// It was replaced.
    Update,
    /// It was removed.
    Delete,
}

impl CredentialChangeType {
    /// The specification's name for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Revoke => "revoke",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// A risk level, as CAEP's `current_level` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalRiskLevel {
    /// The least severe CAEP risk category reported to receivers.
    Low,
    /// The intermediate CAEP risk category reported to receivers.
    Medium,
    /// The most severe CAEP risk category reported to receivers.
    High,
}

impl SignalRiskLevel {
    /// The specification's name for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

/// An authentication assurance level, as CAEP's `current_level` spells it
/// in the `NIST-AAL` namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalAssuranceLevel {
    /// One factor.
    Aal1,
    /// Two factors.
    Aal2,
    /// Two factors, one of them bound to hardware.
    Aal3,
}

impl SignalAssuranceLevel {
    /// The namespace the level is written in.
    pub const NAMESPACE: &'static str = "NIST-AAL";

    /// The specification's name for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aal1 => "nist-aal1",
            Self::Aal2 => "nist-aal2",
            Self::Aal3 => "nist-aal3",
        }
    }
}

/// A security signal ready to be pushed to subscribed receivers.
///
/// The app layer raises one when something happens that relying parties
/// must react to. The adapter delivers it as a Security Event Token
/// (RFC 8417) to each stream's push endpoint.
#[derive(Debug, Clone)]
pub struct SecuritySignal {
    id: SignalId,
    tenant_id: TenantId,
    subject: SignalSubject,
    event: SignalEvent,
    occurred_at: OffsetDateTime,
}

/// A security signal as kept for a later try, read back through
/// [`SecuritySignal::reconstitute`].
pub struct SecuritySignalRow {
    /// The id it was raised under.
    pub id: SignalId,
    /// The tenant it happened in.
    pub tenant_id: TenantId,
    /// The user or agent it concerns.
    pub subject: SignalSubject,
    /// What happened.
    pub event: SignalEvent,
    /// When it happened.
    pub occurred_at: OffsetDateTime,
}

/// What a security signal reports and about whom.
pub struct NewSecuritySignal {
    /// The tenant it happened in.
    pub tenant_id: TenantId,
    /// The user or agent it concerns.
    pub subject: SignalSubject,
    /// What happened.
    pub event: SignalEvent,
    /// When it happened.
    pub occurred_at: OffsetDateTime,
}

impl SecuritySignal {
    /// Creates a new security signal.
    ///
    /// An agent signs in from no device of its own, proves no second factor
    /// and is known by no address, and CAEP names no risk level for one, so
    /// none of those is reported about an agent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a compromised device, a risk
    ///   level, an assurance level or a changed address is reported about
    ///   an agent.
    pub fn new(signal: NewSecuritySignal) -> Result<Self, DomainError> {
        let NewSecuritySignal {
            tenant_id,
            subject,
            event,
            occurred_at,
        } = signal;
        ensure_fits_the_subject(&subject, &event)?;
        Ok(Self {
            id: SignalId::new(),
            tenant_id,
            subject,
            event,
            occurred_at,
        })
    }

    /// Rebuilds a signal as it was kept for a later try, with the id it was
    /// raised under, so every try carries the same token id and a receiver
    /// drops a repeat.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the kept signal reports
    ///   something about an agent that [`new`](Self::new) refuses.
    pub fn reconstitute(row: SecuritySignalRow) -> Result<Self, DomainError> {
        if ensure_fits_the_subject(&row.subject, &row.event).is_err() {
            return Err(DomainError::corrupt_row(
                "security signal",
                "an event that cannot be about its subject",
            ));
        }
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            event: row.event,
            occurred_at: row.occurred_at,
        })
    }

    /// Unique signal identifier.
    #[must_use]
    pub fn id(&self) -> &SignalId {
        &self.id
    }

    /// The tenant this signal originated from.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The user or agent it concerns.
    #[must_use]
    pub fn subject(&self) -> &SignalSubject {
        &self.subject
    }

    /// What happened.
    #[must_use]
    pub fn event(&self) -> &SignalEvent {
        &self.event
    }

    /// The type streams subscribe to.
    #[must_use]
    pub fn signal_type(&self) -> SecuritySignalType {
        self.event.signal_type()
    }

    /// When the underlying event occurred.
    #[must_use]
    pub fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
}

/// Refuses an event that cannot be about `subject`.
///
/// # Errors
///
/// - [`DomainError::Validation`] when a compromised device, a risk level,
///   an assurance level or a changed address is reported about an agent.
fn ensure_fits_the_subject(
    subject: &SignalSubject,
    event: &SignalEvent,
) -> Result<(), DomainError> {
    let SignalSubject::Agent(_) = subject else {
        return Ok(());
    };
    match event {
        SignalEvent::DeviceCompromised
        | SignalEvent::RiskLevelChanged { .. }
        | SignalEvent::AssuranceChanged { .. }
        | SignalEvent::IdentifierChanged => Err(DomainError::invalid(message!(
            "signals-a-device-a-risk-level-an",
            "a device, a risk level, an assurance level or an address is reported about people, not agents"
        ))),
        SignalEvent::SessionRevoked
        | SignalEvent::SessionSuspended
        | SignalEvent::CredentialChanged { .. }
        | SignalEvent::CredentialCompromised { .. }
        | SignalEvent::AccountLocked
        | SignalEvent::AccountDisabled
        | SignalEvent::AccountPurged
        | SignalEvent::PermissionsChanged { .. }
        | SignalEvent::TokenCompromised => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signal about a fresh user, raised now for `event`.
    fn about_a_user(event: SignalEvent) -> NewSecuritySignal {
        NewSecuritySignal {
            tenant_id: TenantId::new(),
            subject: SignalSubject::User(UserId::new()),
            event,
            occurred_at: crate::shared::clock::now(),
        }
    }

    /// A signal is raised for a password update. It keeps that event and
    /// reports the credential-changed type that streams subscribe to.
    #[test]
    fn a_signal_keeps_what_it_was_raised_with() {
        let event = SignalEvent::CredentialChanged {
            credential: CredentialKind::Password,
            change: CredentialChangeType::Update,
        };

        let signal = SecuritySignal::new(about_a_user(event.clone())).unwrap();

        assert_eq!(signal.signal_type(), SecuritySignalType::CredentialChanged);
        assert_eq!(signal.event(), &event);
    }

    /// Ann suspends the billing agent. The signal names the agent, so a
    /// receiver that let the agent in drops its tokens too.
    #[test]
    fn a_signal_may_be_about_an_agent() {
        let agent = AgentId::new();

        let signal = SecuritySignal::new(NewSecuritySignal {
            subject: SignalSubject::Agent(agent),
            ..about_a_user(SignalEvent::AccountDisabled)
        })
        .unwrap();

        assert_eq!(signal.subject(), &SignalSubject::Agent(agent));
    }

    /// A compromised device, a risk level, an assurance level or a changed
    /// address reported about an agent is refused. An agent has no device
    /// of its own, proves no second factor and is known by no address, and
    /// CAEP names no risk level for one, so a receiver would have to reject
    /// it.
    #[test]
    fn a_signal_only_a_person_can_be_about_is_refused_for_an_agent() {
        for event in [
            SignalEvent::DeviceCompromised,
            SignalEvent::RiskLevelChanged {
                current: SignalRiskLevel::High,
            },
            SignalEvent::AssuranceChanged {
                current: SignalAssuranceLevel::Aal2,
            },
            SignalEvent::IdentifierChanged,
        ] {
            let result = SecuritySignal::new(NewSecuritySignal {
                subject: SignalSubject::Agent(AgentId::new()),
                ..about_a_user(event)
            });

            assert!(matches!(result, Err(DomainError::Validation(_))));
        }
    }

    /// Every signal type maps to one of ten event names CAEP or RISC define.
    /// A receiver drops a name it does not know, which would leave a revoked
    /// session open.
    #[test]
    fn every_signal_goes_out_under_a_name_the_specifications_define() {
        const DEFINED: [&str; 10] = [
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            "https://schemas.openid.net/secevent/caep/event-type/credential-change",
            "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
            "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
            "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
            "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
            "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
            "https://schemas.openid.net/secevent/risc/event-type/account-purged",
            "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
            "https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
        ];
        let types = [
            SecuritySignalType::SessionRevoked,
            SecuritySignalType::SessionSuspended,
            SecuritySignalType::CredentialChanged,
            SecuritySignalType::AccountLocked,
            SecuritySignalType::AccountDisabled,
            SecuritySignalType::PermissionsChanged,
            SecuritySignalType::DeviceCompromised,
            SecuritySignalType::TokenCompromised,
            SecuritySignalType::RiskLevelChanged,
            SecuritySignalType::AssuranceChanged,
            SecuritySignalType::CredentialCompromised,
            SecuritySignalType::IdentifierChanged,
            SecuritySignalType::AccountPurged,
        ];
        for t in types {
            assert!(DEFINED.contains(&t.as_urn()), "{t:?}");
        }
    }

    /// Three signal types are written to JSON and read back under their
    /// variant names. Renaming a variant fails here before it breaks stored
    /// rows.
    #[cfg(feature = "serde")]
    #[test]
    fn security_signal_type_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&SecuritySignalType::SessionRevoked).unwrap(),
            r#""SessionRevoked""#
        );
        assert_eq!(
            serde_json::to_string(&SecuritySignalType::AccountLocked).unwrap(),
            r#""AccountLocked""#
        );
        assert_eq!(
            serde_json::to_string(&SecuritySignalType::RiskLevelChanged).unwrap(),
            r#""RiskLevelChanged""#
        );
        assert_eq!(
            serde_json::from_str::<SecuritySignalType>(r#""SessionRevoked""#).unwrap(),
            SecuritySignalType::SessionRevoked
        );
        assert_eq!(
            serde_json::from_str::<SecuritySignalType>(r#""AccountLocked""#).unwrap(),
            SecuritySignalType::AccountLocked
        );
        assert_eq!(
            serde_json::from_str::<SecuritySignalType>(r#""RiskLevelChanged""#).unwrap(),
            SecuritySignalType::RiskLevelChanged
        );
    }

    /// A signal is raised in Acme. It names Acme as its tenant and gets a
    /// fresh id, so it goes only to Acme's streams and can be told apart.
    #[test]
    fn a_signal_carries_its_own_id_and_names_its_tenant() {
        let tenant = TenantId::new();

        let signal = SecuritySignal::new(NewSecuritySignal {
            tenant_id: tenant,
            ..about_a_user(SignalEvent::SessionRevoked)
        })
        .unwrap();

        assert_eq!(*signal.tenant_id(), tenant);
        assert!(!signal.id().as_uuid().is_nil());
    }

    /// A revoked session kept for a retry reads back under the id it was
    /// raised with, so the retry carries the same token id.
    #[test]
    fn a_kept_signal_reads_back_under_its_id() {
        let raised = SecuritySignal::new(about_a_user(SignalEvent::SessionRevoked)).unwrap();

        let read = SecuritySignal::reconstitute(SecuritySignalRow {
            id: *raised.id(),
            tenant_id: *raised.tenant_id(),
            subject: *raised.subject(),
            event: raised.event().clone(),
            occurred_at: raised.occurred_at(),
        })
        .unwrap();

        assert_eq!(read.id(), raised.id());
        assert_eq!(read.event(), raised.event());
    }

    /// A kept signal reporting a risk level about an agent is refused as
    /// corrupt: no signal like it could have been raised.
    #[test]
    fn a_kept_signal_that_cannot_be_about_its_agent_is_refused() {
        let row = SecuritySignalRow {
            id: SignalId::new(),
            tenant_id: TenantId::new(),
            subject: SignalSubject::Agent(AgentId::new()),
            event: SignalEvent::RiskLevelChanged {
                current: SignalRiskLevel::High,
            },
            occurred_at: crate::shared::clock::now(),
        };

        let result = SecuritySignal::reconstitute(row);

        assert!(crate::shared::model::row_check::refused_as_corrupt(&result));
    }
}
