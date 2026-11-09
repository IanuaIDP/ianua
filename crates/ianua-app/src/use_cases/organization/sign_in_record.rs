//! The audit record of an org sign-in, shared by the password and passkey
//! paths so both read the same in the audit log.

use ianua_domain::domains::organization::events::access::{
    OrgLoginFailed, OrgLoginSucceeded, OrgSignInMethod, OrgSignInRefusal,
};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::ActorRef;

use crate::error::AppError;

/// The record of a sign-in attempt for `org_user`: done by them when it
/// worked, by the system when it was refused.
///
/// `None` when the attempt failed for a reason that says nothing about the
/// account, such as a storage error: recording it as a refused sign-in would
/// blame the person for an outage.
pub(crate) fn org_sign_in_record<T>(
    org_user: &OrgUser,
    method: OrgSignInMethod,
    outcome: &Result<T, AppError>,
) -> Option<DomainEvent> {
    let Err(error) = outcome else {
        return Some(
            OrgLoginSucceeded::observed(org_user, method)
                .with_actor(ActorRef::OrgUser(*org_user.id())),
        );
    };
    refusal_of(error).map(|reason| {
        OrgLoginFailed::observed(org_user, method, reason).with_actor(ActorRef::System)
    })
}

/// Why a refused sign-in is recorded as refused, or `None` when the error is
/// not a refusal.
fn refusal_of(error: &AppError) -> Option<OrgSignInRefusal> {
    match error {
        AppError::NotFound(_) | AppError::Unauthenticated => {
            Some(OrgSignInRefusal::InvalidCredentials)
        }
        AppError::Forbidden(_) => Some(OrgSignInRefusal::Refused),
        AppError::AccountLocked(_) => Some(OrgSignInRefusal::Locked),
        AppError::EmailNotVerified => Some(OrgSignInRefusal::EmailNotVerified),
        AppError::TooManyRequests(_) => Some(OrgSignInRefusal::RateLimited),
        AppError::TenantUnavailable(_) => Some(OrgSignInRefusal::TenantUnavailable),
        AppError::Domain(_)
        | AppError::Conflict(_)
        | AppError::StepUpRequired
        | AppError::LinkExpired(_)
        | AppError::Busy
        | AppError::ChallengeRequired(_)
        | AppError::Internal(_)
        | AppError::Upstream(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::event_type::{EventType, OrganizationEvent};
    use ianua_domain::types::{Fact, OrganizationId};

    use super::*;
    use crate::test_support::organization::test_org_user;

    fn ada() -> OrgUser {
        test_org_user(OrganizationId::new(), "ada@acme.com", OrgRole::Member)
    }

    fn reason_of(event: &DomainEvent) -> Option<String> {
        match event.payload().value("reason") {
            Some(FieldValue::Text(reason)) => Some(reason.clone()),
            _ => None,
        }
    }

    /// Ada signs in with her password. The record says she signed in, by
    /// password, and names her as the one who did.
    #[test]
    fn a_sign_in_is_recorded_as_done_by_the_member() {
        let ada = ada();

        let event =
            org_sign_in_record(&ada, OrgSignInMethod::Password, &Ok::<(), AppError>(())).unwrap();

        assert_eq!(
            event.event_type(),
            EventType::from(OrganizationEvent::OrgLoginSucceeded)
        );
        assert_eq!(event.organization_id(), Some(ada.organization_id()));
        assert!(matches!(
            event.performed_by(),
            Fact::Known(ActorRef::OrgUser(id)) if id == ada.id()
        ));
    }

    /// Ada types the wrong password. The record says her sign-in was refused
    /// for invalid credentials, without saying which half was wrong, and is
    /// not attributed to her.
    #[test]
    fn a_wrong_credential_is_recorded_as_invalid_credentials() {
        let outcome: Result<(), AppError> = Err(AppError::Unauthenticated);

        let event = org_sign_in_record(&ada(), OrgSignInMethod::Password, &outcome).unwrap();

        assert_eq!(
            event.event_type(),
            EventType::from(OrganizationEvent::OrgLoginFailed)
        );
        assert_eq!(reason_of(&event).as_deref(), Some("invalid_credentials"));
        assert!(matches!(
            event.performed_by(),
            Fact::Known(ActorRef::System)
        ));
    }

    /// Ada's account is locked after too many tries. Her passkey sign-in is
    /// recorded as refused because the account is locked.
    #[test]
    fn a_locked_account_is_recorded_as_locked() {
        let outcome: Result<(), AppError> = Err(AppError::AccountLocked("locked".to_owned()));

        let event = org_sign_in_record(&ada(), OrgSignInMethod::Passkey, &outcome).unwrap();

        assert_eq!(reason_of(&event).as_deref(), Some("locked"));
    }

    /// Ada's sign-in fails because the database is down. Nothing is
    /// recorded against her account, since the outage was not her doing.
    #[test]
    fn an_outage_is_not_recorded_as_a_refused_sign_in() {
        let outcome: Result<(), AppError> = Err(AppError::internal(DomainError::infra_msg(
            "database unreachable",
        )));

        let event = org_sign_in_record(&ada(), OrgSignInMethod::Password, &outcome);

        assert!(event.is_none());
    }
}
