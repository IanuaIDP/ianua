//! How a settled password sign-in attempt is told and recorded: the caller's
//! answer, and the events the audit trail keeps, for a kept sign-in and for
//! each refusal alike.

use std::time::Instant;

use ianua_domain::domains::authentication::operations::password_login::{
    LoginFailure, LoginResult,
};
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;

use crate::auditor::raised_by_holder;
use crate::error::AppError;
use crate::services::authentication::refused::invalid_credentials;
use crate::services::authentication::sign_in_steps::no_factor_to_prove_with;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::password::sign_in::login::{LoginOutcome, LoginSuccess};
use crate::use_cases::authentication::timing::elapsed_millis;

/// A settled attempt: what the caller is told, and what is recorded.
pub(in crate::use_cases::authentication::password) struct Settlement {
    /// What the caller is told.
    pub(in crate::use_cases::authentication::password) result: Result<LoginOutcome, AppError>,
    /// What the audit trail keeps, whatever the caller is told.
    pub(in crate::use_cases::authentication::password) events: Vec<DomainEvent>,
    /// Whether it counts against the tenant's count of failures.
    pub(in crate::use_cases::authentication::password) tally: Tally,
}

/// Whether a settled attempt counts against the tenant's count of failures.
///
/// Only a guess that missed counts: a wrong password, or an address with no
/// account. A lockout, a refused risk or an unconfirmed address is not a
/// miss, and a refusal before the password, by the hashing cap or the
/// challenge, never settles at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::authentication::password) enum Tally {
    /// A wrong password or an unknown address.
    Failure,
    /// Anything else.
    NotAFailure,
}

impl Settlement {
    /// The settlement of an attempt the domain refused.
    pub(in crate::use_cases::authentication::password) fn refused(failure: LoginFailure) -> Self {
        let tally = match failure {
            LoginFailure::InvalidCredentials { .. } => Tally::Failure,
            _ => Tally::NotAFailure,
        };
        let (error, events) = refusal(failure);
        Self {
            result: Err(error),
            events,
            tally,
        }
    }

    /// What the caller is told about a kept sign-in in `tenant`, and what
    /// is recorded: the sign-in itself first, by the person, timed from
    /// `started`, then what the attempt raised.
    pub(in crate::use_cases::authentication::password) fn signed_in(
        result: LoginResult,
        tenant: &ScopedTenant,
        started: Instant,
    ) -> Self {
        let LoginResult {
            mut session,
            refresh_token,
            second_factor,
            events,
            ..
        } = result;
        session.record_sign_in(elapsed_millis(started));
        let holder = *session.user_id();
        let recorded = raised_by_holder(&mut session, tenant, holder)
            .into_iter()
            .chain(events)
            .collect();
        Self {
            result: Ok(LoginOutcome::SignedIn(LoginSuccess {
                session_id: *session.id(),
                user_id: *session.user_id(),
                refresh_token,
                second_factor,
            })),
            events: recorded,
            tally: Tally::NotAFailure,
        }
    }
}

/// What the caller is told about a refused attempt, and what is recorded.
///
/// A network locked out of the account is told exactly what a wrong
/// password is, so the lockout tells a guesser nothing: not that the
/// address has an account, nor that guessing from there has stopped
/// counting.
fn refusal(failure: LoginFailure) -> (AppError, Vec<DomainEvent>) {
    match failure {
        LoginFailure::AccountLocked { events, .. }
        | LoginFailure::InvalidCredentials { events } => (invalid_credentials(), events),
        LoginFailure::AccountNotActive { events } => (
            AppError::Forbidden(message!(
                "authentication-this-account-has-not-finished-joining",
                "this account has not finished joining"
            )),
            events,
        ),
        LoginFailure::EmailNotVerified { events } => (AppError::EmailNotVerified, events),
        LoginFailure::RiskDenied { events } => (
            AppError::Forbidden(message!(
                "authentication-risk-level-too-high",
                "risk level too high"
            )),
            events,
        ),
        LoginFailure::NothingToProveWith { events } => (no_factor_to_prove_with(), events),
        LoginFailure::MethodNotAdmitted { events } => (
            AppError::Forbidden(message!(
                "authentication-this-workspace-does-not-accept-a",
                "this workspace does not accept a password alone"
            )),
            events,
        ),
        LoginFailure::Unavailable(source) => (AppError::from_domain(source), Vec::new()),
    }
}
