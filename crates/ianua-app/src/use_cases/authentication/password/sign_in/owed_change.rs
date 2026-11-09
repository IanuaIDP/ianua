//! What a proved password that must change does to its sign-in: no session
//! opens, and the change it owes begins instead, its token handed back or
//! mailed as the proof it asks decides.

use ianua_domain::domains::authentication::credentials::password_rules::ChangeReason;
use ianua_domain::domains::authentication::operations::password_login::LoginResult;

use crate::error::AppError;
use crate::services::lookup::existing_user;
use crate::use_cases::authentication::password::sign_in::due::{DueChange, ensure_possible};
use crate::use_cases::authentication::password::sign_in::login::{
    Attempt, LoginOutcome, LoginPorts, LoginSettings,
};
use crate::use_cases::authentication::password::sign_in::settlement::{Settlement, Tally};

/// Where the change a sign-in owes begins, under the deployment's
/// settings.
pub(super) struct OwedChange<'a> {
    /// The ports the sign-in runs through.
    pub(super) ports: &'a LoginPorts,
    /// What the deployment decides for every sign-in.
    pub(super) settings: &'a LoginSettings,
}

impl OwedChange<'_> {
    /// Opens no session for a proved password that must change for
    /// `reason`: begins the change the sign-in owes, and answers what the
    /// attempt and the change raised. A password an admin set that nothing
    /// only the person holds can confirm is refused, the attempt still
    /// recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the account is gone.
    /// - `AppError::Internal` on storage, token or mail failure.
    pub(super) async fn begun(
        &self,
        attempt: &Attempt<'_>,
        result: LoginResult,
        reason: ChangeReason,
    ) -> Result<Settlement, AppError> {
        let users = self.ports.security.users.as_ref();
        let holder = existing_user(users, attempt.tenant, result.session.user_id()).await?;
        let due_ports = &self.ports.password_due;
        let proof = due_ports.proof_for(attempt.tenant, &holder, reason).await?;
        if let Err(refused) = ensure_possible(proof) {
            return Ok(Settlement {
                result: Err(refused),
                events: result.events,
                tally: Tally::NotAFailure,
            });
        }
        let due = DueChange {
            tenant: attempt.tenant,
            holder: &holder,
            reason,
            proof,
            scope: &attempt.request.confirm_at,
            base_url: &self.settings.confirmation.base_url,
        };
        let (owed, change_events) = due_ports
            .begin_change(due, self.ports.token_generator.as_ref())
            .await?;
        Ok(Settlement {
            result: Ok(LoginOutcome::PasswordChangeOwed(owed)),
            events: result.events.into_iter().chain(change_events).collect(),
            tally: Tally::NotAFailure,
        })
    }
}
