//! What a successful password sign-in keeps: its session, naming the
//! remembered browser it came from, the account's last sign-in, that
//! browser stamped as used and the place it came from, and the
//! confirmation by email it may owe.

use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::domains::authentication::operations::password_login::LoginResult;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::Fact;

use crate::error::{AppError, OrInternal};
use crate::services::lookup::existing_user;
use crate::use_cases::authentication::password::sign_in::confirmation::{
    Confirmation, owes_email_confirmation,
};
use crate::use_cases::authentication::password::sign_in::login::{
    Attempt, LoginPorts, LoginSettings,
};
use crate::use_cases::authentication::password::sign_in::login_security::PresentedDevice;
use crate::use_cases::authentication::password::sign_in::settlement::Settlement;
use crate::use_cases::authentication::signed_in_event::record_login;

/// Where a successful sign-in is kept, under the deployment's settings.
pub(super) struct KeptSignIn<'a> {
    /// The ports the sign-in runs through.
    pub(super) ports: &'a LoginPorts,
    /// What the deployment decides for every sign-in.
    pub(super) settings: &'a LoginSettings,
}

impl KeptSignIn<'_> {
    /// Keeps what a successful sign-in produced, and its outcome, with the
    /// sign-in recorded first among its events.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage or mail failure.
    pub(super) async fn succeeded(
        &self,
        attempt: &Attempt<'_>,
        mut result: LoginResult,
    ) -> Result<Settlement, AppError> {
        let device = self.remembered_device(attempt, &result).await;
        name_device(&mut result, device.as_ref())?;
        self.ports
            .sessions
            .save(attempt.tenant, &result.session)
            .await
            .or_internal()?;
        let users = self.ports.security.users.as_ref();
        record_login(users, attempt.tenant, result.session.user_id()).await?;
        self.stamp_device(attempt, device).await?;
        self.remember_place(attempt, &result).await?;
        self.confirm_if_owed(attempt, &result).await?;
        Ok(Settlement::signed_in(
            result,
            attempt.tenant,
            attempt.started,
        ))
    }

    /// The remembered browser the sign-in came from, when it presented the
    /// secret of one the account remembered that still counts.
    async fn remembered_device(
        &self,
        attempt: &Attempt<'_>,
        result: &LoginResult,
    ) -> Option<TrustedDevice<ResolvedTenant>> {
        let presented = PresentedDevice {
            tenant: attempt.tenant,
            user_id: result.session.user_id(),
            secret: attempt.request.device_secret.as_ref(),
        };
        let window = self.settings.security.device_trust;
        self.ports
            .security
            .remembered_device(presented, window)
            .await
    }

    /// Stamps the remembered browser the sign-in came from as used now, so
    /// it keeps counting while it is in use.
    async fn stamp_device(
        &self,
        attempt: &Attempt<'_>,
        device: Option<TrustedDevice<ResolvedTenant>>,
    ) -> Result<(), AppError> {
        let Some(device) = device else {
            return Ok(());
        };
        self.ports
            .security
            .record_device_sign_in(attempt.tenant, device, &attempt.request.origin)
            .await
    }

    /// Adds where the sign-in came from to the account's history, when the
    /// address could be placed.
    async fn remember_place(
        &self,
        attempt: &Attempt<'_>,
        result: &LoginResult,
    ) -> Result<(), AppError> {
        let Fact::Known(place) = result.risk_assessment.current_location() else {
            return Ok(());
        };
        self.ports
            .security
            .sign_in_history
            .record(
                attempt.tenant,
                result.session.user_id(),
                place,
                result.occurred_at,
            )
            .await
            .or_internal()
    }

    /// Mails the confirmation link when the sign-in waits for one.
    async fn confirm_if_owed(
        &self,
        attempt: &Attempt<'_>,
        result: &LoginResult,
    ) -> Result<(), AppError> {
        if !owes_email_confirmation(result.second_factor) {
            return Ok(());
        }
        let users = self.ports.security.users.as_ref();
        let account = existing_user(users, attempt.tenant, result.session.user_id()).await?;
        let to = Confirmation {
            tenant: attempt.tenant,
            account: &account,
            scope: &attempt.request.confirm_at,
        };
        self.ports
            .confirmation
            .send(to, &self.settings.confirmation)
            .await
    }
}

/// Names `device`, the remembered browser the sign-in came from, on the
/// session it opened, so the session's tokens carry it to a device posture
/// check.
///
/// # Errors
///
/// `AppError::Internal` when the session refuses it: the device was found
/// for the session's own holder, still trusted, so a refusal is a bug.
fn name_device(
    result: &mut LoginResult,
    device: Option<&TrustedDevice<ResolvedTenant>>,
) -> Result<(), AppError> {
    let Some(device) = device else {
        return Ok(());
    };
    result
        .session
        .record_signed_in_from(device)
        .map_err(AppError::internal)
}
