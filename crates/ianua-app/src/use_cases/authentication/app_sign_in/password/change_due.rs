//! Setting the new password an app sign-in owes, on the app's own domain,
//! and finishing that sign-in.
//!
//! A password an admin set, or one that expired, opened no session: the
//! sign-in began a single-use change, its token kept in the host's
//! challenge cookie, or mailed to the person when their mailbox is the
//! proof a password an admin set asks. The person types a new password,
//! with a code from their own factor when the change asks for one, and the
//! dashboard's own change sets it and finishes the sign-in.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::password::log_in::{
    continued, device_on_host, on_app_host,
};
use crate::use_cases::authentication::app_sign_in::relay::common::{AppSignInCommon, OnTarget};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::password::{TenantChangeDueRequest, TenantChangeDueUseCase};

/// A new password for a sign-in that owes one. Holds the challenge token
/// and the password, so it has no `Debug`.
pub struct AppChangePasswordRequest {
    /// The change's token: the challenge cookie's, handed out when the
    /// password was accepted, or the one in the mailed link.
    pub challenge: Secret,
    /// The chosen replacement secret to install after confirmation.
    pub new_password: Secret,
    /// A code from the person's own second factor, when the change asks
    /// for one.
    pub code: Option<String>,
    /// The secret of the device cookie the host keeps, when the browser
    /// remembered a device there.
    pub device: Option<DeviceSecret>,
    /// Where to send them afterwards, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Sets the new password a sign-in owes on the app's host, and finishes it.
pub struct AppChangePasswordUseCase {
    common: Arc<AppSignInCommon>,
    change: Arc<TenantChangeDueUseCase>,
}

impl AppChangePasswordUseCase {
    /// A use case setting the password through the dashboard's own
    /// `change`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        change: Arc<TenantChangeDueUseCase>,
    ) -> Self {
        Self { common, change }
    }
}

impl Command for AppChangePasswordUseCase {
    type Caller = AppSignInContext;
    type Input = AppChangePasswordRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Sets `request.new_password` with the change the challenge cookie
    /// holds, then signs the person in on the app's host or asks for the
    /// second factor the sign-in still owes, as a password sign-in does.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the change
    ///   is unknown, used or expired.
    /// - `AppError::Domain` when the new password breaks the tenant's
    ///   rules, each refusal counted against the address's lockout.
    /// - `AppError::AccountLocked` while the address is locked out.
    /// - `AppError::Forbidden` if the account must set up a second factor
    ///   first, which an app's host does not offer, or the workspace takes
    ///   no passwords.
    /// - `AppError::Internal` on persistence or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppChangePasswordRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let change = TenantChangeDueRequest {
            tenant: on_app_host(&target),
            change_token: request.challenge,
            new_password: request.new_password,
            factor_code: request.code,
            device_secret: request.device.map(|secret| device_on_host(&target, secret)),
            origin: ctx.origin(),
        };
        let outcome = self.change.execute(&(), &auditor, change).await?;
        let on = OnTarget {
            ctx,
            target: &target,
        };
        continued(&self.common, &on, outcome, request.return_to).await
    }
}
