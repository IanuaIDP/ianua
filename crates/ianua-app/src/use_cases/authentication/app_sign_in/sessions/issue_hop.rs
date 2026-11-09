//! Handing out the code a hop carries to a host of a service that accepts
//! the app's sign-in with a cookie of its own, bound to the browser that
//! asked for it.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DomainName;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::sessions::across::HopAsk;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};

/// What a hop's code is asked for with. Holds the session cookie's token,
/// so it has no `Debug`.
pub struct AppIssueHopRequest {
    /// The session cookie's token on the owner's host, as presented.
    pub session: Option<Secret>,
    /// The host the code is for.
    pub host: DomainName,
    /// The digest of the value the asking browser keeps in its hop cookie
    /// on that host.
    pub browser: Secret,
}

/// Hands out a hop's code for a host of a service accepting the sign-in with
/// a cookie of its own.
pub struct AppIssueHopUseCase {
    common: Arc<AppSignInCommon>,
}

impl AppIssueHopUseCase {
    /// A use case working through the shared app sign-in parts.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
    ) -> Self {
        Self { common }
    }
}

impl Command for AppIssueHopUseCase {
    type Caller = AppSignInContext;
    type Input = AppIssueHopRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Hands out the code, provided the session is a live one of the app's
    /// sign-in and `request.host` is a host of a service accepting it with a
    /// cookie of its own. The code works once, on that host, and only in the
    /// browser whose hop cookie digests to `request.browser`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or no service
    ///   accepting it keeps a cookie on that host.
    /// - `AppError::Forbidden` without a live session of the app's sign-in.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppIssueHopRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, _) = self.common.resolved(ctx, auditor).await?;
        let ask = HopAsk {
            session: request.session.as_ref(),
            host: request.host,
            browser: &request.browser,
        };
        self.common.across.issue_hop(ctx, &target, ask).await
    }
}
