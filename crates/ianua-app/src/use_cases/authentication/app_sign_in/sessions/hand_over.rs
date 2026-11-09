//! Handing an app sign-in over to a host that keeps a cookie of its own.

use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::{
    AcrossHosts, AppSignInContext, AppSignInOutcome,
};

/// A hop as it arrived: the code it carried, and the browser it arrived in.
/// Both are credentials, so it has no `Debug`.
pub struct AppHandOverRequest {
    /// The one-time code the browser carried.
    pub code: Secret,
    /// The digest of the value the arriving browser keeps in its hop cookie
    /// on this host.
    pub browser: Secret,
}

/// Sets the session a hop carries as a cookie on the host it arrived at.
pub struct HandOverAppSessionUseCase {
    across: AcrossHosts,
}

impl HandOverAppSessionUseCase {
    /// A use case handing sessions over through `across`.
    #[must_use]
    pub fn new(across: AcrossHosts) -> Self {
        Self { across }
    }
}

impl Command for HandOverAppSessionUseCase {
    type Caller = AppSignInContext;
    type Input = AppHandOverRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Sets the session the hop's one-time code carries as a cookie on the
    /// host `ctx` names, provided it arrived in the browser that asked for
    /// it. See [`AcrossHosts::hand_over`].
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the host is not one of a service's own
    ///   cookie, or the code is unknown, used, lapsed, for another host or
    ///   for another browser.
    /// - `AppError::Forbidden` when the session it carries has ended.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        landing: AppHandOverRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        self.across.hand_over(ctx, &landing, auditor).await
    }
}
