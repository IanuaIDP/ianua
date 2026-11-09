//! Issuing a short-lived token under an app session, for a service accepting
//! the app's sign-in by token.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Audience;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::sessions::across_tokens::TokenGrant;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};

/// What a token is asked for with. Holds the session cookie's token, so it
/// has no `Debug`.
pub struct AppIssueTokenRequest {
    /// The session cookie's token, as presented.
    pub session: Option<Secret>,
    /// The audience of the service the token is for.
    pub audience: Audience,
}

/// Issues a short-lived token for a service accepting the sign-in by token.
pub struct AppIssueTokenUseCase {
    common: Arc<AppSignInCommon>,
}

impl AppIssueTokenUseCase {
    /// A use case working through the shared app sign-in parts.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
    ) -> Self {
        Self { common }
    }
}

impl Command for AppIssueTokenUseCase {
    type Caller = AppSignInContext;
    type Input = AppIssueTokenRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Issues the token, provided the session is live and the service named
    /// by `audience` accepts this sign-in by token.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or no service
    ///   takes tokens for the audience from it.
    /// - `AppError::Forbidden` without a live session of the app's sign-in.
    /// - `AppError::Internal` on storage or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppIssueTokenRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let grant = TokenGrant {
            session: request.session.as_ref(),
            audience: &request.audience,
        };
        self.common
            .across
            .issue_token(ctx, &target, grant, &auditor)
            .await
    }
}
