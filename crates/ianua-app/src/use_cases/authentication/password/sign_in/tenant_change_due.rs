//! Finishing a password sign-in to a tenant that owed a new password, for
//! a tenant named by the slugs in the address or already resolved by the
//! caller, as [`TenantLoginUseCase`] resolves it.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::PresentedSecret;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::due_change::{
    ChangeDueUseCase, DueChangeRequest,
};
use crate::use_cases::authentication::password::sign_in::tenant_login::{
    LoginTenant, TenantLoginOutcome, TenantLoginUseCase,
};

/// A password change a sign-in to a tenant owes, answered with a new
/// password. It holds both secrets, so it has no `Debug`.
pub struct TenantChangeDueRequest {
    /// The tenant the sign-in is for, as the sign-in named it.
    pub tenant: LoginTenant,
    /// The token the sign-in handed back.
    pub change_token: Secret,
    /// The replacement secret submitted with the change challenge.
    pub new_password: Secret,
    /// A code from the person's own second factor, when the change asks
    /// for one.
    pub factor_code: Option<String>,
    /// The secret of a browser the person remembered, if it sent one.
    pub device_secret: Option<PresentedSecret>,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// Finishes a sign-in to a tenant that owed a new password.
pub struct TenantChangeDueUseCase {
    change: Arc<ChangeDueUseCase>,
    login: Arc<TenantLoginUseCase>,
}

impl TenantChangeDueUseCase {
    /// A use case resolving the tenant as `login` does and setting the
    /// password through `change`.
    #[must_use]
    pub fn new(change: Arc<ChangeDueUseCase>, login: Arc<TenantLoginUseCase>) -> Self {
        Self { change, login }
    }
}

impl Command for TenantChangeDueUseCase {
    type Caller = ();
    type Input = TenantChangeDueRequest;
    type Output = Result<TenantLoginOutcome, AppError>;

    /// Sets `request.new_password` with the token a sign-in to the tenant
    /// `request.tenant` names handed back, then finishes that sign-in, as
    /// [`ChangeDueUseCase`] does, attributed to its organization and
    /// tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` for an unknown slug, alike with an unknown or
    ///   spent token.
    /// - The errors of [`ChangeDueUseCase`].
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: TenantChangeDueRequest,
    ) -> Result<TenantLoginOutcome, AppError> {
        let destination = self.login.resolved(request.tenant).await?;
        let scoped = ScopedTenant::from_registry(&destination.tenant);
        let attributed = auditor
            .with_organization(*destination.org.id())
            .with_tenant(*destination.tenant.id());
        let change = DueChangeRequest {
            change_token: request.change_token,
            new_password: request.new_password,
            factor_code: request.factor_code,
            device_secret: request.device_secret,
            origin: request.origin,
            confirm_at: destination.confirm_at,
        };
        let outcome = self.change.execute(&scoped, &attributed, change).await?;
        self.login.told(outcome, &scoped, &destination.tenant).await
    }
}
