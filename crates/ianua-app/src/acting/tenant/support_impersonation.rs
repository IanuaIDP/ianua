//! A tenant admin acting as one of the tenant's people for support, through
//! a support impersonation, signed in with their own session.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::support_acting::acting_as;
use ianua_domain::message;
use ianua_domain::types::{SessionId, SupportImpersonationId, UserId};

use crate::acting::tenant::{Resolving, TenantActing};
use crate::context::Credential;
use crate::error::AppError;
use crate::ports::authorization::Holder;

impl TenantActing {
    /// The admin `parties` names, acting as the person the impersonation
    /// names with what that person holds now, while the admin's own session
    /// counts and the impersonation's window is open.
    pub(in crate::acting::tenant) async fn of_support_impersonation(
        &self,
        at: &Resolving<'_>,
        parties: SupportParties<'_>,
    ) -> Result<TenantAuthority, AppError> {
        let admin = self
            .checked_session(at.caller, parties.admin, parties.session, at.now)
            .await?;
        let tenant = at.caller.tenant();
        let impersonation = self
            .ports
            .operators
            .support_impersonations
            .find_by_id(&tenant, parties.impersonation)
            .await
            .map_err(AppError::from_domain)?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "app-the-support-impersonation-is-gone",
                    "the support impersonation is gone"
                ))
            })?;
        let account = self.user(&tenant, parties.user).await?;
        let records = self.held_by(at.caller, Holder::user(*parties.user)).await?;
        acting_as(
            &impersonation,
            &records.access(at.caller.tenant_id()),
            &admin.signed_in,
            &account,
            at.now,
        )
        .map_err(AppError::from_domain)
    }
}

/// What a support impersonation credential names.
pub(in crate::acting::tenant) struct SupportParties<'a> {
    /// The admin signed in.
    pub(in crate::acting::tenant) admin: &'a UserId,
    /// The admin's own session.
    pub(in crate::acting::tenant) session: &'a SessionId,
    /// The impersonation that lets them act as the person.
    pub(in crate::acting::tenant) impersonation: &'a SupportImpersonationId,
    /// The person they act as.
    pub(in crate::acting::tenant) user: &'a UserId,
}

impl<'a> SupportParties<'a> {
    /// What `credential` names for `admin`, when it is a support
    /// impersonation.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthenticated` for any other credential.
    pub(in crate::acting::tenant) fn of(
        admin: &'a UserId,
        credential: &'a Credential,
    ) -> Result<Self, AppError> {
        let Credential::SupportImpersonation {
            session,
            impersonation,
            user,
        } = credential
        else {
            return Err(AppError::Unauthenticated);
        };
        Ok(Self {
            admin,
            session,
            impersonation,
            user,
        })
    }
}
