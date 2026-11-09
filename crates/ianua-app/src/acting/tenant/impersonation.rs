//! An operator acting in a tenant as the user an impersonation grant names.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::operator::impersonation::{Impersonated, ImpersonationGrant};
use ianua_domain::message;
use ianua_domain::types::{ImpersonationGrantId, KeyPrefix, OperatorId, UserId};
use time::OffsetDateTime;

use crate::acting::tenant::{Resolving, TenantActing};
use crate::context::Credential;
use crate::error::AppError;
use crate::ports::authorization::Holder;

impl TenantActing {
    /// An operator acting as a user through an impersonation grant, signed
    /// in with their own key.
    pub(in crate::acting::tenant) async fn of_impersonation(
        &self,
        at: &Resolving<'_>,
        parties: OperatorParties<'_>,
    ) -> Result<TenantAuthority, AppError> {
        let (operator, by) = self.operator_authority(&parties, at.now).await?;
        let grant = self.impersonation_grant(parties.grant).await?;
        let tenant = self.tenant_record(&at.caller.tenant_id()).await?;
        let user = self.user(&at.caller.tenant(), parties.user).await?;
        let impersonated = Impersonated {
            operator: &operator,
            tenant: &tenant,
            user: &user,
        };
        let records = self.held_by(at.caller, Holder::user(*parties.user)).await?;
        let acting = grant
            .act_as(
                &records.access(at.caller.tenant_id()),
                &by,
                &impersonated,
                at.now,
            )
            .map_err(AppError::from_domain)?;
        Ok(acting.authority().clone())
    }

    /// The impersonating operator, and what their own key lets them do.
    pub(in crate::acting::tenant) async fn operator_authority(
        &self,
        parties: &OperatorParties<'_>,
        now: OffsetDateTime,
    ) -> Result<(Operator, OperatorAuthority), AppError> {
        let operator = self
            .ports
            .operators
            .operators
            .find_by_id(parties.operator)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let key = self
            .ports
            .operators
            .operator_keys
            .find_by_prefix(parties.key)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let authority =
            OperatorAuthority::of_key(&operator, &key, now).map_err(AppError::from_domain)?;
        Ok((operator, authority))
    }

    /// The impersonation grant `id` names, refused once it is gone.
    async fn impersonation_grant(
        &self,
        id: &ImpersonationGrantId,
    ) -> Result<ImpersonationGrant, AppError> {
        self.ports
            .operators
            .impersonations
            .find_by_id(id)
            .await
            .map_err(AppError::from_domain)?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "app-the-impersonation-grant-is-gone",
                    "the impersonation grant is gone"
                ))
            })
    }
}

/// What an impersonating operator's credential names.
pub(in crate::acting::tenant) struct OperatorParties<'a> {
    pub(in crate::acting::tenant) operator: &'a OperatorId,
    pub(in crate::acting::tenant) key: &'a KeyPrefix,
    pub(in crate::acting::tenant) grant: &'a ImpersonationGrantId,
    pub(in crate::acting::tenant) user: &'a UserId,
}

impl<'a> OperatorParties<'a> {
    /// What `credential` names for `operator`, when it is an impersonation.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthenticated` for any other credential.
    pub(in crate::acting::tenant) fn of(
        operator: &'a OperatorId,
        credential: &'a Credential,
    ) -> Result<Self, AppError> {
        let Credential::Impersonation { key, grant, user } = credential else {
            return Err(AppError::Unauthenticated);
        };
        Ok(Self {
            operator,
            key,
            grant,
            user,
        })
    }
}
