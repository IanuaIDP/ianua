//! Act through a grant: the credential an operator acts in a tenant with as
//! the user their impersonation grant names.
//!
//! The operator names the grant on a request to the user's tenant, with
//! their own key. This checks that the key works and the account is active,
//! that the grant is theirs, and that it is in force now, and hands back
//! the grant's tenant and the credential the request then acts with. What
//! the operator may do through it is worked out again on every use, from
//! the grant, the tenant and the user as they stand then, so a grant
//! revoked or ended a minute later stops the operator at once.

use std::sync::Arc;

use ianua_domain::domains::operator::impersonation::ImpersonationGrant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{ImpersonationGrantId, TenantId};

use crate::acting::OperatorAuthorities;
use crate::context::{Credential, OperatorCaller};
use crate::error::AppError;
use crate::ports::operator::ImpersonationGrantStore;
use crate::use_case::Query;
use crate::use_cases::operator::lookup::owned_grant;

/// The ports [`ActThroughGrantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ActThroughGrantPorts {
    /// Impersonation grants.
    pub grant_store: Arc<dyn ImpersonationGrantStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Where an operator acts through a grant, and with what.
#[derive(Debug, Clone)]
pub struct GrantInUse {
    /// The tenant the grant is for, the only one it acts in.
    pub tenant_id: TenantId,
    /// The operator's own key, the grant, and the user it names.
    pub credential: Credential,
}

/// Hands an operator the credential they act through as a grant's user.
pub struct ActThroughGrantUseCase {
    ports: ActThroughGrantPorts,
}

impl ActThroughGrantUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ActThroughGrantPorts) -> Self {
        Self { ports }
    }
}

impl Query for ActThroughGrantUseCase {
    type Caller = OperatorCaller;
    type Input = ImpersonationGrantId;
    type Output = Result<GrantInUse, AppError>;

    /// The tenant and credential the calling operator acts with through
    /// grant `id`: theirs, revoked by nobody, and not yet ended.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's operator or key no
    ///   longer exists.
    /// - `AppError::Forbidden` when the caller's key no longer works, their
    ///   account is disabled, or the grant was revoked or has ended.
    /// - `AppError::NotFound` when there is no such grant, or it is another
    ///   operator's.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        id: ImpersonationGrantId,
    ) -> Result<GrantInUse, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let grant = owned_grant(self.ports.grant_store.as_ref(), &id, &authority).await?;
        ensure_in_force(&grant)?;
        Ok(GrantInUse {
            tenant_id: *grant.tenant_id(),
            credential: Credential::Impersonation {
                key: caller.key().clone(),
                grant: id,
                user: *grant.user_id(),
            },
        })
    }
}

/// Refuses `grant` once it was revoked or has ended.
fn ensure_in_force(grant: &ImpersonationGrant) -> Result<(), AppError> {
    if grant.is_revoked() {
        return Err(AppError::Forbidden(message!(
            "operator-the-impersonation-grant-was-revoked",
            "the impersonation grant was revoked"
        )));
    }
    if grant.expires_at() <= clock::now() {
        return Err(AppError::Forbidden(message!(
            "operator-the-impersonation-grant-has-ended",
            "the impersonation grant has ended"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{OperatorId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{
        FakeGrantStore, stored_grant, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{block_on, test_ctx};

    fn act(
        grants: impl IntoIterator<Item = ImpersonationGrant>,
        authorities: FakeOperatorAuthorities,
        id: ImpersonationGrantId,
    ) -> Result<GrantInUse, AppError> {
        let use_case = ActThroughGrantUseCase::new(ActThroughGrantPorts {
            grant_store: Arc::new(FakeGrantStore::holding(grants)),
            operator_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_operator_caller(), id))
    }

    /// Bob holds an hour's grant to act as Ann. He gets the grant's tenant
    /// and a credential carrying his own key, the grant and Ann.
    #[test]
    fn a_grant_in_force_hands_back_its_tenant_and_user() {
        let ann = UserId::new();
        let grant = stored_grant(test_operator_id(), test_ctx().tenant_id(), ann);
        let id = *grant.id();

        let in_use = act([grant], FakeOperatorAuthorities::admitting(), id).unwrap();

        assert_eq!(in_use.tenant_id, test_ctx().tenant_id());
        let Credential::Impersonation { grant, user, .. } = in_use.credential else {
            panic!("acting through a grant is an impersonation");
        };
        assert_eq!(grant, id);
        assert_eq!(user, ann);
    }

    /// An impersonation grant owned by another operator answers not found.
    #[test]
    fn another_operators_grant_reads_as_missing() {
        let carols = stored_grant(OperatorId::new(), test_ctx().tenant_id(), UserId::new());
        let id = *carols.id();

        let result = act([carols], FakeOperatorAuthorities::admitting(), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An unknown grant ID answers not found instead of yielding an
    /// impersonation credential.
    #[test]
    fn a_grant_nobody_holds_is_not_found() {
        let result = act(
            [],
            FakeOperatorAuthorities::admitting(),
            ImpersonationGrantId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A disabled operator's authority refusal prevents using an otherwise
    /// valid impersonation grant.
    #[test]
    fn a_disabled_operator_acts_through_no_grant() {
        let grant = stored_grant(test_operator_id(), test_ctx().tenant_id(), UserId::new());
        let id = *grant.id();

        let result = act(
            [grant],
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
