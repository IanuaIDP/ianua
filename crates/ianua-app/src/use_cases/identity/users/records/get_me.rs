//! Get me: the signed-in person's own account, which needs no right to view
//! users.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::use_case::Query;

/// The ports [`GetMeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMePorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the signed-in person's own account.
pub struct GetMeUseCase {
    ports: GetMePorts,
}

impl GetMeUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetMePorts) -> Self {
        Self { ports }
    }
}

impl Query for GetMeUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// The account of the person signed in to `ctx`'s session, as it is
    /// now: their name, address, preferences and profile.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::TenantUnavailable` when the tenant is not open.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<User<ResolvedTenant>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        Ok(person.account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::{block_on, test_ctx};

    fn me(authorities: FakeTenantAuthorities) -> Result<User<ResolvedTenant>, AppError> {
        let use_case = GetMeUseCase::new(GetMePorts {
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann may not view other users, yet she reads her own account.
    #[test]
    fn a_person_reads_their_own_account_without_the_right_to_view_users() {
        let account = me(FakeTenantAuthorities::holding(&[])).unwrap();

        assert_eq!(account.id(), &test_caller_id());
    }

    /// A signed-out person cannot read their own account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = me(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
