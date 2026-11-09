//! Consent history: every consent a person gave and withdrew, for the
//! person themselves or for someone who may view users, such as support
//! answering what was agreed to and when.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::consent::ConsentRecord;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::ConsentStore;
use crate::use_case::Query;
use crate::use_cases::identity::whose::{Whose, readable_account};

/// The ports [`ConsentHistoryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConsentHistoryPorts {
    /// The consent records.
    pub consent_store: Arc<dyn ConsentStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a person's consent history.
pub struct ConsentHistoryUseCase {
    ports: ConsentHistoryPorts,
}

impl ConsentHistoryUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ConsentHistoryPorts) -> Self {
        Self { ports }
    }
}

impl Query for ConsentHistoryUseCase {
    type Caller = CallerContext;
    type Input = Whose;
    type Output = Result<Vec<ConsentRecord<ResolvedTenant>>, AppError>;

    /// Every consent record of `whose`, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person reading their own came with no session.
    /// - `AppError::Forbidden` when the caller reads another user's without
    ///   the right to view users.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<Vec<ConsentRecord<ResolvedTenant>>, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let user_id = readable_account(authorities, ctx, whose).await?;
        self.ports
            .consent_store
            .history(&ctx.tenant(), &user_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeConsentStore;
    use crate::test_support::{block_on, test_ctx};

    fn read(
        authorities: FakeTenantAuthorities,
        whose: Whose,
    ) -> Result<Vec<ConsentRecord<ResolvedTenant>>, AppError> {
        let use_case = ConsentHistoryUseCase::new(ConsentHistoryPorts {
            consent_store: Arc::new(FakeConsentStore::empty()),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), whose))
    }

    /// Ann, who holds nothing in the tenant, reads her own consents.
    #[test]
    fn a_person_reads_their_own_consents() {
        let result = read(FakeTenantAuthorities::holding(&[]), Whose::Own);

        assert!(result.unwrap().is_empty());
    }

    /// Ann, who may view users, reads Bob's.
    #[test]
    fn an_admin_reads_someones_consents() {
        let result = read(
            FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)]),
            Whose::OnBehalfOf(UserId::new()),
        );

        assert!(result.is_ok());
    }

    /// A caller without user-viewing rights cannot read another person's consents.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let result = read(
            FakeTenantAuthorities::holding(&[]),
            Whose::OnBehalfOf(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person cannot read their own consent history.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Whose::Own,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
