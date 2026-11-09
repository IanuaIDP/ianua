//! List exports: the requests for a copy of a person's data and where each
//! stands, for the person themselves or for staff who may view them.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::DataExportStore;
use crate::use_case::Query;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// The ports [`ListExportsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListExportsPorts {
    /// The requests.
    pub export_store: Arc<dyn DataExportStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a person's export requests.
pub struct ListExportsUseCase {
    ports: ListExportsPorts,
}

impl ListExportsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListExportsPorts) -> Self {
        Self { ports }
    }

    /// The person `whose` names, once the caller may see their exports.
    async fn subject(&self, ctx: &CallerContext, whose: Whose) -> Result<UserId, AppError> {
        let Whose::OnBehalfOf(user_id) = whose else {
            let person = self.ports.tenant_authorities.signed_in(ctx).await?;
            return Ok(*person.account.id());
        };
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let tenant = ctx.tenant();
        account_control(
            records,
            &tenant,
            &authority,
            &user_id,
            AccountAction::Export,
        )
        .await?
        .ensure_allowed(&user_id, AccountAction::Export)
        .map_err(AppError::from_domain)?;
        Ok(user_id)
    }
}

impl Query for ListExportsUseCase {
    type Caller = CallerContext;
    type Input = Whose;
    type Output = Result<Vec<DataExportRequest<ResolvedTenant>>, AppError>;

    /// The export requests of `whose`, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person listing their own came with no session.
    /// - `AppError::Forbidden` when the caller may not view the user, or the
    ///   user holds more than the caller.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<Vec<DataExportRequest<ResolvedTenant>>, AppError> {
        let user_id = self.subject(ctx, whose).await?;
        self.ports
            .export_store
            .list_by_user(&ctx.tenant(), &user_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeDataExportStore, asked_export_of};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        store: FakeDataExportStore,
        authorities: FakeTenantAuthorities,
        whose: Whose,
    ) -> Result<Vec<DataExportRequest<ResolvedTenant>>, AppError> {
        let use_case = ListExportsUseCase::new(ListExportsPorts {
            export_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
            ..ListExportsPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), whose))
    }

    /// Ann sees her own export request.
    #[test]
    fn a_person_sees_their_own_exports() {
        let export = asked_export_of(test_caller_id());

        let listed = list(
            FakeDataExportStore::holding(&export),
            FakeTenantAuthorities::holding_everything(),
            Whose::Own,
        )
        .unwrap();

        assert_eq!(listed.len(), 1);
    }

    /// Ann, who may view users, sees Bob's.
    #[test]
    fn staff_see_someones_exports() {
        let bob = UserId::new();
        let export = asked_export_of(bob);

        let listed = list(
            FakeDataExportStore::holding(&export),
            FakeTenantAuthorities::holding_everything(),
            Whose::OnBehalfOf(bob),
        )
        .unwrap();

        assert_eq!(listed[0].user_id(), &bob);
    }

    /// A caller without user-viewing rights cannot list Bob's export requests.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let bob = UserId::new();

        let result = list(
            FakeDataExportStore::holding(&asked_export_of(bob)),
            FakeTenantAuthorities::holding(&[]),
            Whose::OnBehalfOf(bob),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person cannot list their own export requests.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeDataExportStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Whose::Own,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
