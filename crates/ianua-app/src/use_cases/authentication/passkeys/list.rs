//! The passkeys of the person signed in.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// The tenant's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the passkeys of the person signed in.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<PasskeyCredential<ResolvedTenant>>, AppError>;

    /// The passkeys of the person signed in to `caller`'s session.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<PasskeyCredential<ResolvedTenant>>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        self.ports
            .passkey_store
            .list_by_user(&caller.tenant(), person.account.id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakePasskeyStore;
    use crate::test_support::{block_on, test_ctx, test_ctx_with};

    fn caller(user_id: UserId) -> CallerContext {
        test_ctx_with(
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            user_id,
        )
    }

    fn list(store: FakePasskeyStore, as_user: UserId) -> Result<usize, AppError> {
        let use_case = ListUseCase::new(ListPorts {
            passkey_store: Arc::new(store),
            ..ListPorts::fakes()
        });
        block_on(use_case.execute(&caller(as_user), ())).map(|passkeys| passkeys.len())
    }

    /// Ann holds three passkeys. She sees all three.
    #[test]
    fn a_person_sees_their_passkeys() {
        let ann = UserId::new();

        let count = list(FakePasskeyStore::with_passkeys(ann, 3), ann).unwrap();

        assert_eq!(count, 3);
    }

    /// A caller with no passkeys receives an empty list even when another
    /// user has two stored keys.
    #[test]
    fn nobody_sees_another_persons_passkeys() {
        let ann = UserId::new();

        let count = list(FakePasskeyStore::with_passkeys(ann, 2), UserId::new()).unwrap();

        assert_eq!(count, 0);
    }

    /// A signed-out caller is unauthenticated when listing passkeys.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = ListUseCase::new(ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListPorts::fakes()
        });

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
