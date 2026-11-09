//! The passkeys of the member signed in.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgPasskeyStore;
use crate::use_case::Query;

/// The ports [`OrgListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgListPorts {
    /// Members' passkeys.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Lists the passkeys of the member signed in.
pub struct OrgListUseCase {
    ports: OrgListPorts,
}

impl OrgListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: OrgListPorts) -> Self {
        Self { ports }
    }
}

impl Query for OrgListUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Vec<PasskeyCredential<ResolvedOrganization>>, AppError>;

    /// The passkeys of the member signed in to `caller`'s session.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts, or they act through a key.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        (): (),
    ) -> Result<Vec<PasskeyCredential<ResolvedOrganization>>, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        actor.signed_in()?;
        self.ports
            .passkey_store
            .list_by_user(actor.member().id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgPasskeyStore;
    use crate::test_support::{block_on, test_org_caller};

    fn list(store: FakeOrgPasskeyStore, actors: FakeOrgActors) -> Result<usize, AppError> {
        let use_case = OrgListUseCase::new(OrgListPorts {
            passkey_store: Arc::new(store),
            org_actors: Arc::new(actors),
        });
        block_on(use_case.execute(&test_org_caller(), ())).map(|keys| keys.len())
    }

    fn olivia_holding_one() -> FakeOrgPasskeyStore {
        let caller = test_org_caller();
        FakeOrgPasskeyStore::with_passkey(caller.organization_id(), *caller.member())
    }

    /// Olivia, signed in, sees the passkey she registered.
    #[test]
    fn a_member_sees_her_own_passkeys() {
        let listed = list(
            olivia_holding_one(),
            FakeOrgActors::in_role(OrgRole::Member),
        );

        assert_eq!(listed.unwrap(), 1);
    }

    /// A member's passkey list excludes a key held by another member.
    #[test]
    fn another_members_passkeys_do_not_show() {
        let store = FakeOrgPasskeyStore::with_passkey(
            test_org_caller().organization_id(),
            OrgUserId::new(),
        );

        let listed = list(store, FakeOrgActors::in_role(OrgRole::Member));

        assert_eq!(listed.unwrap(), 0);
    }

    /// A signed-out session cannot list the member's passkeys.
    #[test]
    fn a_signed_out_member_is_refused() {
        let listed = list(
            olivia_holding_one(),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        assert!(matches!(listed, Err(AppError::Unauthenticated)));
    }

    /// An API key cannot supply the signed-in session needed to list passkeys.
    #[test]
    fn a_key_caller_is_refused() {
        let listed = list(
            olivia_holding_one(),
            FakeOrgActors::through_key(OrgRole::Member, Vec::new()),
        );

        assert!(matches!(listed, Err(AppError::Unauthenticated)));
    }
}
