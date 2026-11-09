//! Remove identity provider: disconnect the organization's company
//! directory. Members sign in their other ways from then on; owners keep
//! their password whatever the organization enforces.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgIdentityProviderStore;
use crate::use_case::Command;
use crate::use_cases::organization::identity_providers::lookup::{
    ensure_manages_sign_in, existing_provider,
};

/// The ports [`RemoveOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveOrgPorts {
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Removes the organization's identity provider.
pub struct RemoveOrgUseCase {
    ports: RemoveOrgPorts,
}

impl RemoveOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveOrgUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Deletes the caller's organization's provider and records
    /// `organization.org_identity_provider_removed`. A sign-in already sent
    /// to it is refused when it comes back.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization's sign-in settings.
    /// - `AppError::NotFound` when the organization has no provider.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_manages_sign_in(&control, organization.id())?;
        let store = self.ports.providers.as_ref();
        let mut provider = existing_provider(store, organization.id()).await?;
        provider.remove(&control).map_err(AppError::from_domain)?;
        store
            .delete(organization.id(), provider.id())
            .await
            .or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, provider.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, OrgProviderShape, stored_org_provider,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: RemoveOrgUseCase,
        providers: Arc<FakeOrgIdentityProviderStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, providers: FakeOrgIdentityProviderStore) -> Self {
            let providers = Arc::new(providers);
            Self {
                uc: RemoveOrgUseCase::new(RemoveOrgPorts {
                    providers: providers.clone(),
                    org_actors: Arc::new(actors),
                }),
                providers,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn connected(actors: FakeOrgActors) -> Self {
            let acme = test_org_caller().organization_id();
            let okta = stored_org_provider(acme, OrgProviderShape::saml());
            Self::with(actors, FakeOrgIdentityProviderStore::holding(okta))
        }

        fn remove(&self) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_org_caller(), &test_auditor(self.audit.clone()), ()),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann, Acme's owner, disconnects Okta. It is gone and the removal is
    /// recorded.
    #[test]
    fn an_owner_removes_the_provider() {
        let setup = Setup::connected(FakeOrgActors::in_role(OrgRole::Owner));

        setup.remove().unwrap();

        assert_eq!(setup.providers.count(), 0);
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_identity_provider_removed"]
        );
    }

    /// Ann removes a provider Acme never added. It is not found.
    #[test]
    fn no_provider_is_not_found() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgIdentityProviderStore::empty(),
        );

        let result = setup.remove();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A plain member cannot remove the identity provider; it stays stored
    /// and no removal is recorded.
    #[test]
    fn a_member_without_the_sign_in_right_is_refused() {
        let setup = Setup::connected(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.remove();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.providers.count(), 1);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out caller cannot remove the provider, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::connected(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.remove();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.providers.count(), 1);
    }
}
