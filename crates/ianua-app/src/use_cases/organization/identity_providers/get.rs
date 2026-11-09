//! Get identity provider: how the organization's company directory is
//! connected, for those who manage its sign-in settings.
//!
//! The provider carries an OIDC client secret only in its sealed form, and
//! whoever shows it leaves even that out.

use std::sync::Arc;

use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::organization::OrgIdentityProviderStore;
use crate::use_case::Query;
use crate::use_cases::organization::identity_providers::lookup::{
    ensure_manages_sign_in, existing_provider,
};

/// The ports [`GetOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgPorts {
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the organization's identity provider.
pub struct GetOrgUseCase {
    ports: GetOrgPorts,
}

impl GetOrgUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOrgUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<OrgIdentityProvider, AppError>;

    /// The caller's organization's provider.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not read the
    ///   organization's sign-in settings.
    /// - `AppError::NotFound` when the organization has no provider.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<OrgIdentityProvider, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        ensure_manages_sign_in(&actor.control()?, organization.id())?;
        existing_provider(self.ports.providers.as_ref(), organization.id()).await
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
    use crate::test_support::{block_on, test_org_caller};

    fn read(
        actors: FakeOrgActors,
        providers: FakeOrgIdentityProviderStore,
    ) -> Result<OrgIdentityProvider, AppError> {
        let uc = GetOrgUseCase::new(GetOrgPorts {
            providers: Arc::new(providers),
            org_actors: Arc::new(actors),
        });
        block_on(uc.execute(&test_org_caller(), ()))
    }

    fn okta() -> FakeOrgIdentityProviderStore {
        let acme = test_org_caller().organization_id();
        FakeOrgIdentityProviderStore::holding(stored_org_provider(acme, OrgProviderShape::saml()))
    }

    /// Ann, Acme's owner, reads how Okta is connected. She is shown it.
    #[test]
    fn an_owner_reads_the_provider() {
        let provider = read(FakeOrgActors::in_role(OrgRole::Owner), okta()).unwrap();

        assert_eq!(provider.name().as_str(), "Acme Okta");
    }

    /// Ann reads a provider Acme never added. It is not found.
    #[test]
    fn no_provider_is_not_found() {
        let result = read(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgIdentityProviderStore::empty(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A plain member cannot read the organization's identity-provider settings.
    #[test]
    fn a_member_without_the_sign_in_right_is_refused() {
        let result = read(FakeOrgActors::in_role(OrgRole::Member), okta());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before reading provider settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(FakeOrgActors::refusing(Refusal::SignedOut), okta());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
