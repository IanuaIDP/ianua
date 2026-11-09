//! Switch identity provider: let members sign in through the organization's
//! provider, or stop them.
//!
//! Switching it on opens the dashboard to everyone the directory vouches
//! for, so the caller proves who they are again first.

use std::sync::Arc;

use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgIdentityProviderStore;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::organization::identity_providers::lookup::{
    ensure_manages_sign_in, existing_provider,
};

/// Whether members may sign in through the provider, with what the caller
/// gave to prove who they are.
pub struct SwitchOrgRequest {
    /// On or off.
    pub to: ConnectionStatus,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`SwitchOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SwitchOrgPorts {
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// Switches the organization's identity provider on or off.
pub struct SwitchOrgUseCase {
    ports: SwitchOrgPorts,
}

impl SwitchOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SwitchOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for SwitchOrgUseCase {
    type Caller = OrgCaller;
    type Input = SwitchOrgRequest;
    type Output = Result<OrgIdentityProvider, AppError>;

    /// Switches the provider to `request.to` once the caller proved who
    /// they are again, and records `organization.org_identity_provider_changed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without sign-in-settings rights or adequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `NotFound` for no organization provider.
    /// - `AppError::Domain` for an unchanged provider status; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: SwitchOrgRequest,
    ) -> Result<OrgIdentityProvider, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_manages_sign_in(&control, organization.id())?;
        let store = self.ports.providers.as_ref();
        let mut provider = existing_provider(store, organization.id()).await?;
        self.ports
            .fresh_proofs
            .prove_member(
                actor.member(),
                &organization,
                request.proof,
                caller.origin(),
            )
            .await?;
        provider
            .switch(request.to, &control)
            .map_err(AppError::from_domain)?;
        store.save(&provider).await.or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, provider.take_events())
            .await
            .or_internal()?;
        Ok(provider)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, OrgProviderShape, stored_org_provider,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: SwitchOrgUseCase,
        providers: Arc<FakeOrgIdentityProviderStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, providers: FakeOrgIdentityProviderStore) -> Self {
            let providers = Arc::new(providers);
            Self {
                uc: SwitchOrgUseCase::new(SwitchOrgPorts {
                    providers: providers.clone(),
                    org_actors: Arc::new(actors),
                    ..SwitchOrgPorts::fakes()
                }),
                providers,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn added_off(role: OrgRole) -> Self {
            let shape = OrgProviderShape::saml().in_status(ConnectionStatus::Disabled);
            Self::with(
                FakeOrgActors::in_role(role),
                FakeOrgIdentityProviderStore::holding(stored_org_provider(acme(), shape)),
            )
        }

        fn switch(
            &self,
            to: ConnectionStatus,
            proof: ReenteredProof,
        ) -> Result<OrgIdentityProvider, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                SwitchOrgRequest { to, proof },
            ))
        }

        fn status(&self) -> ConnectionStatus {
            self.providers.stored(&acme()).unwrap().status()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    /// Ann, Acme's owner, checked Okta and switches it on with her password
    /// typed again. Members may sign in through it, and the change is
    /// recorded.
    #[test]
    fn a_proven_owner_switches_the_provider_on() {
        let setup = Setup::added_off(OrgRole::Owner);

        setup
            .switch(ConnectionStatus::Active, right_password())
            .unwrap();

        assert_eq!(setup.status(), ConnectionStatus::Active);
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_identity_provider_changed"]
        );
    }

    /// Ann switches off a provider that is off already. It is refused as a
    /// move that goes nowhere, and nothing is recorded.
    #[test]
    fn switching_to_where_it_stands_is_refused() {
        let setup = Setup::added_off(OrgRole::Owner);

        let result = setup.switch(ConnectionStatus::Disabled, right_password());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// An incorrect password proof prevents enabling the provider; it stays
    /// disabled and no change is recorded.
    #[test]
    fn a_wrong_password_leaves_it_off() {
        let setup = Setup::added_off(OrgRole::Owner);

        let result = setup.switch(ConnectionStatus::Active, wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), ConnectionStatus::Disabled);
        assert!(setup.recorded().is_empty());
    }

    /// A plain member cannot enable the provider, which stays disabled.
    #[test]
    fn a_member_without_the_sign_in_right_is_refused() {
        let setup = Setup::added_off(OrgRole::Member);

        let result = setup.switch(ConnectionStatus::Active, right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status(), ConnectionStatus::Disabled);
    }

    /// Ann switches on a provider Acme never added. It is not found.
    #[test]
    fn no_provider_is_not_found() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgIdentityProviderStore::empty(),
        );

        let result = setup.switch(ConnectionStatus::Active, right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before switching a provider on.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeOrgIdentityProviderStore::empty(),
        );

        let result = setup.switch(ConnectionStatus::Active, right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
