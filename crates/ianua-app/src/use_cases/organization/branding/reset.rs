//! Returning the organization's own dashboard and mail to the platform's
//! look, every part at once.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgBrandingStore;
use crate::use_case::Command;
use crate::use_cases::organization::branding::lookup::current_org_branding;

/// The ports [`ResetOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetOrgPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Organizations' branding.
    pub branding: Arc<dyn OrgBrandingStore>,
}

/// Returns the caller's organization's branding to the platform's.
pub struct ResetOrgUseCase {
    ports: ResetOrgPorts,
}

impl ResetOrgUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ResetOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for ResetOrgUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Returns the logo, the color and the sender name to the platform's,
    /// saves the branding and records `organization.branding_reset`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the branding.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.branding.as_ref();
        let mut branding = current_org_branding(store, organization.id()).await?;
        branding.reset(&control).map_err(AppError::from_domain)?;
        store.save(&branding).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), branding.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::branding::OrgBranding;
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgBrandingStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ResetOrgUseCase,
        store: Arc<FakeOrgBrandingStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            let store = Arc::new(FakeOrgBrandingStore::empty());
            Self {
                uc: ResetOrgUseCase::new(ResetOrgPorts {
                    org_actors: Arc::new(actors),
                    branding: store.clone(),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn reset(&self) -> Result<(), AppError> {
            block_on(
                self.uc
                    .execute(&test_org_caller(), &test_auditor(self.audit.clone()), ()),
            )
        }

        fn stored(&self) -> Option<OrgBranding> {
            self.store.stored(&test_org_caller().organization_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ada, an admin, returns Acme's look to the platform's. It is saved
    /// and the reset recorded.
    #[test]
    fn an_admin_resets_the_branding() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        setup.reset().unwrap();

        let stored = setup.stored().unwrap();
        assert!(stored.logo_url().is_none());
        assert_eq!(setup.recorded(), ["organization.branding_reset"]);
    }

    /// A plain member cannot reset branding; nothing is saved or recorded.
    #[test]
    fn a_member_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.reset();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before resetting branding.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.reset();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
