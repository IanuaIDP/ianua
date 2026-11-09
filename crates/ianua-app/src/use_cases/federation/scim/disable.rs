//! Disable SCIM: stop SCIM provisioning for the tenant, keeping its token
//! and settings for when it is switched back on.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ScimStore;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_scim_endpoint;

/// The ports [`DisableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Loads and saves the tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Switches SCIM provisioning off.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Switches SCIM off and records `federation.scim_disabled`. Incoming
    /// SCIM requests are refused from then on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not configure SCIM.
    /// - `AppError::NotFound` if SCIM was never set up.
    /// - `AppError::Domain` if SCIM is already off.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::ConfigureScim)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut endpoint = existing_scim_endpoint(self.ports.scim_store.as_ref(), &tenant).await?;
        endpoint.disable(&control).map_err(AppError::from_domain)?;

        self.ports
            .scim_store
            .save(&tenant, &endpoint)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), endpoint.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::Enablement;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeScimStore, test_scim_endpoint};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn holding(enabled: Enablement) -> Arc<FakeScimStore> {
        Arc::new(FakeScimStore::holding(
            &test_ctx().tenant(),
            test_scim_endpoint("hash:token", enabled),
        ))
    }

    fn use_case(store: Arc<FakeScimStore>, authorities: FakeTenantAuthorities) -> DisableUseCase {
        DisableUseCase::new(DisablePorts {
            scim_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn disable(use_case: &DisableUseCase, audit: Arc<FakeEventDispatcher>) -> Result<(), AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), ()))
    }

    fn enabled(store: &FakeScimStore) -> bool {
        block_on(store.find(&test_ctx().tenant()))
            .unwrap()
            .unwrap()
            .enabled()
    }

    /// Ann switches SCIM off. It is saved off and the change is recorded.
    #[test]
    fn scim_is_switched_off_and_recorded() {
        let store = holding(Enablement::Enabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        disable(&use_case, audit.clone()).unwrap();

        assert!(!enabled(&store));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.scim_disabled"]
        );
    }

    /// The record of switching SCIM off cannot be written. The change fails
    /// rather than go unrecorded.
    #[test]
    fn disabling_fails_when_its_record_cannot_be_written() {
        let use_case = use_case(
            holding(Enablement::Enabled),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            (),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Ann switches off SCIM that is already off. She is told it is in the
    /// wrong state.
    #[test]
    fn scim_that_is_off_cannot_be_switched_off_again() {
        let use_case = use_case(
            holding(Enablement::Disabled),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann switches off SCIM her tenant never set up. It is not found and
    /// nothing is recorded.
    #[test]
    fn scim_that_was_never_set_up_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = disable(&use_case, audit.clone());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Disabling SCIM without its configuration right is forbidden and leaves
    /// the endpoint enabled.
    #[test]
    fn a_caller_without_the_scim_right_is_refused() {
        let store = holding(Enablement::Enabled);
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&[]));

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(enabled(&store));
    }

    /// A caller without the SCIM configuration right receives a permission
    /// refusal even when no endpoint exists.
    #[test]
    fn a_caller_without_the_scim_right_learns_nothing_of_missing_scim() {
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot disable SCIM.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            holding(Enablement::Enabled),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = disable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
