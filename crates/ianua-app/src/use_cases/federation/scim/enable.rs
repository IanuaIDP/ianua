//! Enable SCIM: set up SCIM provisioning for the tenant, or switch it back
//! on.
//!
//! The first time, a bearer token is made and handed back once. Switching
//! it back on later keeps the token it had.

use std::sync::Arc;

use ianua_domain::domains::federation::control::FederationControl;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{ScimStore, ScimTokenGenerator};
use crate::use_case::Command;

/// What switching SCIM on hands back.
pub enum SwitchedOn {
    /// SCIM was set up now. Its bearer token, shown this once.
    SetUp(Secret),
    /// SCIM was set up before and keeps the token it had.
    KeptToken,
}

/// The ports [`EnableUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EnablePorts {
    /// Loads and saves the tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// Makes bearer tokens.
    pub token_generator: Arc<dyn ScimTokenGenerator>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets SCIM provisioning up, or switches it back on.
pub struct EnableUseCase {
    ports: EnablePorts,
}

impl EnableUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EnablePorts) -> Self {
        Self { ports }
    }

    /// The endpoint to save, switched on as `control` allows, and what the
    /// caller is handed back.
    async fn switched_on(
        &self,
        existing: Option<ScimEndpoint<ResolvedTenant>>,
        control: &FederationControl<'_>,
    ) -> Result<(ScimEndpoint<ResolvedTenant>, SwitchedOn), AppError> {
        let Some(mut endpoint) = existing else {
            let (raw_token, hash) = self.ports.token_generator.generate().await.or_internal()?;
            let endpoint = ScimEndpoint::create(hash, control).map_err(AppError::from_domain)?;
            return Ok((endpoint, SwitchedOn::SetUp(raw_token)));
        };
        endpoint.enable(control).map_err(AppError::from_domain)?;
        Ok((endpoint, SwitchedOn::KeptToken))
    }
}

impl Command for EnableUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<SwitchedOn, AppError>;

    /// Switches SCIM on and records `federation.scim_enabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not configure SCIM.
    /// - `AppError::Domain` if SCIM is already on.
    /// - `AppError::Internal` on token generation, audit or persistence
    ///   failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SwitchedOn, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let existing = self.ports.scim_store.find(&tenant).await.or_internal()?;
        let (mut endpoint, switched_on) = self
            .switched_on(existing, &FederationControl::new(&authority))
            .await?;

        self.ports
            .scim_store
            .save(&tenant, &endpoint)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), endpoint.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(switched_on)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::Enablement;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{
        FakeScimStore, FakeScimTokenGenerator, test_scim_endpoint,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn use_case(store: Arc<FakeScimStore>, authorities: FakeTenantAuthorities) -> EnableUseCase {
        EnableUseCase::new(EnablePorts {
            scim_store: store,
            token_generator: Arc::new(FakeScimTokenGenerator::new()),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn holding(enabled: Enablement) -> Arc<FakeScimStore> {
        Arc::new(FakeScimStore::holding(
            &test_ctx().tenant(),
            test_scim_endpoint("hash:original", enabled),
        ))
    }

    fn enable(
        use_case: &EnableUseCase,
        audit: Arc<FakeEventDispatcher>,
    ) -> Result<SwitchedOn, AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), ()))
    }

    fn saved(store: &FakeScimStore) -> ScimEndpoint<ResolvedTenant> {
        block_on(store.find(&test_ctx().tenant())).unwrap().unwrap()
    }

    /// Ann sets SCIM up for Acme. It is switched on, she is shown its new
    /// token once, and the change is recorded.
    #[test]
    fn scim_is_set_up_with_a_new_token_and_recorded() {
        let store = Arc::new(FakeScimStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let switched_on = enable(&use_case, audit.clone()).unwrap();

        let SwitchedOn::SetUp(token) = switched_on else {
            panic!("a first setup hands back a token");
        };
        assert_eq!(token.expose(), "scim-token-1");
        assert!(saved(&store).enabled());
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.scim_enabled"]
        );
    }

    /// Ann switches SCIM back on after switching it off. It keeps the token
    /// the directory already holds, and no new one is shown.
    #[test]
    fn switching_scim_back_on_keeps_its_token() {
        let store = holding(Enablement::Disabled);
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let switched_on = enable(&use_case, Arc::new(FakeEventDispatcher::new())).unwrap();

        assert!(matches!(switched_on, SwitchedOn::KeptToken));
        assert!(saved(&store).enabled());
        assert_eq!(saved(&store).bearer_token_hash().as_str(), "hash:original");
    }

    /// Ann switches on SCIM that is already on. She is told it is in the
    /// wrong state and nothing is recorded.
    #[test]
    fn scim_that_is_on_cannot_be_switched_on_again() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            holding(Enablement::Enabled),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = enable(&use_case, audit.clone());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// The record of switching SCIM on cannot be written. The change fails
    /// rather than go unrecorded.
    #[test]
    fn enabling_fails_when_its_record_cannot_be_written() {
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            (),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Setting up SCIM without its configuration right is forbidden and
    /// leaves the tenant without an endpoint.
    #[test]
    fn a_caller_without_the_scim_right_is_refused() {
        let store = Arc::new(FakeScimStore::empty());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&[]));

        let result = enable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            block_on(store.find(&test_ctx().tenant()))
                .unwrap()
                .is_none()
        );
    }

    /// A signed-out session cannot enable SCIM.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = enable(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
