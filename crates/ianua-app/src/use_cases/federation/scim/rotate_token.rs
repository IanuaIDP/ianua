//! Rotate SCIM token: make a new bearer token, so the old one stops
//! working at once. The new token is handed back once.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{ScimStore, ScimTokenGenerator};
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_scim_endpoint;

/// The ports [`RotateTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateTokenPorts {
    /// Loads and saves the tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// Makes bearer tokens.
    pub token_generator: Arc<dyn ScimTokenGenerator>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces the SCIM bearer token.
pub struct RotateTokenUseCase {
    ports: RotateTokenPorts,
}

impl RotateTokenUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateTokenPorts) -> Self {
        Self { ports }
    }
}

impl Command for RotateTokenUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Secret, AppError>;

    /// Replaces the SCIM bearer token, records
    /// `federation.scim_token_rotated`, and hands back the new token.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not configure SCIM.
    /// - `AppError::NotFound` if SCIM was never set up.
    /// - `AppError::Internal` on token generation, audit or persistence
    ///   failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<Secret, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::ConfigureScim)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut endpoint = existing_scim_endpoint(self.ports.scim_store.as_ref(), &tenant).await?;
        let (raw_token, hash) = self.ports.token_generator.generate().await.or_internal()?;
        endpoint
            .rotate_token(hash, &control)
            .map_err(AppError::from_domain)?;

        self.ports
            .scim_store
            .save(&tenant, &endpoint)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), endpoint.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(raw_token)
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

    fn set_up() -> Arc<FakeScimStore> {
        Arc::new(FakeScimStore::holding(
            &test_ctx().tenant(),
            test_scim_endpoint("hash:old", Enablement::Enabled),
        ))
    }

    fn use_case(
        store: Arc<FakeScimStore>,
        authorities: FakeTenantAuthorities,
    ) -> RotateTokenUseCase {
        RotateTokenUseCase::new(RotateTokenPorts {
            scim_store: store,
            token_generator: Arc::new(FakeScimTokenGenerator::new()),
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn rotate(
        use_case: &RotateTokenUseCase,
        audit: Arc<FakeEventDispatcher>,
    ) -> Result<Secret, AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit), ()))
    }

    fn saved_hash(store: &FakeScimStore) -> String {
        block_on(store.find(&test_ctx().tenant()))
            .unwrap()
            .unwrap()
            .bearer_token_hash()
            .as_str()
            .to_owned()
    }

    /// Ann rotates the SCIM token after it leaked. She is shown the new one,
    /// the old one no longer matches, and the rotation is recorded.
    #[test]
    fn the_token_is_replaced_and_recorded() {
        let store = set_up();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let token = rotate(&use_case, audit.clone()).unwrap();

        assert_eq!(token.expose(), "scim-token-1");
        assert_eq!(saved_hash(&store), "hash:scim-token-1");
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.scim_token_rotated"]
        );
    }

    /// The record of the rotation cannot be written. The rotation fails
    /// rather than go unrecorded.
    #[test]
    fn rotating_fails_when_its_record_cannot_be_written() {
        let use_case = use_case(set_up(), FakeTenantAuthorities::holding_everything());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            (),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Ann rotates the token of SCIM her tenant never set up. It is not
    /// found and nothing is recorded.
    #[test]
    fn scim_that_was_never_set_up_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = rotate(&use_case, audit.clone());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Rotating a SCIM token without its configuration right is forbidden
    /// and preserves the saved token hash.
    #[test]
    fn a_caller_without_the_scim_right_is_refused() {
        let store = set_up();
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding(&[]));

        let result = rotate(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved_hash(&store), "hash:old");
    }

    /// A caller without the SCIM configuration right receives a permission
    /// refusal even when no endpoint exists to rotate.
    #[test]
    fn a_caller_without_the_scim_right_learns_nothing_of_missing_scim() {
        let use_case = use_case(
            Arc::new(FakeScimStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = rotate(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot rotate the SCIM token.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = use_case(
            set_up(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = rotate(&use_case, Arc::new(FakeEventDispatcher::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
