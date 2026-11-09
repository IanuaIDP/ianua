//! Generate canary token: mint a random decoy credential.
//!
//! It is not stored in any pipeline. The caller adds it to a `CanaryToken`
//! stage's tokens the way every other stage change is made: no stage takes
//! part of its settings changed on its own, and one field is no reason to
//! start.

use std::sync::Arc;

use ianua_domain::domains::proxy::issued::CanaryIssue;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SecureTokenGenerator;
use crate::use_case::Command;

/// Marks a value as a canary decoy, recognizable at a glance if it ever
/// turns up somewhere it should not, such as a log or a leaked response.
const CANARY_PREFIX: &str = "sk-decoy-";

/// Random bytes behind each decoy.
const CANARY_BYTES: usize = 24;

/// The ports [`GenerateCanaryTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GenerateCanaryTokenPorts {
    /// Makes the token's random part.
    pub token_generator: Arc<dyn SecureTokenGenerator>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Generates a canary decoy token.
pub struct GenerateCanaryTokenUseCase {
    ports: GenerateCanaryTokenPorts,
}

impl GenerateCanaryTokenUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GenerateCanaryTokenPorts) -> Self {
        Self { ports }
    }
}

impl Command for GenerateCanaryTokenUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<String, AppError>;

    /// A new canary decoy token. Records `proxy.canary_token_generated`,
    /// without the token.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines.
    /// - `AppError::Internal` when the audit record cannot be written.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<String, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let mut issue = CanaryIssue::<ResolvedTenant>::issue(&RoutingControl::new(&authority))
            .map_err(AppError::from_domain)?;
        let random = self.ports.token_generator.generate(CANARY_BYTES);
        let token = format!("{CANARY_PREFIX}{}", random.expose());

        auditor
            .dispatch_by(&caller.actor(), issue.take_events(&caller.tenant()))
            .await
            .or_internal()?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::shared::security::secret::Secret;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Hands out `1`, `2` and so on, so successive tokens differ.
    struct CountingGenerator(Mutex<u32>);

    impl SecureTokenGenerator for CountingGenerator {
        fn generate(&self, _byte_len: usize) -> Secret {
            let mut count = self.0.lock().unwrap();
            *count += 1;
            Secret::new(count.to_string())
        }
    }

    fn generate(
        use_case: &GenerateCanaryTokenUseCase,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<String, AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), ()))
    }

    fn with(authorities: FakeTenantAuthorities) -> GenerateCanaryTokenUseCase {
        GenerateCanaryTokenUseCase::new(GenerateCanaryTokenPorts {
            tenant_authorities: Arc::new(authorities),
            ..GenerateCanaryTokenPorts::fakes()
        })
    }

    /// Ann asks for a decoy. It carries the decoy prefix, and that one was
    /// made is recorded.
    #[test]
    fn a_decoy_carries_its_prefix() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let token = generate(&with(FakeTenantAuthorities::holding_everything()), &audit).unwrap();

        assert!(token.starts_with("sk-decoy-"));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.canary_token_generated"]
        );
    }

    /// Two decoys in a row differ, each made from fresh randomness.
    #[test]
    fn successive_decoys_differ() {
        let use_case = GenerateCanaryTokenUseCase::new(GenerateCanaryTokenPorts {
            token_generator: Arc::new(CountingGenerator(Mutex::new(0))),
            ..GenerateCanaryTokenPorts::fakes()
        });
        let audit = Arc::new(FakeEventDispatcher::new());

        let first = generate(&use_case, &audit).unwrap();
        let second = generate(&use_case, &audit).unwrap();

        assert_ne!(first, second);
    }

    /// Pipeline view rights do not permit generating a canary decoy.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let result = generate(
            &with(FakeTenantAuthorities::holding(&[
                SystemPermission::Pipeline(PipelineAction::View),
            ])),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session is refused when requesting a canary decoy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = generate(
            &with(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
