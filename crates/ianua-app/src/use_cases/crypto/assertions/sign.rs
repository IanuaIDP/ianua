//! Signing the identity assertion the gateway hands an upstream as
//! `X-Ianua-Assertion`.
//!
//! The gateway asks the domain what the assertion says, from the request's
//! verified caller, and this signs it with the tenant's assertion key. Deny
//! by default: a tenant with no key that signs, a key that does not open,
//! a failed signing or an assertion for another tenant is an error, and
//! the gateway forwards nothing on it.

use std::sync::Arc;

use ianua_domain::domains::proxy::assertion::UpstreamAssertion;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{AssertionSigner, AssertionSigningKeys};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The ports [`SignUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignPorts {
    /// Reads the key that signs the tenant's assertions, opened.
    pub keys: Arc<dyn AssertionSigningKeys>,
    /// Signs the assertion with it.
    pub signer: Arc<dyn AssertionSigner>,
}

/// Signs an upstream identity assertion with the tenant's assertion key.
///
/// The gateway runs it as it forwards a request whose caller is known. It
/// only reads: what is signed is recorded with the request, not here.
pub struct SignUseCase {
    ports: SignPorts,
}

impl SignUseCase {
    /// A use case signing through `ports`.
    #[must_use]
    pub fn new(ports: SignPorts) -> Self {
        Self { ports }
    }
}

impl Query for SignUseCase {
    type Caller = ScopedTenant;
    type Input = UpstreamAssertion;
    type Output = Result<Secret, AppError>;

    /// `assertion`, made in `tenant`, signed with the tenant's assertion
    /// key, in compact form.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the assertion was made in another
    ///   tenant: one tenant's key never vouches for another's caller.
    /// - `AppError::Internal` when the tenant holds no key that signs, its
    ///   key cannot be read or opened, or the signing fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        assertion: UpstreamAssertion,
    ) -> Result<Secret, AppError> {
        if assertion.tenant_id() != **tenant {
            return Err(AppError::Forbidden(message!(
                "crypto-an-assertion-is-signed-only-with",
                "an assertion is signed only with its own tenant's key"
            )));
        }
        let Some(key) = self.ports.keys.signing(tenant).await.or_internal()? else {
            return Err(AppError::internal_msg(
                "the tenant holds no assertion key that signs",
            ));
        };
        self.ports.signer.sign(&assertion, &key).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, AssertionSigningKey, NewAssertionKey,
    };
    use ianua_domain::domains::proxy::request::context::{
        Caller, PipelineContext, UserSignIn, Verified,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        CorrelationId, Expiry, Fact, Issuer, KeyId, PipelineId, PublicKeyPem, ServiceId, TenantId,
        UserId,
    };

    use super::*;
    use crate::test_support::crypto::{FakeAssertionKeyStore, FakeAssertionSigner};
    use crate::test_support::{block_on, test_ctx};

    fn key(kid: &str) -> AssertionKey {
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    /// Ann's request in `tenant_id`, let through, forwarded to a service.
    fn assertion_in(tenant_id: TenantId, ann: UserId) -> UpstreamAssertion {
        let mut context = PipelineContext::new(tenant_id, PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        context
            .authenticate(Verified {
                caller: Caller::User {
                    user_id: ann,
                    sign_in: UserSignIn::Token,
                },
                expiry: Expiry::Never,
            })
            .unwrap();
        context.authorize();
        UpstreamAssertion::for_request(&context, ServiceId::new(), clock::now())
            .unwrap()
            .unwrap()
    }

    fn use_case_over(store: FakeAssertionKeyStore) -> (SignUseCase, Arc<FakeAssertionSigner>) {
        let signer = Arc::new(FakeAssertionSigner::default());
        let use_case = SignUseCase::new(SignPorts {
            keys: Arc::new(store),
            signer: signer.clone(),
        });
        (use_case, signer)
    }

    /// Acme's gateway forwards Ann's request. The assertion is signed with
    /// Acme's assertion key and names her.
    #[test]
    fn an_assertion_is_signed_with_the_tenants_key() {
        let ann = UserId::new();
        let store = FakeAssertionKeyStore::holding(&AssertionKeySet::new(key("a1")));
        let (use_case, signer) = use_case_over(store);

        let signed = block_on(use_case.execute(
            &test_ctx().tenant(),
            assertion_in(test_ctx().tenant_id(), ann),
        ))
        .unwrap();

        assert_eq!(signed.expose(), format!("assertion.a1.{}", ann.as_uuid()));
        assert_eq!(signer.signed.lock().unwrap().len(), 1);
    }

    /// A tenant with no assertion key gets an internal error and the signer
    /// receives no assertion.
    #[test]
    fn a_tenant_without_an_assertion_key_signs_nothing() {
        let (use_case, signer) = use_case_over(FakeAssertionKeyStore::empty());

        let signed = block_on(use_case.execute(
            &test_ctx().tenant(),
            assertion_in(test_ctx().tenant_id(), UserId::new()),
        ));

        assert!(matches!(signed, Err(AppError::Internal(_))));
        assert!(signer.signed.lock().unwrap().is_empty());
    }

    /// An assertion for another tenant is forbidden before the signer
    /// receives it.
    #[test]
    fn an_assertion_from_another_tenant_is_refused() {
        let store = FakeAssertionKeyStore::holding(&AssertionKeySet::new(key("a1")));
        let (use_case, signer) = use_case_over(store);

        let signed = block_on(use_case.execute(
            &test_ctx().tenant(),
            assertion_in(TenantId::new(), UserId::new()),
        ));

        assert!(matches!(signed, Err(AppError::Forbidden(_))));
        assert!(signer.signed.lock().unwrap().is_empty());
    }

    /// An unreachable assertion-key store returns an internal error instead
    /// of a signed assertion.
    #[test]
    fn a_key_store_that_fails_signs_nothing() {
        struct Unreachable;

        impl crate::ports::TenantScoped for Unreachable {}

        #[async_trait::async_trait]
        impl AssertionSigningKeys for Unreachable {
            async fn signing(
                &self,
                _tenant_id: &ScopedTenant,
            ) -> Result<Option<AssertionSigningKey>, DomainError> {
                Err(DomainError::infra_msg("the database is down"))
            }
        }

        let use_case = SignUseCase::new(SignPorts {
            keys: Arc::new(Unreachable),
            ..SignPorts::fakes()
        });

        let signed = block_on(use_case.execute(
            &test_ctx().tenant(),
            assertion_in(test_ctx().tenant_id(), UserId::new()),
        ));

        assert!(matches!(signed, Err(AppError::Internal(_))));
    }
}
