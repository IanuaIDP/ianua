//! The gateway's message signatures, signed with the tenant's assertion
//! key: the request it forwards and the answer it hands back, as the
//! response stages wrote their claims.
//!
//! The key is the one that signs the tenant's assertions now, read through
//! [`AssertionSigningKeys`] (the gateway wires the cached read), so an
//! upstream checks a signature against the same published assertion keys
//! it checks `X-Ianua-Assertion` against. No key, no signature: a tenant
//! with none is an error, and the gateway forwards nothing on it.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::crypto::{AssertionSigningKeys, MessageSigner};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::crypto::tokens::assertions::Pkcs8MessageSigner;

/// The signer of the gateway's message signatures, over the tenant's
/// assertion keys.
pub struct AssertionKeyMessageSigner {
    keys: Arc<dyn AssertionSigningKeys>,
}

impl std::fmt::Debug for AssertionKeyMessageSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionKeyMessageSigner")
            .finish_non_exhaustive()
    }
}

impl AssertionKeyMessageSigner {
    /// A signer with the key `keys` opens for each tenant.
    #[must_use]
    pub fn new(keys: Arc<dyn AssertionSigningKeys>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl MessageSigner for AssertionKeyMessageSigner {
    async fn sign(&self, tenant_id: &TenantId, claims_json: &str) -> Result<String, DomainError> {
        let tenant = ScopedTenant::from_request_host(*tenant_id);
        let Some(key) = self.keys.signing(&tenant).await? else {
            return Err(DomainError::infra_msg(
                "the tenant holds no assertion key that signs",
            ));
        };
        Pkcs8MessageSigner.sign(claims_json, &key)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::TenantScoped;
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, AssertionSigningKey, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::jwt_type::JwtType;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{KeyId, PublicKeyPem};
    use serde_json::Value;

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{Compact, JwsError, PublicKey};

    /// The tenant's opened assertion key, or none.
    struct Opened(Option<AssertionSigningKey>);

    impl TenantScoped for Opened {}

    #[async_trait]
    impl AssertionSigningKeys for Opened {
        async fn signing(
            &self,
            _: &ScopedTenant,
        ) -> Result<Option<AssertionSigningKey>, DomainError> {
            Ok(self.0.clone())
        }
    }

    /// A fresh ES256 assertion key `a1`, opened, and its public half.
    fn opened_key() -> (AssertionSigningKey, PublicKey) {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new("a1").unwrap(),
            public_key: PublicKeyPem::new(public.clone()).unwrap(),
            private_key: Secret::new(private.clone()),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        let signing = AssertionSigningKey::of(&set, Secret::new(private)).unwrap();
        (
            signing,
            PublicKey::from_pem(SigningAlgorithm::Es256, &public).unwrap(),
        )
    }

    /// Acme's gateway signs the answer it hands back with Acme's assertion
    /// key: the signature verifies with the published half as a message
    /// signature, names the key, and carries the claims as written.
    #[tokio::test]
    async fn a_signature_verifies_with_the_published_assertion_key() {
        let (key, public) = opened_key();
        let signer = AssertionKeyMessageSigner::new(Arc::new(Opened(Some(key))));

        let jws = signer
            .sign(&TenantId::new(), r#"{"sub":"response","status":200}"#)
            .await
            .unwrap();

        let token = Compact::parse(&jws).unwrap();
        let claims: Value = token.verified(&public, JwtType::MessageSignature).unwrap();
        assert_eq!(token.header().kid.as_deref(), Some("a1"));
        assert_eq!(claims["sub"], "response");
        assert_eq!(claims["status"], 200);
    }

    /// A message signature fails the access-token type check.
    #[tokio::test]
    async fn a_signature_is_never_taken_for_an_access_token() {
        let (key, public) = opened_key();
        let signer = AssertionKeyMessageSigner::new(Arc::new(Opened(Some(key))));

        let jws = signer
            .sign(&TenantId::new(), r#"{"sub":"request"}"#)
            .await
            .unwrap();

        let as_access = Compact::parse(&jws)
            .unwrap()
            .verified::<Value>(&public, JwtType::Access);
        assert!(matches!(as_access, Err(JwsError::WrongType)));
    }

    /// A tenant without an assertion key receives an infrastructure error instead of a signature.
    #[tokio::test]
    async fn a_tenant_without_an_assertion_key_signs_nothing() {
        let signer = AssertionKeyMessageSigner::new(Arc::new(Opened(None)));

        let signed = signer.sign(&TenantId::new(), r#"{"sub":"request"}"#).await;

        assert!(matches!(signed, Err(DomainError::Infrastructure(_))));
    }
}
