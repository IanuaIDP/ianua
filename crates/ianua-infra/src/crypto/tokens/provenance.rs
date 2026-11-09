//! Message provenance: the signed authorship an agent's message carries on
//! the message plane, sealed with the tenant's active key and typed so no
//! other check takes it for a token of its own.
//!
//! The seal names the sender (`snd`), whom it acts for (`obo`, root last),
//! the delegation it acts under (`jti`), and the digest of the payload it
//! is bound to (`ph`).

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::broker::{MessageProvenanceSigner, MessageProvenanceVerifier};
use ianua_app::ports::crypto::SigningKeyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::provenance::{
    MessageProvenance, PayloadHash, SealedProvenance,
};
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationId, Lifetime, PrincipalRef};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::issued::made;
use crate::crypto::jws::{Compact, TokenHeader, signed};
use crate::crypto::tokens::claims::{TenantKeys, refused};

/// What a provenance seal says.
#[derive(Debug, Serialize, Deserialize)]
struct ProvenanceClaims {
    snd: Uuid,
    obo: Vec<String>,
    jti: Uuid,
    ph: String,
}

/// The sealer of message provenance, with the tenant's active key.
pub struct Pkcs8MessageProvenanceSigner {
    keys: TenantKeys,
}

impl Pkcs8MessageProvenanceSigner {
    /// A sealer with the tenant keys `signing_keys` holds.
    #[must_use]
    pub fn new(signing_keys: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
        }
    }
}

/// The opener of message provenance, against the tenant's keys.
pub struct Pkcs8MessageProvenanceVerifier {
    keys: TenantKeys,
}

impl Pkcs8MessageProvenanceVerifier {
    /// An opener with the tenant keys `signing_keys` holds, a rotated key
    /// still opening seals for `grace`.
    #[must_use]
    pub fn new(signing_keys: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
        }
    }
}

#[async_trait]
impl MessageProvenanceSigner for Pkcs8MessageProvenanceSigner {
    async fn sign(
        &self,
        tenant_id: &ScopedTenant,
        provenance: &MessageProvenance,
    ) -> Result<SealedProvenance, DomainError> {
        let claims = ProvenanceClaims {
            snd: *provenance.sender().as_uuid(),
            obo: provenance
                .on_behalf_of()
                .iter()
                .map(PrincipalRef::label)
                .collect(),
            jti: *provenance.delegation_id().as_uuid(),
            ph: provenance.payload_hash().to_hex(),
        };
        let claims = serde_json::to_string(&claims).map_err(DomainError::infra)?;
        let active = self.keys.active(tenant_id).await?;
        let token = signed(
            &claims,
            TokenHeader::new(
                JwtType::MessageProvenance,
                active.key.kid().as_str(),
                active.key.algorithm(),
            ),
            &active.private,
        )
        .map_err(DomainError::infra)?;
        made(SealedProvenance::new(token))
    }
}

#[async_trait]
impl MessageProvenanceVerifier for Pkcs8MessageProvenanceVerifier {
    async fn verify(
        &self,
        tenant_id: &ScopedTenant,
        token: &SealedProvenance,
    ) -> Result<MessageProvenance, DomainError> {
        let token = Compact::parse(token.as_str()).map_err(|_| refused("the seal is no JWT"))?;
        let key = self.keys.checking(tenant_id, &token).await?;
        let claims: ProvenanceClaims = token
            .verified(&key, JwtType::MessageProvenance)
            .map_err(|_| refused("the seal was not made with the tenant's key"))?;
        let on_behalf_of = claims
            .obo
            .iter()
            .map(|label| PrincipalRef::from_label(label))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| refused("the seal names a principal that is not one"))?;
        let payload_hash = PayloadHash::from_hex(&claims.ph)
            .map_err(|_| refused("the seal's digest is no digest"))?;
        MessageProvenance::new(
            AgentId::from_uuid(claims.snd),
            on_behalf_of,
            DelegationId::from_uuid(claims.jti),
            payload_hash,
        )
        .map_err(|_| refused("the seal names too long a chain"))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::crypto::FakeSigningKeyStore;
    use ianua_domain::types::{TenantId, UserId};

    use super::*;
    use crate::crypto::tokens::claims::tests::{grace, key_set};

    fn provenance() -> MessageProvenance {
        MessageProvenance::new(
            AgentId::new(),
            vec![PrincipalRef::User(UserId::new())],
            DelegationId::new(),
            PayloadHash::from_bytes([7; 32]),
        )
        .unwrap()
    }

    /// A seal opens to the provenance it was made from.
    #[tokio::test]
    async fn a_seal_opens_to_its_provenance() {
        let tenant = ScopedTenant::for_background(TenantId::new());
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*tenant, key_set().0);
        let signer = Pkcs8MessageProvenanceSigner::new(keys.clone(), grace());
        let verifier = Pkcs8MessageProvenanceVerifier::new(keys, grace());
        let made = provenance();

        let sealed = signer.sign(&tenant, &made).await.unwrap();
        let opened = verifier.verify(&tenant, &sealed).await.unwrap();

        assert_eq!(opened.sender(), made.sender());
        assert_eq!(opened.delegation_id(), made.delegation_id());
        assert!(opened.binds_to(made.payload_hash()));
    }

    /// A provenance seal cannot be verified with another tenant's keys.
    #[tokio::test]
    async fn another_tenants_seal_is_refused() {
        let acme = ScopedTenant::for_background(TenantId::new());
        let other = ScopedTenant::for_background(TenantId::new());
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*acme, key_set().0);
        keys.put(*other, key_set().0);
        let sealed = Pkcs8MessageProvenanceSigner::new(keys.clone(), grace())
            .sign(&acme, &provenance())
            .await
            .unwrap();

        let opened = Pkcs8MessageProvenanceVerifier::new(keys, grace())
            .verify(&other, &sealed)
            .await;

        assert!(matches!(opened, Err(DomainError::Unauthorized(_))));
    }
}
