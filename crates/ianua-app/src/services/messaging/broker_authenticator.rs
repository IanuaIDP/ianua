//! Broker authenticator: layer A0 of the message plane (connection
//! authentication).
//!
//! Resolves a presented task token to an [`AgentPrincipal`], holds its `iss`
//! to the issuer of the tenant it names, and re-checks that its delegation
//! is still live, so a revoked agent cannot ride an unexpired token onto the
//! bus. Deny by default: any verification failure, an issuer that is not
//! the tenant's own, a tenant whose issuer cannot be worked out, and any
//! revoked or missing delegation, rejects the connection.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::error::AppError;
use crate::ports::agents::DelegationRevocationCheck;
use crate::ports::broker::{
    AgentPrincipal, BrokerAuthenticator, TaskTokenVerifier, VerifiedTaskToken,
};
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;

/// Authenticates broker connections from task tokens, backed by the tenants'
/// issuers and the delegation graph's revocation state.
pub struct DelegationBrokerAuthenticator {
    token_verifier: Arc<dyn TaskTokenVerifier>,
    issuers: TenantIssuers,
    revocation: Arc<dyn DelegationRevocationCheck>,
}

impl DelegationBrokerAuthenticator {
    /// Creates the authenticator over a token verifier, the issuers tokens
    /// must name, and a revocation check.
    #[must_use]
    pub fn new(
        token_verifier: Arc<dyn TaskTokenVerifier>,
        issuers: TenantIssuers,
        revocation: Arc<dyn DelegationRevocationCheck>,
    ) -> Self {
        Self {
            token_verifier,
            issuers,
            revocation,
        }
    }

    /// The principal `verified` names, once its issuer is its tenant's own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the issuer is another, or the
    ///   tenant or its organization is not on record.
    /// - [`DomainError::Infrastructure`] when the tenant cannot be read.
    async fn issued_by_its_tenant(
        &self,
        verified: VerifiedTaskToken,
    ) -> Result<AgentPrincipal, DomainError> {
        let expected = match self.issuers.of(&verified.principal.tenant_id).await {
            Ok(issuer) => issuer,
            Err(AppError::NotFound(_)) => {
                return Err(DomainError::unauthorized(message!(
                    "messaging-the-token-names-no-tenant-of",
                    "the token names no tenant of record"
                )));
            }
            Err(failed) => return Err(DomainError::infra(failed)),
        };
        if verified.issuer != expected {
            return Err(DomainError::unauthorized(message!(
                "messaging-the-token-was-not-issued-by",
                "the token was not issued by its tenant's issuer"
            )));
        }
        Ok(verified.principal)
    }
}

#[async_trait]
impl BrokerAuthenticator for DelegationBrokerAuthenticator {
    async fn authenticate(&self, credential: &Secret) -> Result<AgentPrincipal, DomainError> {
        let verified = self.token_verifier.verify(credential).await?;
        let principal = self.issued_by_its_tenant(verified).await?;
        let revoked = self
            .revocation
            .is_revoked(
                &ScopedTenant::from_verified_credential(principal.tenant_id),
                &principal.delegation_id,
            )
            .await?;
        if revoked {
            return Err(DomainError::unauthorized(message!(
                "messaging-delegation-revoked",
                "delegation revoked"
            )));
        }
        Ok(principal)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::types::{AgentId, DelegationId, Issuer, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::{Fake, block_on, test_ctx};

    /// Verifies every token as one verified token, or none.
    struct StubVerifier {
        verified: Option<VerifiedTaskToken>,
    }

    #[async_trait]
    impl TaskTokenVerifier for StubVerifier {
        async fn verify(&self, _credential: &Secret) -> Result<VerifiedTaskToken, DomainError> {
            self.verified
                .clone()
                .ok_or_else(|| DomainError::unauthorized("bad token"))
        }
    }

    /// The test tenant's own issuer.
    fn acmes_issuer() -> Issuer {
        block_on(TenantIssuers::fake().of(&test_ctx().tenant_id())).unwrap()
    }

    /// `principal`'s token, issued by `issuer`.
    fn issued(principal: AgentPrincipal, issuer: Issuer) -> VerifiedTaskToken {
        VerifiedTaskToken { principal, issuer }
    }

    /// Whether every delegation is still live.
    #[derive(Clone, Copy)]
    enum Delegations {
        Live,
        Revoked,
    }

    impl TenantScoped for Delegations {}

    #[async_trait]
    impl DelegationRevocationCheck for Delegations {
        async fn is_revoked(
            &self,
            _tenant_id: &ScopedTenant,
            _delegation_id: &DelegationId,
        ) -> Result<bool, DomainError> {
            Ok(matches!(self, Self::Revoked))
        }
    }

    /// An agent of `tenant_id` acting under a delegation from a person.
    fn principal_in(tenant_id: TenantId) -> AgentPrincipal {
        AgentPrincipal {
            tenant_id,
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            subject: PrincipalRef::User(UserId::new()),
            caps: CapabilitySet::empty(),
        }
    }

    fn principal() -> AgentPrincipal {
        principal_in(test_ctx().tenant_id())
    }

    fn authenticator(
        verified: Option<VerifiedTaskToken>,
        delegations: Delegations,
    ) -> DelegationBrokerAuthenticator {
        DelegationBrokerAuthenticator::new(
            Arc::new(StubVerifier { verified }),
            TenantIssuers::fake(),
            Arc::new(delegations),
        )
    }

    fn token() -> Secret {
        Secret::new("token")
    }

    /// Ann's agent presents a valid token of Acme's issuer under a live
    /// delegation, and connects as itself.
    #[test]
    fn authenticates_a_valid_live_token() {
        let expected = principal();
        let auth = authenticator(
            Some(issued(expected.clone(), acmes_issuer())),
            Delegations::Live,
        );

        let principal = block_on(auth.authenticate(&token())).unwrap();

        assert_eq!(principal, expected);
    }

    /// A verified token naming another issuer is refused broker authentication.
    #[test]
    fn rejects_a_token_of_another_issuer() {
        let other = Issuer::new("https://elsewhere.example").unwrap();
        let auth = authenticator(Some(issued(principal(), other)), Delegations::Live);

        let result = block_on(auth.authenticate(&token()));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// A token for an unknown tenant is refused even when token verification succeeds.
    #[test]
    fn rejects_a_token_of_a_tenant_not_on_record() {
        let auth = authenticator(
            Some(issued(principal_in(TenantId::new()), acmes_issuer())),
            Delegations::Live,
        );

        let result = block_on(auth.authenticate(&token()));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// A verified token is refused when its delegation has been revoked.
    #[test]
    fn rejects_a_revoked_delegation() {
        let auth = authenticator(
            Some(issued(principal(), acmes_issuer())),
            Delegations::Revoked,
        );

        let result = block_on(auth.authenticate(&token()));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// Token verification failure prevents broker authentication.
    #[test]
    fn rejects_an_unverifiable_token() {
        let auth = authenticator(None, Delegations::Live);

        let result = block_on(auth.authenticate(&token()));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }
}
