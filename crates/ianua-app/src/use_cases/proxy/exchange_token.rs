//! Exchange a token: the narrowed token the gateway's TokenExchange stage
//! hands an upstream in place of the caller's own credential.
//!
//! The gateway reads what the request proved into the domain's
//! [`ExchangeGrounds`] and hands it over with the route's
//! [`TokenExchangeConfig`]. The domain narrows the token: one audience, the
//! scopes asked for that the caller holds, minutes at most and never past
//! the caller's credential. This signs it with the tenant's assertion key,
//! typed `ianua-exchanged+jwt`, so neither the gateway nor the API ever
//! takes it as an access token, and an upstream checks it against the
//! assertion keys the tenant publishes.
//!
//! Deny by default: grounds of another tenant, a caller holding none of
//! what is asked, a credential run out, a tenant with no key that signs or
//! a signing that fails each gives no token, and the gateway forwards
//! nothing without one.

use std::fmt;
use std::sync::Arc;

use ianua_domain::domains::proxy::exchange::{ExchangeGrounds, ExchangedToken};
use ianua_domain::domains::proxy::stages::stage::TokenExchangeConfig;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TokenId;
use time::OffsetDateTime;

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{AssertionSigner, AssertionSigningKeys};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// What a token is exchanged for.
pub struct TokenExchangeRequest {
    /// What the request proved: who it is for, what they hold, until when.
    pub grounds: ExchangeGrounds,
    /// What the route's TokenExchange stage asks the token to be.
    pub config: TokenExchangeConfig,
}

/// A narrowed token, signed. The token is a credential for its upstream
/// and is never printed.
pub struct ExchangedForUpstream {
    /// The signed token, in compact form, for the upstream's
    /// `Authorization` header.
    pub token: Secret,
    /// When the upstream stops accepting it.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for ExchangedForUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangedForUpstream")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The ports [`ExchangeTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExchangeTokenPorts {
    /// Reads the key that signs the tenant's assertions, opened.
    pub keys: Arc<dyn AssertionSigningKeys>,
    /// Signs the exchanged token with it.
    pub signer: Arc<dyn AssertionSigner>,
}

/// Mints the narrowed token a route's TokenExchange stage asks for.
///
/// The gateway runs it for each request through such a stage. It only
/// reads: what was minted is on the request's record, not here.
pub struct ExchangeTokenUseCase {
    ports: ExchangeTokenPorts,
}

impl ExchangeTokenUseCase {
    /// A use case signing through `ports`.
    #[must_use]
    pub fn new(ports: ExchangeTokenPorts) -> Self {
        Self { ports }
    }

    /// `token` signed with the tenant's assertion key.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenant holds no key that signs, its
    /// key cannot be read or opened, or the signing fails.
    async fn signed(
        &self,
        tenant: &ScopedTenant,
        token: &ExchangedToken,
    ) -> Result<Secret, AppError> {
        let Some(key) = self.ports.keys.signing(tenant).await.or_internal()? else {
            return Err(AppError::internal_msg(
                "the tenant holds no assertion key that signs",
            ));
        };
        self.ports
            .signer
            .sign_exchanged(token, &key)
            .await
            .or_internal()
    }
}

impl Query for ExchangeTokenUseCase {
    type Caller = ScopedTenant;
    type Input = TokenExchangeRequest;
    type Output = Result<ExchangedForUpstream, AppError>;

    /// The token `request.config` asks for, narrowed to what
    /// `request.grounds` proved, signed with `tenant`'s assertion key.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the grounds were proved in another
    ///   tenant, the caller's credential has run out, or the caller holds
    ///   none of the scopes asked for.
    /// - `AppError::Internal` when the tenant holds no key that signs, its
    ///   key cannot be read or opened, or the signing fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: TokenExchangeRequest,
    ) -> Result<ExchangedForUpstream, AppError> {
        ensure_own_tenant(tenant, &request.grounds)?;
        let token_id =
            TokenId::new(uuid::Uuid::now_v7().to_string()).map_err(AppError::internal)?;
        let token =
            ExchangedToken::narrowed(&request.grounds, &request.config, token_id, clock::now())
                .map_err(|refused| AppError::Forbidden(refused.to_string().into()))?;
        let signed = self.signed(tenant, &token).await?;
        Ok(ExchangedForUpstream {
            token: signed,
            expires_at: token.expires_at(),
        })
    }
}

/// Refuses grounds proved in another tenant than `tenant`: one tenant's
/// key never vouches for another's caller.
fn ensure_own_tenant(tenant: &ScopedTenant, grounds: &ExchangeGrounds) -> Result<(), AppError> {
    if grounds.tenant_id() == **tenant {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "proxy-a-token-is-exchanged-only-with",
        "a token is exchanged only with its own tenant's key"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::proxy::request::context::{
        Caller, PipelineContext, UserSignIn, Verified,
    };
    use ianua_domain::types::{
        Audience, CorrelationId, Expiry, Fact, Issuer, KeyId, PermissionName, PipelineId,
        PublicKeyPem, Scope, Seconds, TenantId, UserId,
    };
    use time::Duration;

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

    /// Ann's request in `tenant_id`, proven until `expiry`, holding
    /// `invoices:read` through her roles, let through.
    fn anns_request(tenant_id: TenantId, ann: UserId, expiry: Expiry) -> ExchangeGrounds {
        let mut context = PipelineContext::new(tenant_id, PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        context.claims.permissions = vec![PermissionName::new("invoices:read").unwrap()];
        context
            .authenticate(Verified {
                caller: Caller::User {
                    user_id: ann,
                    sign_in: UserSignIn::Token,
                },
                expiry,
            })
            .unwrap();
        context.authorize();
        ExchangeGrounds::of_request(&context).unwrap()
    }

    /// The billing route's stage, asking for `scopes`.
    fn billing(scopes: &[&str]) -> TokenExchangeConfig {
        TokenExchangeConfig {
            target_audience: Audience::new("billing-service").unwrap(),
            scopes: scopes
                .iter()
                .map(|name| Scope::new(*name).unwrap())
                .collect(),
            ttl_seconds: Seconds::new(120),
        }
    }

    struct Fixture {
        use_case: ExchangeTokenUseCase,
        signer: Arc<FakeAssertionSigner>,
    }

    fn over(store: FakeAssertionKeyStore) -> Fixture {
        let signer = Arc::new(FakeAssertionSigner::default());
        Fixture {
            use_case: ExchangeTokenUseCase::new(ExchangeTokenPorts {
                keys: Arc::new(store),
                signer: signer.clone(),
            }),
            signer,
        }
    }

    fn with_key() -> Fixture {
        over(FakeAssertionKeyStore::holding(&AssertionKeySet::new(key(
            "a1",
        ))))
    }

    impl Fixture {
        fn exchange(
            &self,
            grounds: ExchangeGrounds,
            config: TokenExchangeConfig,
        ) -> Result<ExchangedForUpstream, AppError> {
            let request = TokenExchangeRequest { grounds, config };
            block_on(self.use_case.execute(&test_ctx().tenant(), request))
        }

        fn signed(&self) -> Vec<ExchangedToken> {
            self.signer.exchanged.lock().unwrap().clone()
        }
    }

    /// Ann's request reaches the billing route, which asks for
    /// `invoices:read` and `invoices:void`. Her token is signed with
    /// Acme's assertion key, for the billing service, carrying only
    /// `invoices:read`, and for two minutes.
    #[test]
    fn a_narrowed_token_is_signed_with_the_tenants_assertion_key() {
        let ann = UserId::new();
        let f = with_key();
        let grounds = anns_request(test_ctx().tenant_id(), ann, Expiry::Never);

        let issued = f
            .exchange(grounds, billing(&["invoices:read", "invoices:void"]))
            .unwrap();

        assert_eq!(
            issued.token.expose(),
            format!("exchanged.a1.{}", ann.as_uuid())
        );
        let signed = f.signed();
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].audience().as_str(), "billing-service");
        let scopes: Vec<&str> = signed[0].scopes().iter().map(Scope::as_str).collect();
        assert_eq!(scopes, ["invoices:read"]);
        assert_eq!(
            signed[0].expires_at() - signed[0].issued_at(),
            Duration::minutes(2)
        );
        assert_eq!(issued.expires_at, signed[0].expires_at());
    }

    /// An exchange requesting only scopes the caller lacks is forbidden,
    /// with no token signed.
    #[test]
    fn a_caller_holding_nothing_asked_gets_no_token() {
        let f = with_key();
        let grounds = anns_request(test_ctx().tenant_id(), UserId::new(), Expiry::Never);

        let refused = f.exchange(grounds, billing(&["invoices:void"]));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(f.signed().is_empty());
    }

    /// Expired credentials cannot be exchanged, and nothing reaches the signer.
    #[test]
    fn an_expired_credential_gets_no_token() {
        let f = with_key();
        let gone = Expiry::At(clock::now() - Duration::seconds(1));
        let grounds = anns_request(test_ctx().tenant_id(), UserId::new(), gone);

        let refused = f.exchange(grounds, billing(&["invoices:read"]));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(f.signed().is_empty());
    }

    /// Grounds from another tenant are forbidden from using this tenant's
    /// assertion key, and no token is signed.
    #[test]
    fn grounds_from_another_tenant_are_refused() {
        let f = with_key();
        let grounds = anns_request(TenantId::new(), UserId::new(), Expiry::Never);

        let refused = f.exchange(grounds, billing(&["invoices:read"]));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(f.signed().is_empty());
    }

    /// A tenant without an assertion key receives an internal error and no
    /// signed exchange token.
    #[test]
    fn a_tenant_without_an_assertion_key_mints_nothing() {
        let f = over(FakeAssertionKeyStore::empty());
        let grounds = anns_request(test_ctx().tenant_id(), UserId::new(), Expiry::Never);

        let refused = f.exchange(grounds, billing(&["invoices:read"]));

        assert!(matches!(refused, Err(AppError::Internal(_))));
        assert!(f.signed().is_empty());
    }

    /// Debug output redacts the returned bearer even after a successful exchange.
    #[test]
    fn the_minted_token_is_never_printed() {
        let f = with_key();
        let grounds = anns_request(test_ctx().tenant_id(), UserId::new(), Expiry::Never);

        let issued = f.exchange(grounds, billing(&["invoices:read"])).unwrap();

        assert!(!format!("{issued:?}").contains(issued.token.expose()));
    }
}
