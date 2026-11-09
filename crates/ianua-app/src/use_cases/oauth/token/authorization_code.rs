//! The authorization code grant at the token endpoint: a client swaps the
//! code a person's consent produced for tokens (RFC 6749 4.1.3, RFC 7636).
//!
//! Nobody is signed in here. The client proves itself the way it
//! registered, and the code proves the rest: it works once, for the client
//! it was issued to, sent back with the redirect it went to and the PKCE
//! verifier behind its challenge, while the session it was consented in
//! still stands. The ID token is built from the swapped code, so it says
//! what the person's session proved and nothing a caller wrote.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthCodeError, AuthorizationCode, CodeExchange,
};
use ianua_domain::domains::oauth::grants::id_token_grant::IdTokenGrant;
use ianua_domain::domains::oauth::grants::jwt_access_token::SignInFacts;
use ianua_domain::domains::oauth::grants::refresh_terms::RefreshIssue;
use ianua_domain::domains::oauth::grants::refresh_token::OAuthRefreshToken;
use ianua_domain::domains::oauth::grants::resource::TokenResource;
use ianua_domain::domains::oauth::grants::token_binding::{PresentedProof, SenderBinding};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Issuer, RedirectUri};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::input::{validate_pkce_verifier, validate_token};
use crate::ports::oauth::{AuthCodeStore, PkceVerifier};
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::sender::SenderEvidence;
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::issuing::{
    Granted, HandedToken, IssuedTokens, IssuingPorts, Minting, PersonGrant, Target, TokenType,
    checked_target, ensure_may_use, granted_account, handed_id_token, person_access,
    proven_binding, terms_for,
};
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// What a client presents to swap a code.
pub struct CodeGrant {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer, written into the tokens.
    pub issuer: Issuer,
    /// What the request carried to prove its holder, checked before the
    /// tokens are bound to it.
    pub sender: SenderEvidence,
    /// The raw authorization code.
    pub code: Secret,
    /// The redirect URI the code was sent to.
    pub redirect_uri: RedirectUri,
    /// The PKCE verifier behind the code's challenge.
    pub code_verifier: Secret,
    /// What the access token is asked to be meant for (RFC 8707
    /// `resource`).
    pub resource: TokenResource,
}

/// The ports [`RedeemCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RedeemCodePorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// How the tokens are made and kept.
    pub issuing: IssuingPorts,
    /// Where issued codes are kept.
    pub auth_code_store: Arc<dyn AuthCodeStore>,
    /// Turns the PKCE verifier into its challenge.
    pub pkce_verifier: Arc<dyn PkceVerifier>,
    /// Where the session the code was consented in is kept.
    pub session_store: Arc<dyn SessionStore>,
}

/// Swaps an authorization code for tokens.
pub struct RedeemCodeUseCase {
    platform: TokenTerms,
    ports: RedeemCodePorts,
}

impl RedeemCodeUseCase {
    /// A use case issuing tokens on the platform's `platform` terms, unless
    /// a client has its own, working through `ports`.
    #[must_use]
    pub fn new(platform: TokenTerms, ports: RedeemCodePorts) -> Self {
        Self { platform, ports }
    }

    /// The code `grant` presents, swapped by `client`, used up in one step
    /// with the store.
    async fn swapped_code(
        &self,
        tenant: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
        grant: &CodeGrant,
    ) -> Result<AuthorizationCode<ResolvedTenant>, TokenError> {
        let hasher = self.ports.issuing.code_hasher.as_ref();
        let code_hash = hasher.hash_code(&grant.code).await.or_internal()?;
        let store = self.ports.auth_code_store.as_ref();
        let mut code = store
            .find_by_hash(tenant, &code_hash)
            .await
            .or_internal()?
            .ok_or_else(|| invalid_grant("the authorization code is not known"))?;
        let verifier_challenge = self
            .ports
            .pkce_verifier
            .challenge_for(&grant.code_verifier, code.code_challenge_method())
            .await
            .map_err(|_| malformed("the code verifier is malformed"))?;
        let exchange = CodeExchange {
            client,
            redirect_uri: grant.redirect_uri.as_str(),
            verifier_challenge: &verifier_challenge,
        };
        code.consume(&exchange, clock::now())?;
        if !store.redeem(tenant, &code).await.or_internal()? {
            return Err(AuthCodeError::AlreadyConsumed.into());
        }
        Ok(code)
    }

    /// Refuses a code whose session was signed out of since the person
    /// consented: signing out ends what the session handed out.
    async fn ensure_session_stands(
        &self,
        tenant: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<(), TokenError> {
        self.ports
            .session_store
            .find_by_id(tenant, code.session_id())
            .await
            .or_internal()?
            .filter(|session| !session.is_revoked())
            .map(|_| ())
            .ok_or_else(|| invalid_grant("the session the code was consented in has ended"))
    }

    /// The tokens `code` is worth to `minting.client`, with the access
    /// token's record.
    async fn tokens_for(
        &self,
        minting: Minting<'_>,
        code: &AuthorizationCode<ResolvedTenant>,
        bound: Bound<'_>,
        target: Target,
    ) -> Result<(AccessToken<ResolvedTenant>, IssuedTokens), TokenError> {
        let issuing = &self.ports.issuing;
        let account = granted_account(issuing, minting.tenant, code.user_id()).await?;
        let terms = terms_for(minting.client, self.platform);
        let grant = person_grant(code, bound.binding, terms, target);
        let (token, access_token) = person_access(issuing, minting, grant).await?;
        let refresh_token = self
            .first_refresh(minting, code, bound.proof, terms)
            .await?;
        let granted = Granted {
            grant: IdTokenGrant::Code(code),
            scopes: code.scopes(),
            account: &account,
            access_token: &access_token,
        };
        let id_token = handed_id_token(issuing, minting, granted, terms).await?;
        let issued = IssuedTokens {
            token_type: TokenType::of(token.binding()),
            access_token,
            expires_in: terms.access(),
            scopes: code.scopes().to_vec(),
            refresh_token,
            id_token,
        };
        Ok((token, issued))
    }

    /// The first refresh token of a family for `code`, when the client may
    /// refresh.
    async fn first_refresh(
        &self,
        minting: Minting<'_>,
        code: &AuthorizationCode<ResolvedTenant>,
        proof: &PresentedProof,
        terms: TokenTerms,
    ) -> Result<HandedToken, AppError> {
        if !minting.client.supports_grant_type(GrantType::RefreshToken) {
            return Ok(HandedToken::NotIssued);
        }
        let issuing = &self.ports.issuing;
        let (raw, token_hash) = issuing.code_hasher.generate_code().await.or_internal()?;
        let issue = RefreshIssue {
            token_hash,
            lifetimes: terms.refresh(),
            proof: proof.clone(),
        };
        let token = OAuthRefreshToken::from_code(issue, code, minting.client)
            .map_err(AppError::from_domain)?;
        issuing
            .refresh_token_store
            .insert(minting.tenant, &token)
            .await
            .or_internal()?;
        Ok(HandedToken::Issued(raw))
    }
}

/// What the issued tokens are bound to, and what the request proved.
#[derive(Clone, Copy)]
struct Bound<'a> {
    binding: &'a SenderBinding,
    proof: &'a PresentedProof,
}

impl Command for RedeemCodeUseCase {
    type Caller = ScopedTenant;
    type Input = CodeGrant;
    type Output = Result<IssuedTokens, TokenError>;

    /// Swaps the code `grant` presents in `tenant` for an access token, a
    /// refresh token when the client may refresh, and an ID token when the
    /// grant asked for `openid`. The code is used up first, in one step
    /// with the store, so it never works twice, even for two exchanges
    /// arriving together. Records `oauth.authorization_code_exchanged`,
    /// then `oauth.access_token_issued`, with the person as actor.
    ///
    /// # Errors
    ///
    /// - `invalid_request` for malformed code/verifier; `invalid_client` for failed authentication; `unauthorized_client` for a disallowed flow.
    /// - `invalid_dpop_proof` for invalid proof; `invalid_dpop_proof` or `invalid_request` for missing required token-binding evidence.
    /// - `invalid_grant` for unknown/spent/expired/foreign codes, wrong redirect/verifier, ended sessions or accounts unable to sign in.
    /// - `invalid_target` for a resource other than an active tenant stream route with a signed-in tunnel, or an opaque-token client.
    /// - `TokenError::Failed` carries `AppError::NotFound` for no signing key, or `Internal` on hashing, signing, save or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: CodeGrant,
    ) -> Result<IssuedTokens, TokenError> {
        ensure_well_formed(&grant)?;
        let asking = Asking {
            tenant,
            issuer: &grant.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &grant.client).await?;
        ensure_may_use(&client, GrantType::AuthorizationCode)?;
        let (binding, proof) =
            proven_binding(&self.ports.issuing, tenant, &client, &grant.sender).await?;
        let target = checked_target(&self.ports.issuing, tenant, &client, grant.resource).await?;
        let mut code = self.swapped_code(tenant, &client, &grant).await?;
        self.ensure_session_stands(tenant, &code).await?;
        let minting = Minting {
            tenant,
            issuer: &grant.issuer,
            client: &client,
        };
        let bound = Bound {
            binding: &binding,
            proof: &proof,
        };
        let (mut token, issued) = self.tokens_for(minting, &code, bound, target).await?;
        record_exchange(auditor, tenant, &mut code, &mut token).await?;
        Ok(issued)
    }
}

/// Refuses an empty or oversized code, and a PKCE verifier outside RFC
/// 7636, before anything is hashed or looked up.
fn ensure_well_formed(grant: &CodeGrant) -> Result<(), TokenError> {
    validate_token("code", grant.code.expose())
        .map_err(|_| malformed("the code is empty or too long"))?;
    validate_pkce_verifier(grant.code_verifier.expose())
        .map_err(|_| malformed("the code verifier is not one RFC 7636 allows"))
}

/// Records what swapping `code` for `token` did, as the person the code
/// was issued to.
async fn record_exchange(
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    code: &mut AuthorizationCode<ResolvedTenant>,
    token: &mut AccessToken<ResolvedTenant>,
) -> Result<(), TokenError> {
    let mut events = code.take_events(tenant);
    events.extend(token.take_events(tenant));
    auditor
        .dispatch_by(&ActorRef::User(*code.user_id()), events)
        .await
        .or_internal()?;
    Ok(())
}

/// The person's access `code` is worth, bound by `binding`, lasting as
/// long as `terms` let an access token last, and meant for `target`.
fn person_grant(
    code: &AuthorizationCode<ResolvedTenant>,
    binding: &SenderBinding,
    terms: TokenTerms,
    target: Target,
) -> PersonGrant {
    PersonGrant {
        user_id: *code.user_id(),
        scopes: code.scopes().to_vec(),
        binding: binding.clone(),
        lifetime: terms.access(),
        sign_in: SignInFacts::of_code(code),
        target,
    }
}

/// An `invalid_grant` refusal saying `reason`.
fn invalid_grant(reason: &str) -> TokenError {
    TokenError::refused(OAuthErrorCode::InvalidGrant, reason)
}

/// An `invalid_request` refusal saying `reason`.
fn malformed(reason: &str) -> TokenError {
    TokenError::refused(OAuthErrorCode::InvalidRequest, reason)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::oauth::clients::settings::AccessTokenFormat;
    use ianua_domain::domains::oauth::grants::access_token::AccessAudience;
    use ianua_domain::domains::oauth::grants::authorization_code::{AuthCodeRow, NonceSent};
    use ianua_domain::domains::oauth::grants::token_binding::SenderConstraint;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{Nonce, Scope, StreamRouteId, TokenHash};
    use time::Duration;

    use super::*;
    use crate::ports::oauth::OAuthClientStore as _;
    use crate::ports::routing::StreamRouteStore as _;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::crypto::FakeSigningKeyStore;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{
        FakeAuthCodeStore, RejectingPkceVerifier, TEST_RAW_CODE, TEST_REDIRECT, TEST_VERIFIER,
        TokenEndpoint, basic_proof, client_with, code_row, no_proof, public_client, refused_with,
        signed_in_session, stored_client, test_issuer, test_terms,
    };
    use crate::test_support::routing::{FakeStreamRouteStore, tunnel_on};
    use crate::test_support::{block_on, test_auditor, test_ctx, test_session_id};

    /// The portal's token endpoint, holding one code issued to it for Ann.
    struct Fixture {
        endpoint: TokenEndpoint,
        codes: Arc<FakeAuthCodeStore>,
    }

    impl Fixture {
        /// `client`'s endpoint, holding Ann's code as `edit` leaves its row.
        fn serving(
            client: OAuthClient<ResolvedTenant>,
            edit: impl FnOnce(&mut AuthCodeRow),
        ) -> Self {
            let endpoint = TokenEndpoint::serving(client);
            let codes = Arc::new(FakeAuthCodeStore::empty());
            let mut row = code_row(&endpoint.client, endpoint.ann);
            edit(&mut row);
            let code = AuthorizationCode::reconstitute(row).unwrap();
            block_on(codes.save(&test_ctx().tenant(), &code)).unwrap();
            Self { endpoint, codes }
        }

        /// The portal, which may refresh, holding Ann's code as `edit`
        /// leaves its row.
        fn with_code(edit: impl FnOnce(&mut AuthCodeRow)) -> Self {
            Self::serving(
                stored_client(
                    "Portal",
                    &[GrantType::AuthorizationCode, GrantType::RefreshToken],
                ),
                edit,
            )
        }

        /// The portal holding Ann's code as issued.
        fn new() -> Self {
            Self::with_code(|_| {})
        }

        /// The portal swapping Ann's code properly.
        fn grant(&self) -> CodeGrant {
            CodeGrant {
                client: basic_proof(&self.endpoint.client),
                issuer: test_issuer(),
                sender: no_proof(),
                code: Secret::new(TEST_RAW_CODE.to_owned()),
                redirect_uri: RedirectUri::new(TEST_REDIRECT).unwrap(),
                code_verifier: Secret::new(TEST_VERIFIER.to_owned()),
                resource: TokenResource::Holder,
            }
        }

        /// The ports the endpoint swaps codes through.
        fn ports(&self) -> RedeemCodePorts {
            RedeemCodePorts {
                client_auth: self.endpoint.client_auth(),
                issuing: self.endpoint.issuing(),
                auth_code_store: self.codes.clone(),
                session_store: self.endpoint.sessions.clone(),
                ..RedeemCodePorts::fakes()
            }
        }

        /// What swapping as `grant` says answers.
        fn redeem(&self, grant: CodeGrant) -> Result<IssuedTokens, TokenError> {
            self.redeem_through(self.ports(), grant)
        }

        /// What swapping as `grant` says, through `ports`, answers.
        fn redeem_through(
            &self,
            ports: RedeemCodePorts,
            grant: CodeGrant,
        ) -> Result<IssuedTokens, TokenError> {
            let use_case = RedeemCodeUseCase::new(test_terms(), ports);
            let auditor = test_auditor(self.endpoint.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, grant))
        }
    }

    /// The portal swaps Ann's code with its secret, the redirect and the
    /// verifier. It gets an access token, a refresh token and an ID token;
    /// the token's grant is kept, and the swap and the token are recorded.
    #[test]
    fn a_code_is_swapped_for_tokens() {
        let fixture = Fixture::new();

        let tokens = fixture.redeem(fixture.grant()).unwrap();

        assert!(!tokens.access_token.expose().is_empty());
        assert!(matches!(tokens.refresh_token, HandedToken::Issued(_)));
        assert!(matches!(tokens.id_token, HandedToken::Issued(_)));
        assert_eq!(tokens.token_type, TokenType::Bearer);
        assert_eq!(fixture.endpoint.tokens.count(), 1);
        assert_eq!(fixture.endpoint.refresh.count(), 1);
        assert_eq!(
            fixture.endpoint.recorded(),
            [
                "oauth.authorization_code_exchanged",
                "oauth.access_token_issued"
            ]
        );
    }

    /// Ann's code was issued after a password sign-in in her session, with
    /// a nonce. The ID token says so: it is for her, for the portal, with
    /// the nonce, the password and the session, read from the code.
    #[test]
    fn the_id_token_says_what_the_code_carries() {
        let fixture = Fixture::with_code(|row| {
            row.nonce = NonceSent::Sent(Nonce::new("n-0S6_WzA2Mj-portal").unwrap());
        });

        fixture.redeem(fixture.grant()).unwrap();

        let claims = fixture.endpoint.signed_claims();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].contains(&fixture.endpoint.ann.to_string()));
        assert!(claims[0].contains(fixture.endpoint.client.client_id_value().as_str()));
        assert!(claims[0].contains("n-0S6_WzA2Mj-portal"));
        assert!(claims[0].contains("pwd"));
        assert!(claims[0].contains(&test_session_id().to_string()));
        assert!(claims[0].contains("fake-at-hash"));
    }

    /// Ann's code was for `read` alone, a plain OAuth grant. The portal
    /// gets an access token and no ID token, so no personal data reaches
    /// an app that never asked for OpenID Connect.
    #[test]
    fn a_grant_without_openid_gets_no_id_token() {
        let fixture = Fixture::with_code(|row| row.scopes = vec![Scope::new("read").unwrap()]);

        let tokens = fixture.redeem(fixture.grant()).unwrap();

        assert!(matches!(tokens.id_token, HandedToken::NotIssued));
        assert!(fixture.endpoint.signed_claims().is_empty());
    }

    /// The portal was not given refresh tokens. It gets none.
    #[test]
    fn a_client_without_refresh_gets_no_refresh_token() {
        let fixture = Fixture::serving(
            stored_client("Portal", &[GrantType::AuthorizationCode]),
            |_| {},
        );

        let tokens = fixture.redeem(fixture.grant()).unwrap();

        assert!(matches!(tokens.refresh_token, HandedToken::NotIssued));
        assert_eq!(fixture.endpoint.refresh.count(), 0);
    }

    /// The portal chose JWT access tokens. It gets one signed by the
    /// tenant, whose record is kept so it can still be revoked.
    #[test]
    fn a_client_choosing_jwts_gets_a_signed_access_token() {
        let client = client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.settings.token_format = AccessTokenFormat::Jwt;
        });
        let fixture = Fixture::serving(client, |_| {});

        let tokens = fixture.redeem(fixture.grant()).unwrap();

        assert!(tokens.access_token.expose().starts_with("header."));
        assert_eq!(fixture.endpoint.tokens.count(), 1);
    }

    /// The portal, which takes JWTs, holding Ann's code, and the ports it
    /// swaps codes through with the tenant's SSH tunnel kept, by its id.
    fn tunnelling() -> (Fixture, RedeemCodePorts, StreamRouteId) {
        let client = client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.settings.token_format = AccessTokenFormat::Jwt;
        });
        let fixture = Fixture::serving(client, |_| {});
        let ssh = tunnel_on(2222, StreamAccess::People(RoutePolicy::Authenticated));
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&test_ctx().tenant(), &ssh)).unwrap();
        let ports = RedeemCodePorts {
            issuing: IssuingPorts {
                stream_routes: routes,
                ..fixture.endpoint.issuing()
            },
            ..fixture.ports()
        };
        (fixture, ports, *ssh.id())
    }

    /// Ann's CLI swaps her code naming the SSH tunnel as its resource. Its
    /// access token is meant for that tunnel alone.
    #[test]
    fn a_resource_naming_a_tunnel_gets_a_token_for_it() {
        let (fixture, ports, ssh) = tunnelling();

        let tokens = fixture.redeem_through(
            ports,
            CodeGrant {
                resource: TokenResource::StreamRoute(ssh),
                ..fixture.grant()
            },
        );

        assert!(tokens.is_ok());
        let kept = fixture.endpoint.tokens.all();
        assert_eq!(kept[0].audience(), AccessAudience::StreamRoute(ssh));
    }

    /// Naming an unknown stream route returns invalid target without spending
    /// Ann's code. The code can still be exchanged without that resource.
    #[test]
    fn an_unknown_resource_is_refused_before_the_code_is_spent() {
        let (fixture, ports, _) = tunnelling();

        let refused = fixture.redeem_through(
            ports,
            CodeGrant {
                resource: TokenResource::StreamRoute(StreamRouteId::new()),
                ..fixture.grant()
            },
        );
        let afterwards = fixture.redeem(fixture.grant());

        assert_eq!(refused_with(&refused), Some(OAuthErrorCode::InvalidTarget));
        assert!(afterwards.is_ok());
    }

    /// A single-page app holds no secret and proves nothing but PKCE. It
    /// swaps Ann's code all the same.
    #[test]
    fn a_public_client_swaps_its_code_with_pkce_alone() {
        let spa = public_client("SPA", &[GrantType::AuthorizationCode]);
        let fixture = Fixture::serving(spa, |_| {});

        let tokens = fixture.redeem(CodeGrant {
            client: ClientProof::Nothing {
                client_id: fixture.endpoint.client.client_id_value().clone(),
            },
            ..fixture.grant()
        });

        assert!(tokens.is_ok());
    }

    /// Presenting the confidential portal's client ID without its secret
    /// returns invalid client and stores no access token.
    #[test]
    fn a_confidential_client_cannot_skip_its_proof() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            client: ClientProof::Nothing {
                client_id: fixture.endpoint.client.client_id_value().clone(),
            },
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// Replaying Ann's code after a successful exchange returns invalid grant.
    /// Only the first access token remains stored.
    #[test]
    fn a_replayed_code_is_refused() {
        let fixture = Fixture::new();
        fixture.redeem(fixture.grant()).unwrap();

        let replay = fixture.redeem(fixture.grant());

        assert_eq!(refused_with(&replay), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.endpoint.tokens.count(), 1);
    }

    /// Holds codes as the fake store does, but loses every redeem, as when
    /// another exchange of the same code got there between the read and the
    /// write.
    struct RacedAuthCodeStore(Arc<FakeAuthCodeStore>);

    impl crate::ports::TenantScoped for RacedAuthCodeStore {}

    #[async_trait::async_trait]
    impl AuthCodeStore for RacedAuthCodeStore {
        async fn find_by_hash(
            &self,
            tenant_id: &ScopedTenant,
            code_hash: &TokenHash,
        ) -> Result<Option<AuthorizationCode<ResolvedTenant>>, DomainError> {
            self.0.find_by_hash(tenant_id, code_hash).await
        }

        async fn save(
            &self,
            tenant_id: &ScopedTenant,
            code: &AuthorizationCode<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            self.0.save(tenant_id, code).await
        }

        async fn redeem(
            &self,
            _: &ScopedTenant,
            _: &AuthorizationCode<ResolvedTenant>,
        ) -> Result<bool, DomainError> {
            Ok(false)
        }

        async fn consented_sessions(
            &self,
            tenant_id: &ScopedTenant,
            signed_out: ianua_domain::domains::oauth::grants::logout_notice::SignedOut,
        ) -> Result<Vec<crate::ports::oauth::ConsentedSession>, DomainError> {
            self.0.consented_sessions(tenant_id, signed_out).await
        }
    }

    /// A store that reports losing the redemption race makes the exchange
    /// return invalid grant. That exchange stores no access token and records
    /// no audit events.
    #[test]
    fn two_exchanges_of_one_code_at_once_issue_tokens_once() {
        let fixture = Fixture::new();
        let ports = RedeemCodePorts {
            auth_code_store: Arc::new(RacedAuthCodeStore(fixture.codes.clone())),
            ..fixture.ports()
        };

        let result = fixture.redeem_through(ports, fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
        assert!(fixture.endpoint.recorded().is_empty());
    }

    /// Authenticating another client does not let it exchange Ann's portal
    /// code. The request returns invalid grant and stores no access token.
    #[test]
    fn another_client_cannot_swap_the_code() {
        let fixture = Fixture::new();
        let mallorys = stored_client("Mallory's", &[GrantType::AuthorizationCode]);
        block_on(
            fixture
                .endpoint
                .clients
                .save(&test_ctx().tenant(), &mallorys),
        )
        .unwrap();

        let result = fixture.redeem(CodeGrant {
            client: basic_proof(&mallorys),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// A client enabled only for client credentials receives unauthorized
    /// client when it tries to exchange an authorization code.
    #[test]
    fn a_client_without_the_code_flow_is_unauthorized() {
        let fixture = Fixture::serving(
            stored_client("Robot", &[GrantType::ClientCredentials]),
            |_| {},
        );

        let result = fixture.redeem(fixture.grant());

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// Exchanging a code with a different redirect URI returns invalid grant.
    #[test]
    fn a_different_redirect_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            redirect_uri: RedirectUri::new("https://evil.example/callback").unwrap(),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// A verifier that does not match the code's PKCE challenge returns
    /// invalid grant and stores no access token.
    #[test]
    fn a_verifier_that_does_not_match_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            code_verifier: Secret::new("x".repeat(43)),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// A PKCE verifier port that rejects the supplied verifier produces
    /// invalid request. The code still exchanges through the working port.
    #[test]
    fn a_malformed_verifier_is_refused_before_the_code_is_spent() {
        let fixture = Fixture::new();

        let result = fixture.redeem_through(
            RedeemCodePorts {
                pkce_verifier: Arc::new(RejectingPkceVerifier),
                ..fixture.ports()
            },
            fixture.grant(),
        );

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidRequest));
        assert!(fixture.redeem(fixture.grant()).is_ok());
    }

    /// A guessed client secret returns invalid client. The code still
    /// exchanges when the portal supplies its correct secret.
    #[test]
    fn a_wrong_client_secret_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            client: ClientProof::BasicSecret {
                client_id: fixture.endpoint.client.client_id_value().clone(),
                secret: Secret::new("guess".to_owned()),
            },
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
        assert!(fixture.redeem(fixture.grant()).is_ok());
    }

    /// Sending the correct secret in the body returns invalid client when
    /// the portal registered to authenticate through the header.
    #[test]
    fn a_secret_sent_another_way_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            client: ClientProof::PostedSecret {
                client_id: fixture.endpoint.client.client_id_value().clone(),
                secret: Secret::new(crate::test_support::oauth::TEST_CLIENT_SECRET.to_owned()),
            },
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
    }

    /// Exchanging an expired authorization code returns invalid grant.
    #[test]
    fn an_expired_code_is_refused() {
        let fixture = Fixture::with_code(|row| {
            row.authenticated_at = clock::now() - Duration::minutes(10);
            row.created_at = clock::now() - Duration::minutes(5);
            row.expires_at = clock::now() - Duration::minutes(4);
        });

        let result = fixture.redeem(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// Exchanging an unknown code returns invalid grant and records no audit
    /// events.
    #[test]
    fn an_unknown_code_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            code: Secret::new("never-issued".to_owned()),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert!(fixture.endpoint.recorded().is_empty());
    }

    /// A one-megabyte authorization code returns invalid request.
    #[test]
    fn an_oversized_code_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.redeem(CodeGrant {
            code: Secret::new("c".repeat(1 << 20)),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidRequest));
    }

    /// Exchanging Ann's code after its session has been signed out returns
    /// invalid grant and stores no access token.
    #[test]
    fn a_code_from_a_session_signed_out_of_is_refused() {
        let fixture = Fixture::new();
        let mut session: Session<ResolvedTenant> =
            signed_in_session(test_session_id(), fixture.endpoint.ann);
        let refresh_hash = session.refresh_token_hash().clone();
        session.sign_out(&refresh_hash).unwrap();
        let ports = RedeemCodePorts {
            session_store: Arc::new(FakeSessionStore::with_session(session)),
            ..fixture.ports()
        };

        let result = fixture.redeem_through(ports, fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// Exchanging a code for Ann's deactivated account returns invalid grant.
    #[test]
    fn a_code_for_a_deactivated_account_is_refused() {
        let fixture = Fixture::new();
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(
            fixture.endpoint.ann,
            "ann@acme.example",
            UserStatus::Deactivated,
        ));
        let ports = RedeemCodePorts {
            issuing: IssuingPorts {
                users,
                ..fixture.endpoint.issuing()
            },
            ..fixture.ports()
        };

        let result = fixture.redeem_through(ports, fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// A portal requiring DPoP rejects an exchange without sender proof as
    /// invalid DPoP proof and stores no access token.
    #[test]
    fn a_client_requiring_dpop_is_refused_without_a_proof() {
        let client = client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.settings.sender_constraint = SenderConstraint::DpopRequired;
        });
        let fixture = Fixture::serving(client, |_| {});

        let result = fixture.redeem(fixture.grant());

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::InvalidDpopProof)
        );
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// Exchanging an OpenID code with no tenant signing key returns a failed
    /// token operation carrying a not-found error.
    #[test]
    fn a_tenant_without_a_signing_key_issues_no_id_token() {
        let fixture = Fixture::new();
        let ports = RedeemCodePorts {
            issuing: IssuingPorts {
                key_store: Arc::new(FakeSigningKeyStore::empty()),
                ..fixture.endpoint.issuing()
            },
            ..fixture.ports()
        };

        let result = fixture.redeem_through(ports, fixture.grant());

        assert!(matches!(
            result,
            Err(TokenError::Failed(AppError::NotFound(_)))
        ));
    }
}
