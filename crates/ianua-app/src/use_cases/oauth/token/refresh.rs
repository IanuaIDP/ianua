//! The refresh token grant at the token endpoint: a client swaps the
//! refresh token it holds for a new access token and the next refresh
//! token (RFC 6749 6, OAuth 2.1 4.3).
//!
//! Each refresh token works once. A token used already means someone else
//! holds a copy, so its whole family is revoked: the thief's copy and the
//! person's alike.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::domains::oauth::grants::id_token_grant::{GrantSession, IdTokenGrant};
use ianua_domain::domains::oauth::grants::jwt_access_token::SignInFacts;
use ianua_domain::domains::oauth::grants::refresh_terms::{
    RefreshRefusal, RefreshRequest, RefreshScopes,
};
use ianua_domain::domains::oauth::grants::refresh_token::{NextRefresh, OAuthRefreshToken};
use ianua_domain::domains::oauth::grants::resource::TokenResource;
use ianua_domain::domains::oauth::grants::token_binding::{PresentedProof, SenderBinding};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Issuer};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::RefreshRotation;
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
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError, ensure_token_shaped};

/// What a client presents to refresh its tokens.
pub struct RefreshGrant {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// What the request carried to prove its holder.
    pub sender: SenderEvidence,
    /// The raw refresh token.
    pub refresh_token: Secret,
    /// The scopes the new tokens carry: the grant's, or fewer.
    pub scopes: RefreshScopes,
    /// What the new access token is asked to be meant for (RFC 8707
    /// `resource`).
    pub resource: TokenResource,
}

/// The ports [`RefreshTokensUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RefreshTokensPorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// How the tokens are made and kept.
    pub issuing: IssuingPorts,
    /// Where sessions are kept, to state the sign-in a refreshed ID token
    /// carries on.
    pub session_store: Arc<dyn SessionStore>,
}

/// Swaps a refresh token for new tokens, rotating it.
pub struct RefreshTokensUseCase {
    platform: TokenTerms,
    ports: RefreshTokensPorts,
}

impl RefreshTokensUseCase {
    /// A use case issuing tokens on the platform's `platform` terms, unless
    /// a client has its own, working through `ports`.
    #[must_use]
    pub fn new(platform: TokenTerms, ports: RefreshTokensPorts) -> Self {
        Self { platform, ports }
    }

    /// The client `grant` proves in `tenant`, allowed to refresh, once the
    /// token it presents has a token's shape.
    ///
    /// # Errors
    ///
    /// `invalid_request` when the refresh token is empty or oversized,
    /// `invalid_client` when the client does not prove itself,
    /// `unauthorized_client` when it may not refresh.
    async fn refreshing_client(
        &self,
        tenant: &ScopedTenant,
        grant: &RefreshGrant,
    ) -> Result<OAuthClient<ResolvedTenant>, TokenError> {
        ensure_token_shaped(
            "refresh_token",
            grant.refresh_token.expose(),
            "refresh token",
        )?;
        let asking = Asking {
            tenant,
            issuer: &grant.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &grant.client).await?;
        ensure_may_use(&client, GrantType::RefreshToken)?;
        Ok(client)
    }

    /// The kept refresh token `raw`.
    async fn presented(
        &self,
        tenant: &ScopedTenant,
        raw: &Secret,
    ) -> Result<OAuthRefreshToken<ResolvedTenant>, TokenError> {
        let issuing = &self.ports.issuing;
        let hash = issuing.code_hasher.hash_code(raw).await.or_internal()?;
        issuing
            .refresh_token_store
            .find_by_hash(tenant, &hash)
            .await
            .or_internal()?
            .ok_or_else(|| {
                TokenError::refused(
                    OAuthErrorCode::InvalidGrant,
                    "the refresh token is not known",
                )
            })
    }

    /// Revokes the family of `used`, presented again, and records why,
    /// with its person as actor.
    async fn revoke_for_reuse(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        mut used: OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<(), TokenError> {
        self.ports
            .issuing
            .refresh_token_store
            .revoke_family(tenant, used.family(), clock::now())
            .await
            .or_internal()?;
        record_reuse(tenant, auditor, &mut used).await
    }

    /// The next refresh token after `used`, kept in place of it in one step
    /// with the store, with its raw value. A rotation lost to another
    /// refresh with the same token is reuse: the store revoked the family
    /// as it turned it down, and the reuse is recorded.
    async fn rotated(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        spent: Spent<'_>,
        next: NextRefresh,
    ) -> Result<Secret, TokenError> {
        let Spent { client, used } = spent;
        let issuing = &self.ports.issuing;
        let (raw, token_hash) = issuing.code_hasher.generate_code().await.or_internal()?;
        let next = OAuthRefreshToken::rotated(token_hash, next);
        let rotation = issuing
            .refresh_token_store
            .rotate(tenant, used, &next)
            .await
            .or_internal()?;
        match rotation {
            RefreshRotation::Rotated => Ok(raw),
            RefreshRotation::Reused => {
                let refusal = used.lose_rotation(client, clock::now());
                record_reuse(tenant, auditor, used).await?;
                Err(refusal.into())
            }
            RefreshRotation::Ended => Err(RefreshRefusal::Revoked.into()),
        }
    }

    /// The tokens `refreshed` is worth to `minting.client`, with the access
    /// token's issue recorded as done by the person it is for.
    async fn issued_and_recorded(
        &self,
        auditor: &RequestAuditor,
        minting: Minting<'_>,
        refreshed: Refreshed<'_>,
    ) -> Result<IssuedTokens, TokenError> {
        let (tenant, person) = (minting.tenant, *refreshed.next.user_id());
        let (mut token, issued) = self.tokens_for(minting, refreshed).await?;
        auditor
            .dispatch_by(&ActorRef::User(person), token.take_events(tenant))
            .await
            .or_internal()?;
        Ok(issued)
    }

    /// The tokens `refreshed` is worth to `minting.client`: a new access
    /// token, the refresh token just rotated, and an ID token when the
    /// grant carries `openid`, with the access token's record.
    async fn tokens_for(
        &self,
        minting: Minting<'_>,
        refreshed: Refreshed<'_>,
    ) -> Result<(AccessToken<ResolvedTenant>, IssuedTokens), TokenError> {
        let issuing = &self.ports.issuing;
        let next = refreshed.next;
        let terms = terms_for(minting.client, self.platform);
        let person = person_of(next, refreshed.binding, terms, refreshed.target);
        let (token, access_token) = person_access(issuing, minting, person).await?;
        let session = self.grant_session(minting.tenant, next).await?;
        let kept = session
            .as_ref()
            .map_or(GrantSession::NotKept, GrantSession::Kept);
        let granted = Granted {
            grant: IdTokenGrant::Refresh {
                next,
                session: kept,
            },
            scopes: next.scopes(),
            account: refreshed.account,
            access_token: &access_token,
        };
        let id_token = handed_id_token(issuing, minting, granted, terms).await?;
        let issued = IssuedTokens {
            token_type: TokenType::of(token.binding()),
            access_token,
            expires_in: terms.access(),
            scopes: next.scopes().to_vec(),
            refresh_token: HandedToken::Issued(refreshed.refresh_token),
            id_token,
        };
        Ok((token, issued))
    }

    /// The session `next`'s grant was given in, while the store keeps it.
    async fn grant_session(
        &self,
        tenant: &ScopedTenant,
        next: &NextRefresh,
    ) -> Result<Option<Session<ResolvedTenant>>, AppError> {
        let granted_in = next.granted_in();
        let Some(session) = granted_in.session() else {
            return Ok(None);
        };
        self.ports
            .session_store
            .find_by_id(tenant, session)
            .await
            .or_internal()
    }

    /// What `used` hands on to the next token, for `client` on a request
    /// that proved `proof`; a token used already has its family revoked
    /// first.
    async fn next_of(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        client: &OAuthClient<ResolvedTenant>,
        asked: Asked<'_>,
    ) -> Result<(OAuthRefreshToken<ResolvedTenant>, NextRefresh), TokenError> {
        let Asked { grant, proof } = asked;
        let mut used = self.presented(tenant, &grant.refresh_token).await?;
        let request = RefreshRequest {
            scopes: grant.scopes.clone(),
            idle: terms_for(client, self.platform).refresh().idle(),
            proof,
        };
        match used.rotate(client, request, clock::now()) {
            Ok(next) => Ok((used, next)),
            Err(RefreshRefusal::Reused) => {
                self.revoke_for_reuse(tenant, auditor, used).await?;
                Err(RefreshRefusal::Reused.into())
            }
            Err(refusal) => Err(refusal.into()),
        }
    }
}

impl Command for RefreshTokensUseCase {
    type Caller = ScopedTenant;
    type Input = RefreshGrant;
    type Output = Result<IssuedTokens, TokenError>;

    /// Swaps the refresh token `grant` presents in `tenant` for a new
    /// access token and the next refresh token of its family, retiring the
    /// one presented, and a new ID token when the grant carries `openid`
    /// (OIDC Core 12.2): about the same person, stating the sign-in the
    /// session the grant was given in recorded, while that session is kept.
    /// Records `oauth.access_token_issued`, with the person as actor. A
    /// token presented after it was used, or by two refreshes at once,
    /// revokes its whole family and records `oauth.refresh_token_reused`.
    ///
    /// # Errors
    ///
    /// - `invalid_request` for an empty/oversized token; `invalid_client` for failed authentication; `unauthorized_client` for disallowed refresh.
    /// - `invalid_grant` for an unknown/foreign/spent/revoked/expired token, unproved binding key or account unable to sign in; `invalid_scope` for widened scope.
    /// - `invalid_target` for a resource other than an active tenant stream route with a signed-in tunnel, or an opaque-token client; the refresh token remains unspent.
    /// - `invalid_dpop_proof` for invalid proof; `invalid_dpop_proof` or `invalid_request` for missing required binding evidence.
    /// - `TokenError::Failed` on hashing, signing, save or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: RefreshGrant,
    ) -> Result<IssuedTokens, TokenError> {
        let client = self.refreshing_client(tenant, &grant).await?;
        let (binding, proof) =
            proven_binding(&self.ports.issuing, tenant, &client, &grant.sender).await?;
        let target = checked_target(&self.ports.issuing, tenant, &client, grant.resource).await?;
        let asked = Asked {
            grant: &grant,
            proof,
        };
        let (mut used, next) = self.next_of(tenant, auditor, &client, asked).await?;
        let account = granted_account(&self.ports.issuing, tenant, next.user_id()).await?;
        let spent = Spent {
            client: &client,
            used: &mut used,
        };
        let refresh_token = self.rotated(tenant, auditor, spent, next.clone()).await?;
        let minting = Minting {
            tenant,
            issuer: &grant.issuer,
            client: &client,
        };
        let refreshed = Refreshed {
            next: &next,
            account: &account,
            binding,
            refresh_token,
            target,
        };
        self.issued_and_recorded(auditor, minting, refreshed).await
    }
}

/// The refresh token a client just presented, and that client.
struct Spent<'a> {
    client: &'a OAuthClient<ResolvedTenant>,
    used: &'a mut OAuthRefreshToken<ResolvedTenant>,
}

/// What a refresh asked for: the grant presented and the proof of
/// possession the request carried.
struct Asked<'a> {
    grant: &'a RefreshGrant,
    proof: PresentedProof,
}

/// A refresh just rotated: what it hands on, the account it is for, what
/// the new tokens are bound to, and the next refresh token's raw value.
struct Refreshed<'a> {
    next: &'a NextRefresh,
    account: &'a User<ResolvedTenant>,
    binding: SenderBinding,
    refresh_token: Secret,
    target: Target,
}

/// Records the reuse `used` raised, with its person as actor.
async fn record_reuse(
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    used: &mut OAuthRefreshToken<ResolvedTenant>,
) -> Result<(), TokenError> {
    auditor
        .dispatch_by(&ActorRef::User(*used.user_id()), used.take_events(tenant))
        .await
        .or_internal()?;
    Ok(())
}

/// What the access token after `next` carries, bound by `binding`, on
/// `terms`, meant for `target`. A refresh proves no sign-in, so none is
/// stated.
fn person_of(
    next: &NextRefresh,
    binding: SenderBinding,
    terms: TokenTerms,
    target: Target,
) -> PersonGrant {
    PersonGrant {
        user_id: *next.user_id(),
        scopes: next.scopes().to_vec(),
        binding,
        lifetime: terms.access(),
        sign_in: SignInFacts::NotStated,
        target,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::oauth::grants::refresh_token::{OAuthRefreshTokenRow, RefreshState};
    use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
    use ianua_domain::types::{Scope, TokenId};
    use time::Duration;

    use super::*;
    use crate::ports::oauth::{OAuthClientStore as _, SignedDpopProof};
    use crate::test_support::oauth::{
        FakeDpopVerifier, FakeRefreshTokenStore, TEST_DPOP_URL, TEST_REFRESH_TOKEN, TokenEndpoint,
        basic_proof, dpop_sent, hash_of, no_proof, public_client, refresh_row, refused_with,
        stored_client, test_issuer, test_terms,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx, test_session_id};
    use crate::use_cases::oauth::sender::SenderProofPorts;

    /// The portal's token endpoint, holding one refresh token it holds for
    /// Ann.
    struct Fixture {
        endpoint: TokenEndpoint,
    }

    impl Fixture {
        /// `client`'s endpoint, holding its refresh token for Ann as `edit`
        /// leaves its row.
        fn serving(
            client: OAuthClient<ResolvedTenant>,
            edit: impl FnOnce(&mut OAuthRefreshTokenRow),
        ) -> Self {
            let mut endpoint = TokenEndpoint::serving(client);
            let mut row = refresh_row(&endpoint.client, endpoint.ann);
            edit(&mut row);
            endpoint.refresh = Arc::new(FakeRefreshTokenStore::holding(&test_ctx().tenant(), row));
            Self { endpoint }
        }

        /// The portal, which may refresh, holding its token for Ann as
        /// `edit` leaves its row.
        fn with_token(edit: impl FnOnce(&mut OAuthRefreshTokenRow)) -> Self {
            Self::serving(
                stored_client(
                    "Portal",
                    &[GrantType::AuthorizationCode, GrantType::RefreshToken],
                ),
                edit,
            )
        }

        /// The portal holding its refresh token for Ann as issued.
        fn new() -> Self {
            Self::with_token(|_| {})
        }

        /// The client refreshing properly, with the grant's scopes.
        fn grant(&self) -> RefreshGrant {
            RefreshGrant {
                client: basic_proof(&self.endpoint.client),
                issuer: test_issuer(),
                sender: no_proof(),
                refresh_token: Secret::new(TEST_REFRESH_TOKEN.to_owned()),
                scopes: RefreshScopes::AsGranted,
                resource: TokenResource::Holder,
            }
        }

        /// What refreshing as `grant` says answers.
        fn refresh(&self, grant: RefreshGrant) -> Result<IssuedTokens, TokenError> {
            self.refresh_through(self.endpoint.issuing(), grant)
        }

        /// What refreshing as `grant` says answers, the tokens made through
        /// `issuing`.
        fn refresh_through(
            &self,
            issuing: IssuingPorts,
            grant: RefreshGrant,
        ) -> Result<IssuedTokens, TokenError> {
            let use_case = RefreshTokensUseCase::new(
                test_terms(),
                RefreshTokensPorts {
                    client_auth: self.endpoint.client_auth(),
                    issuing,
                    session_store: self.endpoint.sessions.clone(),
                },
            );
            let auditor = test_auditor(self.endpoint.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, grant))
        }

        /// Where the refresh token first seeded stands.
        fn state_of_first(&self) -> Option<RefreshState> {
            self.endpoint.refresh.state_of(&hash_of(TEST_REFRESH_TOKEN))
        }
    }

    /// The portal refreshes Ann's tokens. It gets a new access token and
    /// the next refresh token; the one it used is retired, and the new
    /// access token is recorded.
    #[test]
    fn a_refresh_rotates_the_token() {
        let fixture = Fixture::new();

        let tokens = fixture.refresh(fixture.grant()).unwrap();

        assert!(matches!(tokens.refresh_token, HandedToken::Issued(_)));
        assert!(matches!(
            fixture.state_of_first(),
            Some(RefreshState::Rotated { .. })
        ));
        assert_eq!(fixture.endpoint.refresh.count(), 2);
        assert_eq!(fixture.endpoint.recorded(), ["oauth.access_token_issued"]);
    }

    /// Ann's grant carries `openid`. The refresh hands a new ID token about
    /// her, naming the session she signed in to and when, with no nonce.
    #[test]
    fn a_refresh_for_openid_hands_a_new_id_token() {
        let fixture = Fixture::new();

        let tokens = fixture.refresh(fixture.grant()).unwrap();

        assert!(matches!(tokens.id_token, HandedToken::Issued(_)));
        let signed = fixture.endpoint.signed_claims();
        let id_claims = signed
            .iter()
            .find(|claims| claims.contains("at_hash"))
            .unwrap();
        assert!(id_claims.contains(&fixture.endpoint.ann.to_string()));
        assert!(id_claims.contains(&test_session_id().to_string()));
        assert!(id_claims.contains("auth_time"));
        assert!(!id_claims.contains("nonce"));
    }

    /// The portal asks for `read` alone. The new tokens carry only that,
    /// and no ID token comes without `openid`.
    #[test]
    fn a_refresh_may_narrow_the_scopes() {
        let fixture = Fixture::new();

        let tokens = fixture
            .refresh(RefreshGrant {
                scopes: RefreshScopes::Narrowed(vec![Scope::new("read").unwrap()]),
                ..fixture.grant()
            })
            .unwrap();

        assert_eq!(tokens.scopes, [Scope::new("read").unwrap()]);
        assert!(matches!(tokens.id_token, HandedToken::NotIssued));
    }

    /// Asking for write access beyond Ann's granted scopes returns invalid
    /// scope and leaves the refresh token active.
    #[test]
    fn a_refresh_cannot_widen_the_scopes() {
        let fixture = Fixture::new();

        let result = fixture.refresh(RefreshGrant {
            scopes: RefreshScopes::Narrowed(vec![Scope::new("write").unwrap()]),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidScope));
        assert_eq!(fixture.state_of_first(), Some(RefreshState::Active));
    }

    /// Reusing the original refresh token after a successful rotation returns
    /// invalid grant, revokes its successor, and records refresh-token reuse
    /// after the earlier access-token issue.
    #[test]
    fn a_reused_token_revokes_its_family() {
        let fixture = Fixture::new();
        let first = fixture.refresh(fixture.grant()).unwrap();
        let HandedToken::Issued(next) = first.refresh_token else {
            panic!("the first refresh handed out no next token");
        };

        let replay = fixture.refresh(fixture.grant());

        assert_eq!(refused_with(&replay), Some(OAuthErrorCode::InvalidGrant));
        assert!(matches!(
            fixture.endpoint.refresh.state_of(&hash_of(next.expose())),
            Some(RefreshState::Revoked { .. })
        ));
        assert_eq!(
            fixture.endpoint.recorded(),
            ["oauth.access_token_issued", "oauth.refresh_token_reused"]
        );
    }

    /// When the store simulates a rival rotation winning first, the losing
    /// refresh returns invalid grant, revokes the rival's successor token,
    /// and records refresh-token reuse.
    #[test]
    fn a_rotation_lost_to_a_racing_refresh_revokes_its_family() {
        let mut fixture = Fixture::new();
        let row = refresh_row(&fixture.endpoint.client, fixture.endpoint.ann);
        fixture.endpoint.refresh = Arc::new(FakeRefreshTokenStore::raced(
            &test_ctx().tenant(),
            row,
            hash_of("rivals-next"),
        ));

        let result = fixture.refresh(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert!(matches!(
            fixture.endpoint.refresh.state_of(&hash_of("rivals-next")),
            Some(RefreshState::Revoked { .. })
        ));
        assert_eq!(fixture.endpoint.recorded(), ["oauth.refresh_token_reused"]);
    }

    /// Another authenticated client cannot use the portal's refresh token.
    /// The request returns invalid grant and leaves the token active.
    #[test]
    fn another_client_cannot_use_the_token() {
        let fixture = Fixture::new();
        let mallorys = stored_client("Mallory's", &[GrantType::RefreshToken]);
        block_on(
            fixture
                .endpoint
                .clients
                .save(&test_ctx().tenant(), &mallorys),
        )
        .unwrap();

        let result = fixture.refresh(RefreshGrant {
            client: basic_proof(&mallorys),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.state_of_first(), Some(RefreshState::Active));
    }

    /// A portal enabled only for authorization codes receives unauthorized
    /// client when it presents a refresh token.
    #[test]
    fn a_client_no_longer_given_refresh_is_unauthorized() {
        let fixture = Fixture::serving(
            stored_client("Portal", &[GrantType::AuthorizationCode]),
            |_| {},
        );

        let result = fixture.refresh(fixture.grant());

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// Presenting an expired refresh token returns invalid grant.
    #[test]
    fn an_expired_token_is_refused() {
        let fixture = Fixture::with_token(|row| {
            row.issued_at = clock::now() - Duration::days(2);
            row.expires_at = clock::now() - Duration::days(1);
        });

        let result = fixture.refresh(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }

    /// Presenting an unknown refresh token returns invalid grant and records
    /// no audit events.
    #[test]
    fn an_unknown_token_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.refresh(RefreshGrant {
            refresh_token: Secret::new("never-issued".to_owned()),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert!(fixture.endpoint.recorded().is_empty());
    }

    /// Presenting a single-page app's DPoP-bound refresh token without key
    /// proof returns invalid grant and leaves the token active.
    #[test]
    fn a_bound_token_needs_its_key() {
        let spa = public_client(
            "SPA",
            &[GrantType::AuthorizationCode, GrantType::RefreshToken],
        );
        let key = JwkThumbprint::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").unwrap();
        let fixture = Fixture::serving(spa, |row| row.binding = SenderBinding::DpopKey(key));
        let grant = RefreshGrant {
            client: ClientProof::Nothing {
                client_id: fixture.endpoint.client.client_id_value().clone(),
            },
            ..fixture.grant()
        };

        let result = fixture.refresh(grant);

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert_eq!(fixture.state_of_first(), Some(RefreshState::Active));
    }

    /// The single-page app proves the `DPoP` key its refresh token is bound
    /// to. It gets new tokens, the access token bound to that key too.
    #[test]
    fn a_bound_token_works_with_its_key() {
        let spa = public_client(
            "SPA",
            &[GrantType::AuthorizationCode, GrantType::RefreshToken],
        );
        let key = JwkThumbprint::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").unwrap();
        let bound = key.clone();
        let fixture = Fixture::serving(spa, |row| row.binding = SenderBinding::DpopKey(bound));
        let issuing = IssuingPorts {
            sender: SenderProofPorts {
                dpop_verifier: Arc::new(FakeDpopVerifier::accepting(proof_by(key))),
                ..SenderProofPorts::fakes()
            },
            ..fixture.endpoint.issuing()
        };
        let grant = RefreshGrant {
            client: ClientProof::Nothing {
                client_id: fixture.endpoint.client.client_id_value().clone(),
            },
            sender: dpop_sent(),
            ..fixture.grant()
        };

        let tokens = fixture.refresh_through(issuing, grant).unwrap();

        assert_eq!(tokens.token_type, TokenType::Dpop);
    }

    /// A DPoP proof rejected by the verifier returns invalid DPoP proof and
    /// leaves the refresh token active.
    #[test]
    fn a_proof_that_does_not_verify_is_refused() {
        let fixture = Fixture::new();
        let grant = RefreshGrant {
            sender: dpop_sent(),
            ..fixture.grant()
        };

        let result = fixture.refresh(grant);

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::InvalidDpopProof)
        );
        assert_eq!(fixture.state_of_first(), Some(RefreshState::Active));
    }

    /// A fresh proof signed by `key` for the test token request.
    fn proof_by(key: JwkThumbprint) -> SignedDpopProof {
        SignedDpopProof {
            thumbprint: key,
            jti: TokenId::new("proof-1").unwrap(),
            method: "POST".to_owned(),
            url: TEST_DPOP_URL.to_owned(),
            issued_at: clock::now(),
        }
    }
}
