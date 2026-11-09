//! The device code grant at the token endpoint: a device without a
//! browser polls with its device code until a person answers on another
//! screen, then collects tokens (RFC 8628 3.4 and 3.5).
//!
//! Until then it is told to keep waiting, to slow down when it polls too
//! fast, that the person refused, or that the request ran out. An approval
//! is collected once, by the client that started the request.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::domains::oauth::grants::device_auth_status::DeviceAuthStatus;
use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthorization;
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
use ianua_domain::types::{ActorRef, Issuer, TokenHash, UserId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::DeviceAuthStore;
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

/// What a device polls the token endpoint with.
pub struct DeviceCodeGrant {
    /// How the client proves itself; a device app is usually public.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// What the request carried to prove its holder.
    pub sender: SenderEvidence,
    /// The raw device code it was handed.
    pub device_code: Secret,
    /// What the access token is asked to be meant for (RFC 8707
    /// `resource`).
    pub resource: TokenResource,
}

/// The ports [`CollectDeviceTokensUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CollectDeviceTokensPorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// How the tokens are made and kept.
    pub issuing: IssuingPorts,
    /// Where device requests are kept.
    pub device_auth_store: Arc<dyn DeviceAuthStore>,
}

/// Answers a device's poll, handing it tokens once a person approved.
pub struct CollectDeviceTokensUseCase {
    platform: TokenTerms,
    ports: CollectDeviceTokensPorts,
}

/// The poll being answered: the device code's hash, and when.
struct Polled {
    code_hash: TokenHash,
    now: OffsetDateTime,
}

/// An approval just collected: the request, who approved it, and what the
/// tokens are bound to.
struct Approval<'a> {
    auth: &'a DeviceAuthorization<ResolvedTenant>,
    user: UserId,
    binding: SenderBinding,
    proof: &'a PresentedProof,
}

impl CollectDeviceTokensUseCase {
    /// A use case issuing tokens on the platform's `platform` terms, unless
    /// a client has its own, working through `ports`.
    #[must_use]
    pub fn new(platform: TokenTerms, ports: CollectDeviceTokensPorts) -> Self {
        Self { platform, ports }
    }

    /// The client `grant` proves in `tenant`, allowed the device flow.
    ///
    /// # Errors
    ///
    /// `invalid_client` when it does not prove itself, `unauthorized_client`
    /// when it may not use the device flow.
    async fn polling_client(
        &self,
        tenant: &ScopedTenant,
        grant: &DeviceCodeGrant,
    ) -> Result<OAuthClient<ResolvedTenant>, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &grant.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &grant.client).await?;
        ensure_may_use(&client, GrantType::DeviceCode)?;
        Ok(client)
    }

    /// The poll `grant` makes: its device code's hash, and now.
    ///
    /// # Errors
    ///
    /// `TokenError::Failed` when hashing the device code fails.
    async fn poll_of(&self, grant: &DeviceCodeGrant) -> Result<Polled, TokenError> {
        let hasher = self.ports.issuing.code_hasher.as_ref();
        Ok(Polled {
            code_hash: hasher.hash_code(&grant.device_code).await.or_internal()?,
            now: clock::now(),
        })
    }

    /// The request behind the device code, started by `client`, its poll
    /// recorded.
    async fn polled_request(
        &self,
        tenant: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
        polled: &Polled,
    ) -> Result<DeviceAuthorization<ResolvedTenant>, TokenError> {
        let store = self.ports.device_auth_store.as_ref();
        let mut auth = store
            .find_by_device_code_hash(tenant, &polled.code_hash)
            .await
            .or_internal()?
            .filter(|auth| auth.client_id() == client.id())
            .ok_or_else(|| invalid_grant("the device code is not known"))?;
        let paced = auth.poll(polled.now);
        store.record_poll(tenant, &auth).await.or_internal()?;
        paced?;
        Ok(auth)
    }

    /// Collects the approval on `auth` for `client`, once, in one step with
    /// the store, and answers who approved.
    async fn collected(
        &self,
        tenant: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
        auth: &mut DeviceAuthorization<ResolvedTenant>,
        polled: &Polled,
    ) -> Result<UserId, TokenError> {
        ensure_answered(auth, polled.now)?;
        auth.redeem(client, polled.now)?;
        let redeemed = self
            .ports
            .device_auth_store
            .redeem(tenant, &polled.code_hash, polled.now)
            .await
            .or_internal()?;
        let user = auth.collected_by().copied();
        let (true, Some(user)) = (redeemed, user) else {
            return Err(invalid_grant("the approval was collected already"));
        };
        Ok(user)
    }

    /// The first refresh token of a family for the person who approved
    /// `auth`, when the client may refresh.
    async fn first_refresh(
        &self,
        minting: Minting<'_>,
        auth: &DeviceAuthorization<ResolvedTenant>,
        proof: &PresentedProof,
    ) -> Result<HandedToken, AppError> {
        if !minting.client.supports_grant_type(GrantType::RefreshToken) {
            return Ok(HandedToken::NotIssued);
        }
        let issuing = &self.ports.issuing;
        let (raw, token_hash) = issuing.code_hasher.generate_code().await.or_internal()?;
        let issue = RefreshIssue {
            token_hash,
            lifetimes: terms_for(minting.client, self.platform).refresh(),
            proof: proof.clone(),
        };
        let token = OAuthRefreshToken::from_device(issue, auth, minting.client)
            .map_err(AppError::from_domain)?;
        issuing
            .refresh_token_store
            .insert(minting.tenant, &token)
            .await
            .or_internal()?;
        Ok(HandedToken::Issued(raw))
    }

    /// The tokens `approval` is worth to `minting.client`, with an ID token
    /// when the request asked for `openid`, and the access token's record.
    async fn tokens_for(
        &self,
        minting: Minting<'_>,
        approval: Approval<'_>,
        target: Target,
    ) -> Result<(AccessToken<ResolvedTenant>, IssuedTokens), TokenError> {
        let issuing = &self.ports.issuing;
        let account = granted_account(issuing, minting.tenant, &approval.user).await?;
        let terms = terms_for(minting.client, self.platform);
        let person = person_of(&approval, terms, target);
        let (token, access_token) = person_access(issuing, minting, person).await?;
        let refresh_token = self
            .first_refresh(minting, approval.auth, approval.proof)
            .await?;
        let granted = Granted {
            grant: IdTokenGrant::Device(approval.auth),
            scopes: approval.auth.scopes(),
            account: &account,
            access_token: &access_token,
        };
        let id_token = handed_id_token(issuing, minting, granted, terms).await?;
        let tokens = IssuedTokens {
            token_type: TokenType::of(token.binding()),
            access_token,
            expires_in: terms.access(),
            scopes: token.scopes().to_vec(),
            refresh_token,
            id_token,
        };
        Ok((token, tokens))
    }
}

impl Command for CollectDeviceTokensUseCase {
    type Caller = ScopedTenant;
    type Input = DeviceCodeGrant;
    type Output = Result<IssuedTokens, TokenError>;

    /// Answers the poll `grant` makes in `tenant`. Once a person approved,
    /// the poll that collects the approval gets an access token, a refresh
    /// token when the client may refresh, and an ID token about the
    /// approving person when the request asked for `openid`, and records
    /// `oauth.device_authorization_collected` then
    /// `oauth.access_token_issued`, with the approving person as actor.
    /// Every other poll records nothing.
    ///
    /// # Errors
    ///
    /// - `invalid_request` for an empty/oversized code or certificate-bound client; `invalid_client` for failed authentication; `unauthorized_client` for a disallowed flow; `invalid_dpop_proof` for invalid/missing required DPoP.
    /// - `authorization_pending` while unanswered; `slow_down` for early polling, adding five seconds; `access_denied` for refusal; `expired_token` for expiry.
    /// - `invalid_grant` for an unknown/foreign/already collected code or a person unable to sign in.
    /// - `invalid_target` for a resource other than an active tenant stream route with a signed-in tunnel, or an opaque-token client; approval remains uncollected.
    /// - `TokenError::Failed` on hashing, signing, save or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: DeviceCodeGrant,
    ) -> Result<IssuedTokens, TokenError> {
        ensure_token_shaped("device_code", grant.device_code.expose(), "device code")?;
        let client = self.polling_client(tenant, &grant).await?;
        let (binding, proof) =
            proven_binding(&self.ports.issuing, tenant, &client, &grant.sender).await?;
        let target = checked_target(&self.ports.issuing, tenant, &client, grant.resource).await?;
        let polled = self.poll_of(&grant).await?;
        let mut auth = self.polled_request(tenant, &client, &polled).await?;
        let user = self.collected(tenant, &client, &mut auth, &polled).await?;
        let minting = Minting {
            tenant,
            issuer: &grant.issuer,
            client: &client,
        };
        let approval = Approval {
            auth: &auth,
            user,
            binding,
            proof: &proof,
        };
        let (mut token, tokens) = self.tokens_for(minting, approval, target).await?;
        let mut events = auth.take_events(tenant);
        events.extend(token.take_events(tenant));
        auditor
            .dispatch_by(&ActorRef::User(user), events)
            .await
            .or_internal()?;
        Ok(tokens)
    }
}

/// Refuses a request nobody approved: still waiting, refused, run out, or
/// collected already.
fn ensure_answered(
    auth: &DeviceAuthorization<ResolvedTenant>,
    now: OffsetDateTime,
) -> Result<(), TokenError> {
    let status = auth.status();
    if auth.is_expired(now) && status != DeviceAuthStatus::Denied {
        return Err(TokenError::refused(
            OAuthErrorCode::ExpiredToken,
            "the device request ran out",
        ));
    }
    match status {
        DeviceAuthStatus::Approved => Ok(()),
        DeviceAuthStatus::Pending => Err(TokenError::refused(
            OAuthErrorCode::AuthorizationPending,
            "nobody has answered the device request yet",
        )),
        DeviceAuthStatus::Denied => Err(TokenError::refused(
            OAuthErrorCode::AccessDenied,
            "the person refused the device",
        )),
        DeviceAuthStatus::Expired => Err(TokenError::refused(
            OAuthErrorCode::ExpiredToken,
            "the device request ran out",
        )),
        DeviceAuthStatus::Redeemed => Err(invalid_grant("the approval was collected already")),
    }
}

/// What the access token for `approval` carries, on `terms`, meant for
/// `target`. The sign-in on the second screen is not at hand, so none is
/// stated.
fn person_of(approval: &Approval<'_>, terms: TokenTerms, target: Target) -> PersonGrant {
    PersonGrant {
        user_id: approval.user,
        scopes: approval.auth.scopes().to_vec(),
        binding: approval.binding.clone(),
        lifetime: terms.access(),
        sign_in: SignInFacts::NotStated,
        target,
    }
}

/// An `invalid_grant` refusal saying `reason`.
fn invalid_grant(reason: &str) -> TokenError {
    TokenError::refused(OAuthErrorCode::InvalidGrant, reason)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::grants::device_authorization::{
        DeviceAuthRow, DeviceAuthState, LastPoll,
    };
    use ianua_domain::types::Scope;
    use time::Duration;

    use super::*;
    use crate::ports::oauth::OAuthClientStore as _;
    use crate::test_support::oauth::{
        FakeDeviceAuthStore, TEST_DEVICE_CODE, TokenEndpoint, device_row, hash_of, no_proof,
        public_client, refused_with, stored_client, test_issuer, test_terms,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};

    /// The TV's token endpoint, holding one device request it started.
    struct Fixture {
        endpoint: TokenEndpoint,
        requests: Arc<FakeDeviceAuthStore>,
    }

    impl Fixture {
        /// `client`'s endpoint, holding its request in the state `state`
        /// makes of Ann, as `edit` leaves its row.
        fn with(
            client: OAuthClient<ResolvedTenant>,
            state: impl FnOnce(UserId) -> DeviceAuthState,
            edit: impl FnOnce(&mut DeviceAuthRow),
        ) -> Self {
            let endpoint = TokenEndpoint::serving(client);
            let mut row = device_row(&endpoint.client, state(endpoint.ann));
            edit(&mut row);
            let requests = Arc::new(FakeDeviceAuthStore::empty());
            block_on(requests.save(
                &test_ctx().tenant(),
                &DeviceAuthorization::reconstitute(row).unwrap(),
            ))
            .unwrap();
            Self { endpoint, requests }
        }

        /// The TV app: public, given the device flow and refresh tokens.
        fn tv() -> OAuthClient<ResolvedTenant> {
            public_client("TV", &[GrantType::DeviceCode, GrantType::RefreshToken])
        }

        /// The TV's request, in the state `state` makes of Ann.
        fn in_state(state: impl FnOnce(UserId) -> DeviceAuthState) -> Self {
            Self::with(Self::tv(), state, |_| {})
        }

        /// The TV's request, which Ann approved.
        fn approved() -> Self {
            Self::in_state(|ann| DeviceAuthState::Approved { by: ann })
        }

        /// The TV polling properly, proving nothing.
        fn grant(&self) -> DeviceCodeGrant {
            DeviceCodeGrant {
                client: ClientProof::Nothing {
                    client_id: self.endpoint.client.client_id_value().clone(),
                },
                issuer: test_issuer(),
                sender: no_proof(),
                device_code: Secret::new(TEST_DEVICE_CODE.to_owned()),
                resource: TokenResource::Holder,
            }
        }

        /// What polling as `grant` says answers.
        fn poll(&self, grant: DeviceCodeGrant) -> Result<IssuedTokens, TokenError> {
            let use_case = CollectDeviceTokensUseCase::new(
                test_terms(),
                CollectDeviceTokensPorts {
                    client_auth: self.endpoint.client_auth(),
                    issuing: self.endpoint.issuing(),
                    device_auth_store: self.requests.clone(),
                },
            );
            let auditor = test_auditor(self.endpoint.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, grant))
        }

        /// The request as stored now.
        fn stored(&self) -> DeviceAuthorization<ResolvedTenant> {
            block_on(
                self.requests
                    .find_by_device_code_hash(&test_ctx().tenant(), &hash_of(TEST_DEVICE_CODE)),
            )
            .unwrap()
            .unwrap()
        }
    }

    /// Ann approved the TV. Its next poll collects tokens for her, a
    /// refresh token too, and the collection and the token are recorded.
    #[test]
    fn an_approval_is_collected_as_tokens() {
        let fixture = Fixture::approved();

        let tokens = fixture.poll(fixture.grant()).unwrap();

        assert!(matches!(tokens.refresh_token, HandedToken::Issued(_)));
        assert_eq!(
            fixture.endpoint.tokens.all()[0].subject().person(),
            Some(&fixture.endpoint.ann)
        );
        assert_eq!(
            fixture.endpoint.recorded(),
            [
                "oauth.device_authorization_collected",
                "oauth.access_token_issued"
            ]
        );
    }

    /// The TV asked for `openid`, and Ann approved it. Its tokens come with
    /// an ID token about her, naming no session, since none was signed in
    /// on the TV; a request without `openid` gets none.
    #[test]
    fn an_approval_for_openid_comes_with_an_id_token() {
        let fixture = Fixture::with(
            Fixture::tv(),
            |ann| DeviceAuthState::Approved { by: ann },
            |row| row.scopes = vec![Scope::new("openid").unwrap(), Scope::new("read").unwrap()],
        );
        let plain = Fixture::approved();

        let tokens = fixture.poll(fixture.grant()).unwrap();
        let without = plain.poll(plain.grant()).unwrap();

        assert!(matches!(tokens.id_token, HandedToken::Issued(_)));
        assert!(matches!(without.id_token, HandedToken::NotIssued));
        let signed = fixture.endpoint.signed_claims();
        let id_claims = signed
            .iter()
            .find(|claims| claims.contains("at_hash"))
            .unwrap();
        assert!(id_claims.contains(&fixture.endpoint.ann.to_string()));
        assert!(!id_claims.contains("\"sid\""));
    }

    /// Nobody has typed the TV's code yet. The TV is told to keep waiting,
    /// and nothing is recorded.
    #[test]
    fn a_pending_request_says_to_wait() {
        let fixture = Fixture::in_state(|_| DeviceAuthState::Pending);

        let result = fixture.poll(fixture.grant());

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::AuthorizationPending)
        );
        assert!(fixture.endpoint.recorded().is_empty());
    }

    /// Polling a pending request immediately after its last poll returns slow
    /// down and stores a ten-second polling interval.
    #[test]
    fn polling_too_fast_is_told_to_slow_down() {
        let fixture = Fixture::with(
            Fixture::tv(),
            |_| DeviceAuthState::Pending,
            |row| row.last_poll = LastPoll::At(clock::now()),
        );

        let result = fixture.poll(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::SlowDown));
        assert_eq!(fixture.stored().interval().as_secs(), 10);
    }

    /// Ann refused the TV. It is told so.
    #[test]
    fn a_denied_request_says_so() {
        let fixture = Fixture::in_state(|_| DeviceAuthState::Denied);

        let result = fixture.poll(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::AccessDenied));
    }

    /// Polling an approved request after its expiry returns expired token and
    /// stores no access token.
    #[test]
    fn an_approval_collected_too_late_has_expired() {
        let fixture = Fixture::with(
            Fixture::tv(),
            |ann| DeviceAuthState::Approved { by: ann },
            |row| {
                row.created_at = clock::now() - Duration::minutes(20);
                row.expires_at = clock::now() - Duration::minutes(10);
            },
        );

        let result = fixture.poll(fixture.grant());

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::ExpiredToken));
        assert_eq!(fixture.endpoint.tokens.count(), 0);
    }

    /// Polling again after collecting an approval fails. One access token
    /// remains stored, and the request stays redeemed.
    #[test]
    fn an_approval_is_collected_once() {
        let fixture = Fixture::approved();
        fixture.poll(fixture.grant()).unwrap();

        let again = fixture.poll(fixture.grant());

        assert!(again.is_err());
        assert_eq!(fixture.endpoint.tokens.count(), 1);
        assert_eq!(fixture.stored().status(), DeviceAuthStatus::Redeemed);
    }

    /// Another client cannot collect the TV's approval using its device code.
    /// The TV can still collect the approval after that refusal.
    #[test]
    fn another_client_cannot_collect_the_approval() {
        let fixture = Fixture::approved();
        let mallorys = public_client("Mallory's", &[GrantType::DeviceCode]);
        block_on(
            fixture
                .endpoint
                .clients
                .save(&test_ctx().tenant(), &mallorys),
        )
        .unwrap();

        let result = fixture.poll(DeviceCodeGrant {
            client: ClientProof::Nothing {
                client_id: mallorys.client_id_value().clone(),
            },
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
        assert!(fixture.poll(fixture.grant()).is_ok());
    }

    /// A client enabled only for authorization codes receives unauthorized
    /// client when it tries to collect a device approval.
    #[test]
    fn a_client_without_the_device_flow_is_unauthorized() {
        let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
        let fixture = Fixture::with(portal, |ann| DeviceAuthState::Approved { by: ann }, |_| {});

        let result = fixture.poll(DeviceCodeGrant {
            client: crate::test_support::oauth::basic_proof(&fixture.endpoint.client),
            ..fixture.grant()
        });

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// Polling with an unknown device code returns invalid grant.
    #[test]
    fn an_unknown_device_code_is_refused() {
        let fixture = Fixture::in_state(|_| DeviceAuthState::Pending);

        let result = fixture.poll(DeviceCodeGrant {
            device_code: Secret::new("never-issued".to_owned()),
            ..fixture.grant()
        });

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidGrant));
    }
}
