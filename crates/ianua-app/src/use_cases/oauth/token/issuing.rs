//! What every grant at the token endpoint hands out, made the same way:
//! the access token in the form its client chose, bound as its client
//! requires, the refresh token that may follow it, and the ID token for a
//! grant asking for `openid`.

use std::sync::Arc;

use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningKey;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::clients::settings::AccessTokenFormat;
use ianua_domain::domains::oauth::grants::access_token::{AccessToken, IssueAccessTokenParams};
use ianua_domain::domains::oauth::grants::id_token::{
    IdTokenClaims, IdTokenParams, asks_for_id_token,
};
use ianua_domain::domains::oauth::grants::id_token_grant::IdTokenGrant;
use ianua_domain::domains::oauth::grants::jwt_access_token::{
    JwtAccessTokenClaims, JwtAccessTokenParams, SignInFacts,
};
use ianua_domain::domains::oauth::grants::resource::{TokenResource, ensure_tunnel_for};
use ianua_domain::domains::oauth::grants::token_binding::{
    PresentedProof, SenderBinding, SenderConstraint,
};
use ianua_domain::domains::routing::stream::StreamRoute;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Issuer, Label, Lifetime, PrincipalRef, Scope, TokenHash, TokenId, UserId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::RoleStore;
use crate::ports::crypto::{JwtSigner, JwtSigningKey, SigningKeyStore};
use crate::ports::identity::UserStore;
use crate::ports::oauth::{
    AccessTokenStore, AtHashCalculator, CodeHasher, DpopUse, RefreshTokenStore,
};
use crate::ports::routing::StreamRouteStore;
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_cases::oauth::presented::jti_secret;
use crate::use_cases::oauth::sender::{SenderEvidence, SenderProofPorts, proven_sender};
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// What a grant at the token endpoint hands the client.
pub struct IssuedTokens {
    /// The access token: opaque, or a signed JWT, as the client chose.
    pub access_token: Secret,
    /// How the access token is presented.
    pub token_type: TokenType,
    /// How long the access token is good for.
    pub expires_in: Lifetime,
    /// The scopes it carries.
    pub scopes: Vec<Scope>,
    /// The refresh token, when the grant hands one out.
    pub refresh_token: HandedToken,
    /// The ID token, when the grant asked for `openid`.
    pub id_token: HandedToken,
}

/// How an access token is presented (`token_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// `Bearer`, also for a token bound to a TLS certificate (RFC 8705).
    Bearer,
    /// `DPoP`, for a token bound to a `DPoP` key (RFC 9449 5).
    Dpop,
}

impl TokenType {
    /// How a token bound as `binding` is presented.
    #[must_use]
    pub fn of(binding: &SenderBinding) -> Self {
        match binding {
            SenderBinding::DpopKey(_) => Self::Dpop,
            SenderBinding::Bearer | SenderBinding::Certificate(_) => Self::Bearer,
        }
    }
}

/// A token a grant may or may not hand out.
pub enum HandedToken {
    /// None was handed out.
    NotIssued,
    /// This one, shown once.
    Issued(Secret),
}

/// The ports making and keeping what the token endpoint hands out.
#[derive(ianua_macros::Fakes)]
pub struct IssuingPorts {
    /// Makes opaque tokens and hashes what records are kept under.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Where issued access tokens are kept.
    pub access_token_store: Arc<dyn AccessTokenStore>,
    /// Where refresh tokens are kept.
    pub refresh_token_store: Arc<dyn RefreshTokenStore>,
    /// Where the tenant's signing keys are kept.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs JWT access tokens and ID tokens.
    pub jwt_signer: Arc<dyn JwtSigner>,
    /// Works out the `at_hash` of an access token.
    pub at_hash: Arc<dyn AtHashCalculator>,
    /// Where the accounts tokens are issued for are kept.
    pub users: Arc<dyn UserStore>,
    /// Where roles are kept, for the `roles` claim.
    pub roles: Arc<dyn RoleStore>,
    /// The tenant's stream routes, whose tunnels a token may be asked for.
    pub stream_routes: Arc<dyn StreamRouteStore>,
    /// Checks what a request proves about its holder, for a bound token.
    pub sender: SenderProofPorts,
}

/// Where and for whom tokens are being made.
#[derive(Clone, Copy)]
pub(crate) struct Minting<'a> {
    /// The scope in which issued credentials are stored.
    pub(crate) tenant: &'a ScopedTenant,
    /// The authority named in the issued token claims.
    pub(crate) issuer: &'a Issuer,
    /// The client the tokens go to.
    pub(crate) client: &'a OAuthClient<ResolvedTenant>,
}

/// The raw value of an access token about to be issued.
pub(crate) enum AccessValue {
    /// An opaque token, handed out as it is.
    Opaque(Secret),
    /// A JWT to be signed with this `jti`, once its record exists.
    Jwt(TokenId),
}

/// What `client`'s tokens are bound to on a request to the token endpoint
/// that carried `evidence`, and what the request proved.
///
/// # Errors
///
/// - `TokenError::Refused` with `invalid_dpop_proof` when a `DPoP` header
///   was sent and does not check out, or the client binds its tokens to a
///   `DPoP` key and none was proved; `invalid_request` when it binds them to
///   its certificate, which never reaches the application.
/// - `TokenError::Failed` when the replay record cannot be written.
pub(crate) async fn proven_binding(
    ports: &IssuingPorts,
    tenant: &ScopedTenant,
    client: &OAuthClient<ResolvedTenant>,
    evidence: &SenderEvidence,
) -> Result<(SenderBinding, PresentedProof), TokenError> {
    let proof = proven_sender(&ports.sender, tenant, evidence, DpopUse::TokenRequest)
        .await
        .map_err(refused_proof)?;
    let binding = sender_binding(client, &proof)?;
    Ok((binding, proof))
}

/// The refusal for a `DPoP` proof that does not check out.
fn refused_proof(refusal: DomainError) -> TokenError {
    match refusal {
        DomainError::Unauthorized(reason) => {
            TokenError::refused(OAuthErrorCode::InvalidDpopProof, reason.as_str())
        }
        other => TokenError::Failed(AppError::internal(other)),
    }
}

/// What an access token is presented with, as `client` requires, on a
/// request that proved `proof`.
///
/// # Errors
///
/// - `TokenError::Refused` with `invalid_dpop_proof` when the client binds
///   its tokens to a `DPoP` key and none was proved, or `invalid_request`
///   when it binds them to its certificate and none was presented.
fn sender_binding(
    client: &OAuthClient<ResolvedTenant>,
    proof: &PresentedProof,
) -> Result<SenderBinding, TokenError> {
    let constraint = client.settings().sender_constraint;
    constraint.binding_for(proof).map_err(|_| match constraint {
        SenderConstraint::DpopRequired => TokenError::refused(
            OAuthErrorCode::InvalidDpopProof,
            "this client's tokens are bound to a DPoP key, and no proof was presented",
        ),
        SenderConstraint::CertificateRequired | SenderConstraint::BearerAllowed => {
            TokenError::refused(
                OAuthErrorCode::InvalidRequest,
                "this client's tokens are bound to its certificate, and none was presented",
            )
        }
    })
}

/// Refuses a client that was not given `grant`.
///
/// # Errors
///
/// - `TokenError::Refused` with `unauthorized_client`.
pub(crate) fn ensure_may_use(
    client: &OAuthClient<ResolvedTenant>,
    grant: GrantType,
) -> Result<(), TokenError> {
    if client.supports_grant_type(grant) {
        return Ok(());
    }
    Err(TokenError::refused(
        OAuthErrorCode::UnauthorizedClient,
        "this client may not use this grant",
    ))
}

/// How long `client`'s tokens last: its own terms, or `platform`.
pub(crate) fn terms_for(client: &OAuthClient<ResolvedTenant>, platform: TokenTerms) -> TokenTerms {
    client.settings().lifetimes.or_platform(platform)
}

/// The account a grant is for, while it may still sign in.
///
/// # Errors
///
/// - `TokenError::Refused` with `invalid_grant` when the account is gone or
///   may no longer sign in: its grants end with it.
/// - `TokenError::Failed` on storage failure.
pub(crate) async fn granted_account(
    ports: &IssuingPorts,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<User<ResolvedTenant>, TokenError> {
    ports
        .users
        .find_by_id(tenant, user_id)
        .await
        .or_internal()?
        .filter(User::can_authenticate)
        .ok_or_else(|| {
            TokenError::refused(
                OAuthErrorCode::InvalidGrant,
                "the account this grant is for may no longer sign in",
            )
        })
}

/// The names of the roles `user_id` holds in the tenant, for the `roles`
/// claim.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(crate) async fn role_names(
    roles: &dyn RoleStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<Vec<Label>, AppError> {
    let held = roles
        .find_effective_by_principal(tenant, &PrincipalRef::User(*user_id))
        .await
        .or_internal()?;
    Ok(held.iter().map(|role| role.name().clone()).collect())
}

/// A fresh raw value for an access token to `client`, in the form it chose,
/// with the hash its record is kept under.
///
/// # Errors
///
/// - `AppError::Internal` when the randomness source or the hasher fails,
///   or a fresh `jti` is malformed.
pub(crate) async fn fresh_access_value(
    ports: &IssuingPorts,
    client: &OAuthClient<ResolvedTenant>,
) -> Result<(AccessValue, TokenHash), AppError> {
    let hasher = ports.code_hasher.as_ref();
    if client.settings().token_format == AccessTokenFormat::Opaque {
        let (raw, hash) = hasher.generate_code().await.or_internal()?;
        return Ok((AccessValue::Opaque(raw), hash));
    }
    let jti = TokenId::new(uuid::Uuid::now_v7().to_string()).map_err(AppError::internal)?;
    let hash = hasher.hash_code(&jti_secret(&jti)).await.or_internal()?;
    Ok((AccessValue::Jwt(jti), hash))
}

/// The access token `issued` as handed to the client, once its record is
/// kept.
///
/// # Errors
///
/// - The cases [`handed_access`] lists.
/// - `AppError::Internal` when the record cannot be kept.
pub(crate) async fn kept_access(
    ports: &IssuingPorts,
    minting: Minting<'_>,
    issued: Issued<'_>,
) -> Result<Secret, AppError> {
    let token = issued.token;
    let raw = handed_access(ports, minting, issued).await?;
    ports
        .access_token_store
        .save(minting.tenant, token)
        .await
        .or_internal()?;
    Ok(raw)
}

/// What an access token for a person carries.
pub(crate) struct PersonGrant {
    /// The person.
    pub(crate) user_id: UserId,
    /// The permissions carried by the issued access token.
    pub(crate) scopes: Vec<Scope>,
    /// What it is bound to.
    pub(crate) binding: SenderBinding,
    /// How long it lasts.
    pub(crate) lifetime: Lifetime,
    /// How the person signed in, when that is at hand.
    pub(crate) sign_in: SignInFacts,
    /// What the token is meant for, checked before the grant spent anything.
    pub(crate) target: Target,
}

/// What a person's access token is meant for, checked before the grant
/// spends its code, refresh token or device approval, so a refused
/// resource costs the client nothing.
pub(crate) enum Target {
    /// Its client, and the APIs that client calls.
    Holder,
    /// The signed-in tunnel of this stream route, which a resource
    /// indicator asked for (RFC 8707).
    Tunnel(Box<StreamRoute<ResolvedTenant>>),
}

/// What `resource` names for `client` in `tenant`, checked.
///
/// # Errors
///
/// - `TokenError::Refused` with `invalid_target` when the route is not the
///   tenant's, opens no signed-in tunnel, is not active, or the client
///   takes opaque tokens, which a tunnel cannot read.
/// - `TokenError::Failed` when the route cannot be read.
pub(crate) async fn checked_target(
    ports: &IssuingPorts,
    tenant: &ScopedTenant,
    client: &OAuthClient<ResolvedTenant>,
    resource: TokenResource,
) -> Result<Target, TokenError> {
    let TokenResource::StreamRoute(route_id) = resource else {
        return Ok(Target::Holder);
    };
    let route = ports
        .stream_routes
        .find_by_id(tenant, &route_id)
        .await
        .or_internal()?
        .ok_or_else(|| unknown_target("the resource names no stream route of this tenant"))?;
    ensure_tunnel_for(client, &route).map_err(refused_target)?;
    Ok(Target::Tunnel(Box::new(route)))
}

/// An access token for `grant`, issued to `minting.client`, kept, with its
/// raw value.
///
/// # Errors
///
/// - `invalid_target` when the tunnel no longer takes the token.
/// - The cases [`kept_access`] lists.
pub(crate) async fn person_access(
    ports: &IssuingPorts,
    minting: Minting<'_>,
    grant: PersonGrant,
) -> Result<(AccessToken<ResolvedTenant>, Secret), TokenError> {
    let (value, token_hash) = fresh_access_value(ports, minting.client).await?;
    let params = IssueAccessTokenParams {
        token_hash,
        client_id: *minting.client.id(),
        user_id: grant.user_id,
        scopes: grant.scopes,
        lifetime: grant.lifetime,
        binding: grant.binding,
    };
    let token = match grant.target {
        Target::Holder => AccessToken::issue(params),
        Target::Tunnel(route) => {
            AccessToken::issue_for_tunnel(params, minting.client, &route).map_err(refused_target)?
        }
    };
    let issued = Issued {
        token: &token,
        value,
        audience: minting.client,
        sign_in: grant.sign_in,
    };
    let raw = kept_access(ports, minting, issued).await?;
    Ok((token, raw))
}

/// An `invalid_target` refusal, described by `reason`.
fn unknown_target(reason: &str) -> TokenError {
    TokenError::refused(OAuthErrorCode::InvalidTarget, reason)
}

/// The refusal of a tunnel the domain would not mint a token for.
fn refused_target(refusal: DomainError) -> TokenError {
    let reason = refusal.to_string();
    match refusal {
        DomainError::Validation(_) | DomainError::Forbidden(_) => unknown_target(&reason),
        other => TokenError::Failed(AppError::from_domain(other)),
    }
}

/// The access token `token` as handed to the client: its opaque value, or
/// the JWT of its record, meant for `audience`, signed with the tenant's
/// active key.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no active signing key.
/// - `AppError::Internal` when the claims cannot be built or signed.
async fn handed_access(
    ports: &IssuingPorts,
    minting: Minting<'_>,
    issued: Issued<'_>,
) -> Result<Secret, AppError> {
    let jti = match issued.value {
        AccessValue::Opaque(raw) => return Ok(raw),
        AccessValue::Jwt(jti) => jti,
    };
    let claims = JwtAccessTokenClaims::build(JwtAccessTokenParams {
        issuer: minting.issuer.clone(),
        token: issued.token,
        client: minting.client,
        audience: issued.audience,
        jti,
        sign_in: issued.sign_in,
    })
    .map_err(AppError::from_domain)?;
    let claims_json = serde_json::to_string(&claims).map_err(AppError::internal)?;
    let key = active_key(ports.key_store.as_ref(), minting.tenant).await?;
    signed(
        ports.jwt_signer.as_ref(),
        &key,
        &claims_json,
        JwtType::Access,
    )
    .await
}

/// An access token just issued, with its raw value, whom it is meant for
/// and how its person signed in.
pub(crate) struct Issued<'a> {
    /// The record.
    pub(crate) token: &'a AccessToken<ResolvedTenant>,
    /// Its raw value.
    pub(crate) value: AccessValue,
    /// The client it is meant for.
    pub(crate) audience: &'a OAuthClient<ResolvedTenant>,
    /// How its person signed in, when that is at hand.
    pub(crate) sign_in: SignInFacts,
}

/// The ID token for `granted`, handed to `minting.client`, when `scopes`
/// ask for `openid`: a code, a refresh and a device approval alike.
///
/// # Errors
///
/// - The cases [`signed_id_token`] lists.
pub(crate) async fn handed_id_token(
    ports: &IssuingPorts,
    minting: Minting<'_>,
    granted: Granted<'_>,
    terms: TokenTerms,
) -> Result<HandedToken, AppError> {
    if !asks_for_id_token(granted.scopes) {
        return Ok(HandedToken::NotIssued);
    }
    let signed = signed_id_token(ports, minting, granted, terms.id_token()).await?;
    Ok(HandedToken::Issued(signed))
}

/// The ID token for `granted`, handed to `minting.client`, issued beside
/// its access token, signed with the tenant's active key.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no active signing key.
/// - `AppError::Forbidden` when the grant does not make an ID token.
/// - `AppError::Internal` when a lookup, the hash or the signing fails.
async fn signed_id_token(
    ports: &IssuingPorts,
    minting: Minting<'_>,
    granted: Granted<'_>,
    lifetime: Lifetime,
) -> Result<Secret, AppError> {
    let key = active_key(ports.key_store.as_ref(), minting.tenant).await?;
    let at_hash = ports
        .at_hash
        .at_hash(granted.access_token, key.algorithm())
        .await
        .or_internal()?;
    let roles = role_names(ports.roles.as_ref(), minting.tenant, granted.account.id()).await?;
    let claims = IdTokenClaims::build(IdTokenParams {
        issuer: minting.issuer.clone(),
        client: minting.client,
        grant: granted.grant,
        account: granted.account,
        tenant_id: **minting.tenant,
        lifetime,
        at_hash,
        roles: &roles,
    })
    .map_err(AppError::from_domain)?;
    let claims_json = serde_json::to_string(&claims).map_err(AppError::internal)?;
    signed(
        ports.jwt_signer.as_ref(),
        &key,
        &claims_json,
        JwtType::IdToken,
    )
    .await
}

/// A grant just handed out, the scopes it carries, the account it is for,
/// and the access token issued for it.
pub(crate) struct Granted<'a> {
    /// The grant: a code just swapped, a refresh, or a device approval
    /// just collected.
    pub(crate) grant: IdTokenGrant<'a, ResolvedTenant>,
    /// The scopes the new tokens carry.
    pub(crate) scopes: &'a [Scope],
    /// The subject whose identity claims are added to the response.
    pub(crate) account: &'a User<ResolvedTenant>,
    /// The raw access token.
    pub(crate) access_token: &'a Secret,
}

/// The tenant's signing key in use now.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no key set, or no key in use.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn active_key(
    key_store: &dyn SigningKeyStore,
    tenant: &ScopedTenant,
) -> Result<SigningKey, AppError> {
    let key_set = existing_key_set(key_store, tenant).await?;
    key_set
        .active_key(clock::now())
        .cloned()
        .or_not_found(message!(
            "oauth-no-active-signing-key",
            "no active signing key"
        ))
}

/// `claims_json` signed by `signer` with `key` as a JWT of kind `typ`.
///
/// # Errors
///
/// - `AppError::Internal` when signing fails.
pub(crate) async fn signed(
    signer: &dyn JwtSigner,
    key: &SigningKey,
    claims_json: &str,
    typ: JwtType,
) -> Result<Secret, AppError> {
    let signing_key = JwtSigningKey {
        kid: key.kid(),
        algorithm: key.algorithm(),
        private_key: key.private_key(),
    };
    signer
        .sign_typed(claims_json, typ, signing_key)
        .await
        .or_internal()
        .map(Secret::new)
}
