//! Authorization codes: the short-lived code a client swaps for tokens in
//! the `OAuth2` authorization code flow with PKCE.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::sessions::account_check::SessionCheck;
use crate::domains::authentication::sessions::mfa_factor::{FactorProved, assurance_level_for};
use crate::domains::authentication::sessions::session::Session;
use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::domains::oauth::events::grants::{AuthorizationCodeExchanged, AuthorizationCodeIssued};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{
    EventLabel, Lifetime, Nonce, OAuthClientId, RedirectUri, Scope, SessionId, TokenHash, Usage,
    UserId,
};

/// How a PKCE code challenge is made from the verifier.
///
/// Only `S256` is offered. The `plain` method sends the verifier itself as
/// the challenge. Anyone who sees the authorization request could then
/// redeem an intercepted code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CodeChallengeMethod {
    /// The SHA-256 hash of the verifier.
    S256,
}

/// The OIDC nonce an authorization request carried, or that it carried
/// none.
///
/// A nonce is optional in the code flow. When none was sent, the ID token
/// carries none, and never one the request did not send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceSent {
    /// The request carried no nonce.
    NotSent,
    /// The request carried this nonce.
    Sent(Nonce),
}

impl NonceSent {
    /// Reads the stored column back. No value means none was sent.
    #[must_use]
    pub fn from_stored(nonce: Option<Nonce>) -> Self {
        nonce.map_or(Self::NotSent, Self::Sent)
    }

    /// The nonce, when one was sent. Storage and the ID token keep it this
    /// way.
    #[must_use]
    pub fn sent(&self) -> Option<&Nonce> {
        match self {
            Self::NotSent => None,
            Self::Sent(nonce) => Some(nonce),
        }
    }
}

/// A short-lived authorization code, issued after the user consents.
///
/// The client swaps the code for tokens. It works only once, and its
/// `usage` records that. PKCE is required, so a code caught in transit is
/// worth nothing without the verifier.
///
/// It keeps how its person signed in, read from their session when they
/// consented: the way in, the second factor and the time. The ID token is
/// built from the code, so its `amr`, `aal` and `auth_time` claims say what
/// the session proved, never what a use case wrote.
#[derive(Debug)]
pub struct AuthorizationCode<T: TenantScope> {
    /// The hash of the code. The raw code is sent once, to the redirect URI.
    code_hash: TokenHash,
    /// The client that asked for authorization.
    client_id: OAuthClientId,
    /// The user who approved the request.
    user_id: UserId,
    /// The redirect URI from the authorization request.
    redirect_uri: RedirectUri,
    /// The scopes the user gave.
    scopes: Vec<Scope>,
    /// The PKCE challenge, made from the verifier.
    code_challenge: CodeChallenge,
    /// How the challenge was made.
    code_challenge_method: CodeChallengeMethod,
    /// The OIDC nonce that ties the ID token to the authorization request.
    nonce: NonceSent,
    /// The session the person consented in. The ID token names it as
    /// `sid`, and signing out of it ends what it handed out.
    session_id: SessionId,
    /// How the session that consented began.
    auth_method: AuthMethod,
    /// The second factor that session proved, if any.
    second_factor: FactorProved,
    /// When the user signed in to the session that consented. The ID token
    /// reports it as `auth_time`.
    authenticated_at: OffsetDateTime,
    /// When the code was issued.
    created_at: OffsetDateTime,
    /// When the code expires.
    expires_at: OffsetDateTime,
    /// Whether the code was swapped for tokens, and when.
    usage: Usage,
    /// What it raised and was not taken yet.
    raised: Raised<T>,
    /// Which tenant scope this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// What a new authorization code is made from, beside the client it is
/// issued to and the session that consented.
pub struct CreateAuthCodeParams {
    /// The digest used to find this grant without storing its raw bearer code.
    pub code_hash: TokenHash,
    /// The redirect URI from the authorization request.
    pub redirect_uri: RedirectUri,
    /// The scopes the user gave.
    pub scopes: Vec<Scope>,
    /// The PKCE challenge.
    pub code_challenge: CodeChallenge,
    /// How the challenge was made.
    pub code_challenge_method: CodeChallengeMethod,
    /// The OIDC nonce that ties the ID token to the authorization request.
    pub nonce: NonceSent,
    /// How long the code can be swapped for tokens.
    pub lifetime: Lifetime,
}

/// The session a person consented in, with what it is held to now.
///
/// The code reads who consented and how they signed in from it. Mallory's
/// session is a password alone. Without this, a use case could write "a
/// hardware key at AAL3" on her code, and every app that trusts the ID
/// token's `aal` would let her in where a hardware key is required.
pub struct Consenting<'a, T: TenantScope> {
    /// The session the person consented in.
    pub session: &'a Session<T>,
    /// What the session is held to now: its account as it is, the tenant's
    /// timeouts and the time.
    pub check: &'a SessionCheck<'a, T>,
}

/// An authorization code as storage keeps it, checked again by
/// [`AuthorizationCode::reconstitute`].
pub struct AuthCodeRow {
    /// The stored digest used to find the grant during exchange.
    pub code_hash: TokenHash,
    /// The client that asked for authorization.
    pub client_id: OAuthClientId,
    /// The user who approved the request.
    pub user_id: UserId,
    /// The redirect URI from the authorization request.
    pub redirect_uri: RedirectUri,
    /// The scopes the user gave.
    pub scopes: Vec<Scope>,
    /// The PKCE challenge.
    pub code_challenge: CodeChallenge,
    /// How the challenge was made.
    pub code_challenge_method: CodeChallengeMethod,
    /// The OIDC nonce.
    pub nonce: NonceSent,
    /// The session the person consented in.
    pub session_id: SessionId,
    /// How the session that consented began.
    pub auth_method: AuthMethod,
    /// The second factor that session proved, if any.
    pub second_factor: FactorProved,
    /// When the user signed in to the session that consented.
    pub authenticated_at: OffsetDateTime,
    /// When the code was issued.
    pub created_at: OffsetDateTime,
    /// When the code expires.
    pub expires_at: OffsetDateTime,
    /// Whether it was swapped for tokens, and when.
    pub usage: Usage,
}

impl<T: TenantScope> AuthorizationCode<T> {
    /// Creates an unused authorization code for `client`, issued now, for
    /// the person signed in to `consenting.session`.
    ///
    /// The code is sent to its redirect URI and later swapped for tokens
    /// carrying its scopes. So the redirect must be one `client` registered,
    /// and every scope one it may ask for. Otherwise a request naming a
    /// trusted client could send the code to an attacker's address, or win
    /// scopes the client was never given.
    ///
    /// The person, their way in, their second factor and when they signed
    /// in are read from the session, which must still count now. Raises
    /// `oauth.authorization_code_issued`, naming `client`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `client` is not active or may not
    ///   use the authorization code flow.
    /// - [`DomainError::Forbidden`] when the redirect URI is not one
    ///   `client` registered.
    /// - [`DomainError::Forbidden`] when a scope is not one `client` may ask
    ///   for.
    /// - [`DomainError::Forbidden`] when the session no longer counts, as
    ///   [`SessionCheck::admits`] says.
    pub fn create(
        params: CreateAuthCodeParams,
        client: &OAuthClient<T>,
        consenting: &Consenting<'_, T>,
    ) -> Result<Self, DomainError> {
        ensure_code_client(client, &params.redirect_uri, &params.scopes)?;
        let session = consenting.session;
        let Some(person) = session.signed_in(consenting.check) else {
            return Err(DomainError::forbidden(message!(
                "oauth-the-session-that-consented-is-no",
                "the session that consented is no longer signed in"
            )));
        };
        let now = crate::shared::clock::now();
        Ok(Self {
            code_hash: params.code_hash,
            client_id: *client.id(),
            user_id: *session.user_id(),
            redirect_uri: params.redirect_uri,
            scopes: params.scopes,
            code_challenge: params.code_challenge,
            code_challenge_method: params.code_challenge_method,
            nonce: params.nonce,
            session_id: *session.id(),
            auth_method: person.progress().method(),
            second_factor: person.progress().factor(),
            authenticated_at: session.signed_in_at(),
            created_at: now,
            expires_at: params.lifetime.ends_after(now),
            usage: Usage::Unused,
            raised: Raised::default(),
            _scope: PhantomData,
        }
        .issued(EventLabel::of(client.name().as_str())))
    }

    /// This new code, having raised its issue to the client `client_label`
    /// names.
    fn issued(mut self, client_label: EventLabel) -> Self {
        self.raised.raise(AuthorizationCodeIssued {
            client_id: self.client_id,
            client_label,
            occurred_at: self.created_at,
        });
        self
    }

    /// Rebuilds an authorization code from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row records a provider's
    ///   second factor on a sign-in ianua checked itself.
    /// - [`DomainError::Infrastructure`] when the row was consented to
    ///   before its session signed in.
    /// - [`DomainError::Infrastructure`] when the row expires before it was
    ///   issued.
    /// - [`DomainError::Infrastructure`] when the row was swapped for tokens
    ///   before it was issued.
    pub fn reconstitute(row: AuthCodeRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            code_hash: row.code_hash,
            client_id: row.client_id,
            user_id: row.user_id,
            redirect_uri: row.redirect_uri,
            scopes: row.scopes,
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            nonce: row.nonce,
            session_id: row.session_id,
            auth_method: row.auth_method,
            second_factor: row.second_factor,
            authenticated_at: row.authenticated_at,
            created_at: row.created_at,
            expires_at: row.expires_at,
            usage: row.usage,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AuthCodeRow) -> Result<(), DomainError> {
        RowCheck::of("authorization code")
            .holds(
                !provider_factor_on_local_sign_in(row.auth_method, row.second_factor),
                "a provider's second factor on a sign-in ianua checked itself",
            )
            .in_order(
                row.authenticated_at,
                row.created_at,
                "consented to before its session signed in",
            )
            .holds(
                row.created_at < row.expires_at,
                "expires before it was issued",
            )
            .in_order_if(
                row.created_at,
                row.usage.used_at(),
                "exchanged before it was issued",
            )
            .finish()
    }

    /// The lookup digest; the raw bearer code is never retained here.
    #[must_use]
    pub fn code_hash(&self) -> &TokenHash {
        &self.code_hash
    }

    /// The client that asked for authorization.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// The user who approved the request.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The redirect URI from the authorization request.
    #[must_use]
    pub fn redirect_uri(&self) -> &RedirectUri {
        &self.redirect_uri
    }

    /// The session the person consented in.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The scopes the user gave.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// The PKCE challenge.
    #[must_use]
    pub fn code_challenge(&self) -> &CodeChallenge {
        &self.code_challenge
    }

    /// How the challenge was made.
    #[must_use]
    pub fn code_challenge_method(&self) -> CodeChallengeMethod {
        self.code_challenge_method
    }

    /// The OIDC nonce from the authorization request.
    #[must_use]
    pub fn nonce(&self) -> &NonceSent {
        &self.nonce
    }

    /// The assurance level the user's session had when they consented.
    #[must_use]
    pub fn assurance_level(&self) -> AssuranceLevel {
        assurance_level_for(self.auth_method, self.second_factor)
    }

    /// How the session that consented began.
    #[must_use]
    pub fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    /// The second factor the session that consented proved, if any.
    #[must_use]
    pub fn second_factor(&self) -> FactorProved {
        self.second_factor
    }

    /// When the code was issued.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the user signed in to the session that consented.
    #[must_use]
    pub fn authenticated_at(&self) -> OffsetDateTime {
        self.authenticated_at
    }

    /// When the code expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the code was swapped for tokens, or `None` while it is unused.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Whether the code has run out at `now`.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// Whether the code was already swapped for tokens.
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        self.usage.is_used()
    }

    /// Whether the code can still be swapped for tokens at `now`.
    ///
    /// This looks only at time and use. [`Self::consume`] also checks the
    /// client, the redirect and the verifier.
    #[must_use]
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        !self.is_expired(now) && !self.is_consumed()
    }

    /// Whether `uri` is exactly the redirect URI from the authorization
    /// request.
    #[must_use]
    pub fn matches_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uri.as_str() == uri
    }

    /// Marks the code as swapped for tokens.
    ///
    /// `exchange` must show three things. The caller is the client the code
    /// was issued to. It sent the same redirect. It holds the PKCE verifier
    /// behind the challenge. Without these, anyone who saw the code in
    /// transit could swap it for tokens. Raises
    /// `oauth.authorization_code_exchanged` at `now`, naming the client.
    ///
    /// # Errors
    ///
    /// Returns [`AuthCodeError::AlreadyConsumed`] for replay or [`AuthCodeError::Expired`] after expiry.
    /// Returns [`AuthCodeError::ClientRefused`] for the wrong or inactive client or a disallowed flow,
    /// [`AuthCodeError::ScopeWithdrawn`] for a scope the client lost,
    /// [`AuthCodeError::RedirectMismatch`] for a different redirect, or
    /// [`AuthCodeError::VerifierMismatch`] for a verifier that does not match the challenge.
    pub fn consume(
        &mut self,
        exchange: &CodeExchange<'_, T>,
        now: OffsetDateTime,
    ) -> Result<(), AuthCodeError> {
        if self.is_consumed() {
            return Err(AuthCodeError::AlreadyConsumed);
        }
        if self.is_expired(now) {
            return Err(AuthCodeError::Expired);
        }
        self.ensure_exchanged_by(exchange)?;
        self.usage = Usage::Used { at: now };
        self.raised.raise(AuthorizationCodeExchanged {
            client_id: self.client_id,
            client_label: EventLabel::of(exchange.client.name().as_str()),
            occurred_at: now,
        });
        Ok(())
    }

    fn ensure_exchanged_by(&self, exchange: &CodeExchange<'_, T>) -> Result<(), AuthCodeError> {
        let client = exchange.client;
        let client_may_exchange = *client.id() == self.client_id
            && client.is_active()
            && client.supports_grant_type(GrantType::AuthorizationCode);
        if !client_may_exchange {
            return Err(AuthCodeError::ClientRefused);
        }
        if client.first_unallowed_scope(&self.scopes).is_some() {
            return Err(AuthCodeError::ScopeWithdrawn);
        }
        if !self.matches_redirect_uri(exchange.redirect_uri) {
            return Err(AuthCodeError::RedirectMismatch);
        }
        if !self.answers_challenge(exchange.verifier_challenge) {
            return Err(AuthCodeError::VerifierMismatch);
        }
        Ok(())
    }

    fn answers_challenge(&self, verifier_challenge: &CodeChallenge) -> bool {
        let stored = self.code_challenge.as_str().as_bytes();
        subtle::ConstantTimeEq::ct_eq(stored, verifier_challenge.as_str().as_bytes()).into()
    }
}

impl<T: TenantScope> Raises for AuthorizationCode<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Whether `factor` is one a provider reports, on a sign-in through
/// `method` that ianua checked itself. No session reaches that.
fn provider_factor_on_local_sign_in(method: AuthMethod, factor: FactorProved) -> bool {
    let FactorProved::Proved(factor) = factor else {
        return false;
    };
    factor.is_reported_by_provider() && !method.is_federated()
}

/// Refuses a client that may not be issued a code, a redirect URI it did
/// not register, or scopes it was not given.
fn ensure_code_client<T: TenantScope>(
    client: &OAuthClient<T>,
    redirect_uri: &RedirectUri,
    scopes: &[Scope],
) -> Result<(), DomainError> {
    if !client.is_active() || !client.supports_grant_type(GrantType::AuthorizationCode) {
        return Err(DomainError::forbidden(message!(
            "oauth-this-client-may-not-use-the",
            "this client may not use the authorization code flow"
        )));
    }
    if !client.accepts_redirect(redirect_uri) {
        return Err(DomainError::forbidden(message!(
            "oauth-this-client-did-not-register-the",
            "this client did not register the redirect URI"
        )));
    }
    if let Some(scope) = client.first_unallowed_scope(scopes) {
        return Err(DomainError::forbidden(message!(
            "oauth-this-client-was-not-given-the",
            format!("this client was not given the scope {}", scope.as_str())
        )));
    }
    Ok(())
}

/// What a caller swapping a code for tokens presents.
pub struct CodeExchange<'a, T: TenantScope> {
    /// The client the caller signed in as.
    pub client: &'a OAuthClient<T>,
    /// The redirect URI the caller sent.
    pub redirect_uri: &'a str,
    /// The challenge the caller's `code_verifier` hashes to under the
    /// code's [`CodeChallengeMethod`], as the PKCE port worked it out.
    pub verifier_challenge: &'a CodeChallenge,
}

/// Why an authorization code was not swapped for tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthCodeError {
    /// The code was already used, as in a replay.
    #[error("the authorization code was already used")]
    AlreadyConsumed,
    /// The code has run out.
    #[error("the authorization code has expired")]
    Expired,
    /// The client exchanging the code is not the one it was issued to, or
    /// may not use the flow.
    #[error("this client may not exchange the authorization code")]
    ClientRefused,
    /// The client no longer holds a scope the code carries. The code is
    /// refused whole rather than narrowed, so the client asks again for
    /// what it still holds.
    #[error("the client no longer holds every scope the code carries")]
    ScopeWithdrawn,
    /// The redirect URI is not the one the code was issued for.
    #[error("the redirect URI does not match the authorization request")]
    RedirectMismatch,
    /// The PKCE verifier does not match the code's challenge.
    #[error("the code verifier does not match the code challenge")]
    VerifierMismatch,
}

text_value! {
    /// A PKCE code challenge, as RFC 7636 defines it.
    ///
    /// It is 43 to 128 characters of letters, digits, `-`, `.`, `_` and `~`.
    pub struct CodeChallenge;
}

impl TextValue for CodeChallenge {
    const FIELD: &'static str = "code_challenge";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            43..=128,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::DOT
                | Charset::UNDERSCORE
                | Charset::TILDE,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::proved_factor::proved;
    use crate::domains::authentication::sessions::session::tests::{
        signed_in_session, test_session,
    };
    use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::oauth::clients::client::{NewOAuthClient, OAuthClientChange};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{ClientId, CredentialChange};

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    const REDIRECT: &str = "https://app.acme.com/callback";

    fn web_client() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored(
                    "hashed_secret".to_owned(),
                )),
                name: crate::test_support::builders::label("Web app"),
                redirect_uris: vec![RedirectUri::new(REDIRECT).unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec![Scope::new("read").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    fn challenge() -> CodeChallenge {
        CodeChallenge::new(CHALLENGE).unwrap()
    }

    fn exchange<'a>(
        client: &'a OAuthClient<ResolvedTenant>,
        verifier_challenge: &'a CodeChallenge,
    ) -> CodeExchange<'a, ResolvedTenant> {
        CodeExchange {
            client,
            redirect_uri: REDIRECT,
            verifier_challenge,
        }
    }

    /// A one-minute code for `read`, sent to the web app's redirect.
    fn params() -> CreateAuthCodeParams {
        CreateAuthCodeParams {
            code_hash: TokenHash::from_stored("hash_abc".to_owned()),
            redirect_uri: RedirectUri::new(REDIRECT).unwrap(),
            scopes: vec![Scope::new("read").unwrap()],
            code_challenge: CodeChallenge::new(CHALLENGE).unwrap(),
            code_challenge_method: CodeChallengeMethod::S256,
            nonce: NonceSent::NotSent,
            lifetime: crate::types::Lifetime::seconds(60).unwrap(),
        }
    }

    /// The account `session` belongs to, in `status`.
    fn account_of(session: &Session<ResolvedTenant>, status: UserStatus) -> User<ResolvedTenant> {
        account_with(*session.user_id(), status, CredentialChange::Never)
    }

    /// What a session of `account` is held to now.
    fn check_on(account: &User<ResolvedTenant>) -> SessionCheck<'_, ResolvedTenant> {
        SessionCheck {
            account,
            timeout: &SessionTimeoutPolicy::STANDARD,
            now: crate::shared::clock::now(),
        }
    }

    /// A code made from `params` for `client`, consented to in `session`,
    /// whose account is active.
    fn issued_in(
        session: &Session<ResolvedTenant>,
        params: CreateAuthCodeParams,
        client: &OAuthClient<ResolvedTenant>,
    ) -> Result<AuthorizationCode<ResolvedTenant>, DomainError> {
        let account = account_of(session, UserStatus::Active);
        let check = check_on(&account);
        AuthorizationCode::create(
            params,
            client,
            &Consenting {
                session,
                check: &check,
            },
        )
    }

    /// A code made from `params` for `client`, consented to after a
    /// finished password sign-in.
    fn issued(
        params: CreateAuthCodeParams,
        client: &OAuthClient<ResolvedTenant>,
    ) -> Result<AuthorizationCode<ResolvedTenant>, DomainError> {
        issued_in(&signed_in_session(), params, client)
    }

    fn code_for(client: &OAuthClient<ResolvedTenant>) -> AuthorizationCode<ResolvedTenant> {
        issued(params(), client).unwrap()
    }

    fn test_code() -> AuthorizationCode<ResolvedTenant> {
        code_for(&web_client())
    }

    /// A code that lasts one second, for `client`.
    fn one_second_code(client: &OAuthClient<ResolvedTenant>) -> AuthorizationCode<ResolvedTenant> {
        let params = CreateAuthCodeParams {
            lifetime: crate::types::Lifetime::seconds(1).unwrap(),
            ..params()
        };
        issued(params, client).unwrap()
    }

    /// Ann signs in with her password and an authenticator code, then
    /// consents. The code keeps her account, the password, the code as her
    /// second factor and when she signed in, all read from her session. So
    /// the ID token says AAL2 because she reached it.
    #[test]
    fn a_code_keeps_how_its_person_signed_in() {
        let mut session = test_session();
        let account = account_of(&session, UserStatus::Active);
        let proof = proved((*session.user_id()).into(), MfaFactor::Totp);
        session
            .answer(&account, proof, &StepUpPolicy::relaxed())
            .unwrap();

        let code = issued_in(&session, params(), &web_client()).unwrap();

        assert_eq!(code.user_id(), session.user_id());
        assert_eq!(code.auth_method(), AuthMethod::Password);
        assert_eq!(code.second_factor(), FactorProved::Proved(MfaFactor::Totp));
        assert_eq!(code.authenticated_at(), session.signed_in_at());
        assert_eq!(code.assurance_level(), AssuranceLevel::Aal2);
    }

    /// An existing sign-in cannot authorize code issuance when its account
    /// is locked. Creating the code is forbidden.
    #[test]
    fn a_session_that_no_longer_counts_issues_no_code() {
        let session = signed_in_session();
        let locked = account_of(&session, UserStatus::Locked);
        let check = check_on(&locked);

        let result = AuthorizationCode::<ResolvedTenant>::create(
            params(),
            &web_client(),
            &Consenting {
                session: &session,
                check: &check,
            },
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A session still awaiting its second factor cannot authorize code
    /// issuance. Creating the code is forbidden.
    #[test]
    fn an_unfinished_sign_in_issues_no_code() {
        let result = issued_in(&test_session(), params(), &web_client());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Issuing a code for the web app with an unregistered callback is
    /// forbidden.
    #[test]
    fn a_code_is_not_issued_to_a_redirect_the_client_did_not_register() {
        let params = CreateAuthCodeParams {
            redirect_uri: RedirectUri::new("https://evil.com/callback").unwrap(),
            ..params()
        };

        let result = issued(params, &web_client());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Issuing a code carrying `admin` as well as `read` is forbidden when
    /// the web app is registered only for `read`.
    #[test]
    fn a_code_is_not_issued_for_a_scope_the_client_was_not_given() {
        let params = CreateAuthCodeParams {
            scopes: vec![Scope::new("read").unwrap(), Scope::new("admin").unwrap()],
            ..params()
        };

        let result = issued(params, &web_client());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Revoking the web app makes subsequent code issuance to it forbidden.
    #[test]
    fn a_code_is_not_issued_to_a_revoked_client() {
        let mut client = web_client();
        client.revoke(&key_admin()).unwrap();

        let result = issued(params(), &client);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Removing `read` from the web app after code issuance makes exchange
    /// fail with a withdrawn-scope refusal. The code remains unused.
    #[test]
    fn a_code_is_not_exchanged_for_a_scope_the_client_has_since_lost() {
        let mut client = web_client();
        let mut code = code_for(&client);
        client
            .update(vec![OAuthClientChange::Scopes(Vec::new())], &key_admin())
            .unwrap();

        let result = code.consume(
            &exchange(&client, &challenge()),
            crate::shared::clock::now(),
        );

        assert_eq!(result, Err(AuthCodeError::ScopeWithdrawn));
        assert!(!code.is_consumed());
    }

    /// A code issued for a minute is valid right away, unused and not
    /// expired.
    #[test]
    fn create_is_valid() {
        let code = test_code();
        let now = crate::shared::clock::now();

        assert!(code.is_valid(now));
        assert!(!code.is_consumed());
        assert!(!code.is_expired(now));
    }

    /// The web app swaps its code with the right redirect and verifier. The
    /// code is marked used, with a time.
    #[test]
    fn consume_marks_used() {
        let client = web_client();
        let mut code = code_for(&client);
        let now = crate::shared::clock::now();

        assert!(code.consume(&exchange(&client, &challenge()), now).is_ok());
        assert!(code.is_consumed());
        assert!(code.consumed_at().is_some());
    }

    /// Exchanging the same code twice succeeds once, then returns an
    /// already-consumed refusal.
    #[test]
    fn double_consume_is_replay_attack() {
        let client = web_client();
        let mut code = code_for(&client);
        let now = crate::shared::clock::now();
        let challenge = challenge();

        code.consume(&exchange(&client, &challenge), now).unwrap();
        assert_eq!(
            code.consume(&exchange(&client, &challenge), now),
            Err(AuthCodeError::AlreadyConsumed)
        );
    }

    /// A different client cannot exchange the web app's code. The client
    /// refusal leaves the code unused.
    #[test]
    fn another_client_cannot_exchange_the_code() {
        let client = web_client();
        let mut code = code_for(&client);

        let result = code.consume(
            &exchange(&web_client(), &challenge()),
            crate::shared::clock::now(),
        );

        assert_eq!(result, Err(AuthCodeError::ClientRefused));
        assert!(!code.is_consumed());
    }

    /// Exchanging a code with a different callback returns a redirect-mismatch
    /// refusal.
    #[test]
    fn a_code_is_not_exchanged_at_another_redirect() {
        let client = web_client();
        let mut code = code_for(&client);
        let challenge = challenge();

        let result = code.consume(
            &CodeExchange {
                redirect_uri: "https://evil.com/callback",
                ..exchange(&client, &challenge)
            },
            crate::shared::clock::now(),
        );

        assert_eq!(result, Err(AuthCodeError::RedirectMismatch));
    }

    /// An exchange by the correct client with a mismatched verifier challenge
    /// fails, leaving the code unused.
    #[test]
    fn a_code_is_not_exchanged_without_its_verifier() {
        let client = web_client();
        let mut code = code_for(&client);
        let other = CodeChallenge::new("A".repeat(43)).unwrap();

        let result = code.consume(&exchange(&client, &other), crate::shared::clock::now());

        assert_eq!(result, Err(AuthCodeError::VerifierMismatch));
        assert!(!code.is_consumed());
    }

    /// A code that lasts one second is swapped two seconds later. It is
    /// refused as expired.
    #[test]
    fn consume_expired_code_fails() {
        let client = web_client();
        let mut code = one_second_code(&client);

        let future = crate::shared::clock::now() + time::Duration::seconds(2);
        assert_eq!(
            code.consume(&exchange(&client, &challenge()), future),
            Err(AuthCodeError::Expired)
        );
    }

    /// A code issued for `https://app.acme.com/callback` matches that URI
    /// and not `https://evil.com/callback`.
    #[test]
    fn matches_redirect_uri() {
        let code = test_code();
        assert!(code.matches_redirect_uri("https://app.acme.com/callback"));
        assert!(!code.matches_redirect_uri("https://evil.com/callback"));
    }

    /// Two seconds after a one-second code was issued, it is expired and no
    /// longer valid.
    #[test]
    fn expired_code_is_not_valid() {
        let code = one_second_code(&web_client());

        let future = crate::shared::clock::now() + time::Duration::seconds(2);
        assert!(code.is_expired(future));
        assert!(!code.is_valid(future));
    }

    /// Once a code is swapped for tokens, it is not valid, even while in
    /// date.
    #[test]
    fn consumed_code_is_not_valid() {
        let client = web_client();
        let mut code = code_for(&client);
        let now = crate::shared::clock::now();
        code.consume(&exchange(&client, &challenge()), now).unwrap();

        assert!(!code.is_valid(now));
    }

    /// A code keeps the hash, client, user, redirect, scopes and PKCE
    /// challenge it was made with. The token swap checks against these, so
    /// any of them read back wrong would let a bad swap through.
    #[test]
    fn a_code_carries_everything_the_token_exchange_checks_it_against() {
        let client = web_client();
        let session = signed_in_session();

        let code = issued_in(&session, params(), &client).unwrap();

        assert_eq!(code.code_hash().as_str(), "hash_abc");
        assert_eq!(code.client_id(), client.id());
        assert_eq!(code.user_id(), session.user_id());
        assert_eq!(
            code.redirect_uri().as_str(),
            "https://app.acme.com/callback"
        );
        assert_eq!(code.scopes(), &[Scope::new("read").unwrap()]);
        assert_eq!(code.code_challenge().as_str(), CHALLENGE);
    }

    /// A request that sent a nonce keeps exactly that nonce, and one that
    /// sent none keeps none. The nonce goes into the ID token, so a dropped
    /// one fails the app's replay check and a made-up one answers no request.
    #[test]
    fn a_code_keeps_the_nonce_the_request_carried_and_no_other() {
        let nonce = Nonce::new("n-0S6_WzA2Mj-4B7c").unwrap();

        let with_nonce = issued(
            CreateAuthCodeParams {
                nonce: NonceSent::Sent(nonce.clone()),
                ..params()
            },
            &web_client(),
        )
        .unwrap();

        assert_eq!(with_nonce.nonce(), &NonceSent::Sent(nonce));
        assert_eq!(test_code().nonce(), &NonceSent::NotSent);
    }

    /// A 43-character S256 challenge from RFC 7636 is accepted.
    #[test]
    fn a_well_formed_code_challenge_is_accepted() {
        assert!(CodeChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").is_ok());
    }

    /// An empty challenge, a short one and one with a space are each
    /// refused.
    #[test]
    fn a_malformed_code_challenge_is_refused() {
        for value in ["", "short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw cM"] {
            assert!(CodeChallenge::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// A stored code says its session signed in a second after the code was
    /// made. It would carry an assurance level the person had not reached
    /// when they agreed, so it is refused as corrupt.
    #[test]
    fn a_stored_code_consented_before_its_session_signed_in_is_refused() {
        let code = test_code();
        let row = AuthCodeRow {
            authenticated_at: code.created_at + time::Duration::SECOND,
            ..row_of(&code)
        };

        assert!(refused_as_corrupt(
            &AuthorizationCode::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored code says Ann signed in with her own password and that her
    /// identity provider reported a hardware key. No session reaches that,
    /// and the ID token would claim AAL3, so it is refused as corrupt.
    #[test]
    fn a_stored_code_with_a_provider_factor_on_a_password_sign_in_is_refused() {
        let code = test_code();
        let row = AuthCodeRow {
            auth_method: AuthMethod::Password,
            second_factor: FactorProved::Proved(MfaFactor::ProviderHardwareKey),
            ..row_of(&code)
        };

        assert!(refused_as_corrupt(
            &AuthorizationCode::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// `code` as storage keeps it.
    fn row_of(code: &AuthorizationCode<ResolvedTenant>) -> AuthCodeRow {
        AuthCodeRow {
            code_hash: code.code_hash.clone(),
            client_id: code.client_id,
            user_id: code.user_id,
            redirect_uri: code.redirect_uri.clone(),
            scopes: code.scopes.clone(),
            code_challenge: code.code_challenge.clone(),
            code_challenge_method: code.code_challenge_method,
            nonce: code.nonce.clone(),
            session_id: code.session_id,
            auth_method: code.auth_method,
            second_factor: code.second_factor,
            authenticated_at: code.authenticated_at,
            created_at: code.created_at,
            expires_at: code.expires_at,
            usage: code.usage,
        }
    }

    /// A stored code read back keeps how its person signed in, so an ID
    /// token built from it after a restart says the same.
    #[test]
    fn a_stored_code_reads_back_how_its_person_signed_in() {
        let code = test_code();

        let read = AuthorizationCode::<ResolvedTenant>::reconstitute(row_of(&code)).unwrap();

        assert_eq!(read.auth_method(), code.auth_method());
        assert_eq!(read.second_factor(), code.second_factor());
        assert_eq!(read.authenticated_at(), code.authenticated_at());
        assert_eq!(read.session_id(), code.session_id());
    }

    /// Ann consents to the web app. Issuing the code is raised, naming the
    /// web app by its name.
    #[test]
    fn issuing_raises_oauth_authorization_code_issued() {
        let mut code = test_code();

        let events = raised(&mut code);

        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.authorization_code_issued"
        );
        assert_eq!(events.len(), 1);
        assert_eq!(client_label_of(&events[0]), "Web app");
    }

    /// The web app swaps its code. The swap is raised, naming the web app.
    #[test]
    fn swapping_raises_oauth_authorization_code_exchanged() {
        let client = web_client();
        let mut code = code_for(&client);
        raised_names(&mut code);

        code.consume(
            &exchange(&client, &challenge()),
            crate::shared::clock::now(),
        )
        .unwrap();

        let events = raised(&mut code);
        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.authorization_code_exchanged"
        );
        assert_eq!(client_label_of(&events[0]), "Web app");
    }

    /// Ann's code is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_code_read_back_from_storage_has_raised_nothing() {
        let mut read =
            AuthorizationCode::<ResolvedTenant>::reconstitute(row_of(&test_code())).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }

    /// Once the code has been consumed, further exchanges by its client and
    /// another client both fail without raising events.
    #[test]
    fn a_refused_swap_raises_nothing() {
        let client = web_client();
        let mut code = code_for(&client);
        let now = crate::shared::clock::now();
        code.consume(&exchange(&client, &challenge()), now).unwrap();
        raised_names(&mut code);

        let by_another = code.consume(&exchange(&web_client(), &challenge()), now);
        let replayed = code.consume(&exchange(&client, &challenge()), now);

        assert!(by_another.is_err());
        assert!(replayed.is_err());
        assert!(raised_names(&mut code).is_empty());
    }

    /// The label an event gives the client it names.
    fn client_label_of(event: &DomainEvent) -> String {
        let payload = event.payload();
        let Some(crate::shared::events::data::FieldValue::Reference(client)) =
            payload.value("client")
        else {
            panic!("the event does not name the client");
        };
        client.label().to_owned()
    }
}
