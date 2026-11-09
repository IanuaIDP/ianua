//! Fakes for what an OAuth grant leaves behind: authorization codes, device
//! authorizations, and issued access and refresh tokens.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::domains::oauth::grants::authorization_code::{AuthCodeRow, AuthorizationCode};
use ianua_domain::domains::oauth::grants::device_authorization::{
    DeviceAuthRow, DeviceAuthState, DeviceAuthorization,
};
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::domains::oauth::grants::refresh_token::{
    OAuthRefreshToken, OAuthRefreshTokenRow, RefreshState,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    DeviceUserCode, OAuthClientId, RefreshFamilyId, SessionId, TenantId, TokenHash, Usage, UserId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::oauth::{
    AccessTokenStore, AuthCodeStore, ConsentedSession, DEVICE_EXPIRY_BATCH, DeviceAuthStore,
    RefreshRotation, RefreshTokenStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// In-memory authorization code store, each code kept by its hash under its
/// tenant.
#[derive(Default)]
pub struct FakeAuthCodeStore {
    codes: Mutex<Vec<(TenantId, AuthorizationCode<ResolvedTenant>)>>,
}

impl TenantScoped for FakeAuthCodeStore {}

impl FakeAuthCodeStore {
    /// A store holding no code.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many codes are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.codes.lock().unwrap().len()
    }
}

#[async_trait]
impl AuthCodeStore for FakeAuthCodeStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<AuthorizationCode<ResolvedTenant>>, DomainError> {
        self.codes
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, code)| tenant == &**tenant_id && code.code_hash() == code_hash)
            .map(|(_, code)| copy_code(code))
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_code(code)?;
        let mut codes = self.codes.lock().unwrap();
        codes.retain(|(tenant, kept)| {
            !(tenant == &**tenant_id && kept.code_hash() == code.code_hash())
        });
        codes.push((**tenant_id, copy));
        Ok(())
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let copy = copy_code(code)?;
        let mut codes = self.codes.lock().unwrap();
        let Some(stored) = codes
            .iter_mut()
            .find(|(tenant, kept)| tenant == &**tenant_id && kept.code_hash() == code.code_hash())
        else {
            return Ok(false);
        };
        if stored.1.is_consumed() {
            return Ok(false);
        }
        stored.1 = copy;
        Ok(true)
    }

    async fn consented_sessions(
        &self,
        tenant_id: &ScopedTenant,
        signed_out: SignedOut,
    ) -> Result<Vec<ConsentedSession>, DomainError> {
        let (person, session) = match signed_out {
            SignedOut::Session { person, session } => (person, Some(session)),
            SignedOut::Everywhere { person } => (person, None),
        };
        let mut found: Vec<ConsentedSession> = Vec::new();
        for (tenant, code) in self.codes.lock().unwrap().iter() {
            let pair = ConsentedSession {
                client: *code.client_id(),
                session: *code.session_id(),
            };
            if tenant == &**tenant_id
                && *code.user_id() == person
                && session.is_none_or(|session| *code.session_id() == session)
                && !found.contains(&pair)
            {
                found.push(pair);
            }
        }
        Ok(found)
    }
}

impl Fake for Arc<dyn AuthCodeStore> {
    fn fake() -> Self {
        Arc::new(FakeAuthCodeStore::empty())
    }
}

/// `code` written out and read back, as storage would return it.
fn copy_code(
    code: &AuthorizationCode<ResolvedTenant>,
) -> Result<AuthorizationCode<ResolvedTenant>, DomainError> {
    AuthorizationCode::reconstitute(AuthCodeRow {
        code_hash: code.code_hash().clone(),
        client_id: *code.client_id(),
        user_id: *code.user_id(),
        redirect_uri: code.redirect_uri().clone(),
        scopes: code.scopes().to_vec(),
        code_challenge: code.code_challenge().clone(),
        code_challenge_method: code.code_challenge_method(),
        nonce: code.nonce().clone(),
        session_id: *code.session_id(),
        auth_method: code.auth_method(),
        second_factor: code.second_factor(),
        authenticated_at: code.authenticated_at(),
        created_at: code.created_at(),
        expires_at: code.expires_at(),
        usage: Usage::from_stored(code.consumed_at()),
    })
}

/// In-memory device authorization store, each authorization kept by its
/// device code hash under its tenant.
#[derive(Default)]
pub struct FakeDeviceAuthStore {
    auths: Mutex<Vec<(TenantId, DeviceAuthorization<ResolvedTenant>)>>,
    lapsed_batches: Mutex<Vec<usize>>,
    lapsed_scopes: Mutex<Vec<Option<TenantId>>>,
    refuse_saves: Mutex<bool>,
}

impl TenantScoped for FakeDeviceAuthStore {}

impl FakeDeviceAuthStore {
    /// Refuses later writes so expiry tests can verify fail-fast persistence.
    pub fn refuse_saves(&self) {
        *self.refuse_saves.lock().unwrap() = true;
    }

    /// The tenant scope of each expiry read; `None` records a global scan.
    #[must_use]
    pub fn lapsed_scopes(&self) -> Vec<Option<TenantId>> {
        self.lapsed_scopes.lock().unwrap().clone()
    }

    /// The sizes returned by device-expiry reads, for bounded sweep regressions.
    #[must_use]
    pub fn lapsed_batch_sizes(&self) -> Vec<usize> {
        self.lapsed_batches.lock().unwrap().clone()
    }

    /// A store holding no authorization.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many authorizations are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.auths.lock().unwrap().len()
    }

    fn find(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&DeviceAuthorization<ResolvedTenant>) -> bool,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        self.auths
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, auth)| tenant == &**tenant_id && matches(auth))
            .map(|(_, auth)| copy_auth(auth, auth.state()))
            .transpose()
    }
}

#[async_trait]
impl DeviceAuthStore for FakeDeviceAuthStore {
    async fn list_lapsed(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Result<Vec<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        self.lapsed_scopes.lock().unwrap().push(Some(**tenant));
        let found: Vec<_> = self
            .auths
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, auth)| owner == &**tenant && auth.is_pending() && auth.is_expired(now))
            .take(DEVICE_EXPIRY_BATCH)
            .map(|(_, auth)| copy_auth(auth, auth.state()))
            .collect::<Result<_, DomainError>>()?;
        self.lapsed_batches.lock().unwrap().push(found.len());
        Ok(found)
    }

    async fn find_by_device_code_hash(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        self.find(tenant_id, |auth| {
            auth.device_code_hash() == device_code_hash
        })
    }

    async fn find_by_user_code(
        &self,
        tenant_id: &ScopedTenant,
        user_code: &DeviceUserCode,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        self.find(tenant_id, |auth| auth.user_code() == user_code)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if *self.refuse_saves.lock().unwrap() {
            return Err(DomainError::infra_msg("device authorization save refused"));
        }
        let copy = copy_auth(auth, auth.state())?;
        let mut auths = self.auths.lock().unwrap();
        auths.retain(|(tenant, kept)| {
            !(tenant == &**tenant_id && kept.device_code_hash() == auth.device_code_hash())
        });
        auths.push((**tenant_id, copy));
        Ok(())
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut auths = self.auths.lock().unwrap();
        let Some((_, auth)) = auths.iter_mut().find(|(tenant, auth)| {
            tenant == &**tenant_id && auth.device_code_hash() == device_code_hash
        }) else {
            return Ok(false);
        };
        let DeviceAuthState::Approved { by } = auth.state() else {
            return Ok(false);
        };
        if auth.is_expired(now) {
            return Ok(false);
        }
        *auth = copy_auth(auth, DeviceAuthState::Redeemed { by })?;
        Ok(true)
    }

    async fn record_poll(
        &self,
        tenant_id: &ScopedTenant,
        polled: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut auths = self.auths.lock().unwrap();
        let Some((_, stored)) = auths.iter_mut().find(|(tenant, auth)| {
            tenant == &**tenant_id && auth.device_code_hash() == polled.device_code_hash()
        }) else {
            return Ok(());
        };
        let state = stored.state();
        *stored = copy_auth(polled, state)?;
        Ok(())
    }
}

impl Fake for Arc<dyn DeviceAuthStore> {
    fn fake() -> Self {
        Arc::new(FakeDeviceAuthStore::empty())
    }
}

/// `auth` written out in `state` and read back, as storage would return it.
fn copy_auth(
    auth: &DeviceAuthorization<ResolvedTenant>,
    state: DeviceAuthState,
) -> Result<DeviceAuthorization<ResolvedTenant>, DomainError> {
    DeviceAuthorization::reconstitute(DeviceAuthRow {
        device_code_hash: auth.device_code_hash().clone(),
        user_code: auth.user_code().clone(),
        client_id: *auth.client_id(),
        scopes: auth.scopes().to_vec(),
        state,
        interval: auth.interval(),
        last_poll: auth.last_poll(),
        created_at: auth.created_at(),
        expires_at: auth.expires_at(),
    })
}

/// In-memory store of issued access tokens, each kept by its hash under its
/// tenant.
#[derive(Default)]
pub struct FakeAccessTokenStore {
    tokens: Mutex<Vec<(TenantId, AccessToken<ResolvedTenant>)>>,
}

impl TenantScoped for FakeAccessTokenStore {}

impl FakeAccessTokenStore {
    /// A store holding no token.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `token` in `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, token: AccessToken<ResolvedTenant>) -> Self {
        Self {
            tokens: Mutex::new(vec![(**tenant, token)]),
        }
    }

    /// How many tokens are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }

    /// Every kept token, in every tenant, in the order first saved.
    #[must_use]
    pub fn all(&self) -> Vec<AccessToken<ResolvedTenant>> {
        self.tokens
            .lock()
            .unwrap()
            .iter()
            .map(|(_, token)| token.clone())
            .collect()
    }

    /// Revokes every kept token, to show a revoked grant stops working.
    pub fn revoke_all(&self) {
        for (_, token) in self.tokens.lock().unwrap().iter_mut() {
            token.revoke();
        }
    }
}

#[async_trait]
impl AccessTokenStore for FakeAccessTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<AccessToken<ResolvedTenant>>, DomainError> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, token)| tenant == &**tenant_id && token.token_hash() == token_hash)
            .map(|(_, token)| token.clone()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|(tenant, kept)| {
            !(tenant == &**tenant_id && kept.token_hash() == token.token_hash())
        });
        tokens.push((**tenant_id, token.clone()));
        Ok(())
    }

    async fn revoke_grant(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        for (tenant, token) in self.tokens.lock().unwrap().iter_mut() {
            let of_grant = token.subject().person() == Some(person) && token.belongs_to(client);
            if tenant == &**tenant_id && of_grant {
                token.revoke();
            }
        }
        Ok(())
    }
}

impl Fake for Arc<dyn AccessTokenStore> {
    fn fake() -> Self {
        Arc::new(FakeAccessTokenStore::empty())
    }
}

/// In-memory store of refresh tokens, each kept as its row under its
/// tenant.
#[derive(Default)]
pub struct FakeRefreshTokenStore {
    rows: Mutex<Vec<(TenantId, OAuthRefreshTokenRow)>>,
    rival_next: Mutex<Option<TokenHash>>,
}

impl TenantScoped for FakeRefreshTokenStore {}

impl FakeRefreshTokenStore {
    /// A store holding no token.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `row` in `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, row: OAuthRefreshTokenRow) -> Self {
        Self {
            rows: Mutex::new(vec![(**tenant, row)]),
            rival_next: Mutex::new(None),
        }
    }

    /// A store holding `row` in `tenant`, where another refresh presenting
    /// the same token rotates it first, keeping its own next token under
    /// `rival_next`, just before the first rotation asked of the store.
    #[must_use]
    pub fn raced(tenant: &ScopedTenant, row: OAuthRefreshTokenRow, rival_next: TokenHash) -> Self {
        Self {
            rows: Mutex::new(vec![(**tenant, row)]),
            rival_next: Mutex::new(Some(rival_next)),
        }
    }

    /// Rotates the token `used` names in `rows`, as the rival refresh
    /// would, when one is waiting to.
    fn rival_rotates(&self, rows: &mut Vec<(TenantId, OAuthRefreshTokenRow)>, used: &TokenHash) {
        let Some(rival_next) = self.rival_next.lock().unwrap().take() else {
            return;
        };
        let Some((tenant, stored)) = rows.iter_mut().find(|(_, row)| row.token_hash == *used)
        else {
            return;
        };
        let next = OAuthRefreshTokenRow {
            token_hash: rival_next,
            ..stored.clone()
        };
        stored.state = RefreshState::Rotated {
            at: stored.issued_at,
        };
        let tenant = *tenant;
        rows.push((tenant, next));
    }

    /// How many tokens are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    /// The state of the token whose hash is `hash`, in whichever tenant
    /// keeps it.
    #[must_use]
    pub fn state_of(&self, hash: &TokenHash) -> Option<RefreshState> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|(_, row)| row.token_hash == *hash)
            .map(|(_, row)| row.state)
    }

    /// Revokes, at `now`, every active token of `tenant_id` that `matches`.
    fn revoke_where(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        matches: impl Fn(&OAuthRefreshTokenRow) -> bool,
    ) {
        for (tenant, row) in self.rows.lock().unwrap().iter_mut() {
            let active = row.state == RefreshState::Active;
            if tenant == &**tenant_id && active && matches(row) {
                row.state = RefreshState::Revoked { at: now };
            }
        }
    }
}

#[async_trait]
impl RefreshTokenStore for FakeRefreshTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<OAuthRefreshToken<ResolvedTenant>>, DomainError> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, row)| tenant == &**tenant_id && row.token_hash == *token_hash)
            .map(|(_, row)| OAuthRefreshToken::reconstitute(row.clone()))
            .transpose()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        token: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.rows
            .lock()
            .unwrap()
            .push((**tenant_id, token.to_row()));
        Ok(())
    }

    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        used: &OAuthRefreshToken<ResolvedTenant>,
        next: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<RefreshRotation, DomainError> {
        let mut rows = self.rows.lock().unwrap();
        self.rival_rotates(&mut rows, used.token_hash());
        let Some((_, stored)) = rows
            .iter_mut()
            .find(|(tenant, row)| tenant == &**tenant_id && row.token_hash == *used.token_hash())
        else {
            return Ok(RefreshRotation::Ended);
        };
        let state = stored.state;
        match state {
            RefreshState::Active => {
                *stored = used.to_row();
                rows.push((**tenant_id, next.to_row()));
                Ok(RefreshRotation::Rotated)
            }
            RefreshState::Rotated { .. } => {
                drop(rows);
                self.revoke_where(tenant_id, rotated_at(used), |row| {
                    row.family == *used.family()
                });
                Ok(RefreshRotation::Reused)
            }
            RefreshState::Revoked { .. } => Ok(RefreshRotation::Ended),
        }
    }

    async fn revoke_family(
        &self,
        tenant_id: &ScopedTenant,
        family: &RefreshFamilyId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.revoke_where(tenant_id, now, |row| row.family == *family);
        Ok(())
    }

    async fn revoke_session(
        &self,
        tenant_id: &ScopedTenant,
        session: &SessionId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.revoke_where(tenant_id, now, |row| {
            row.granted_in.session() == Some(session)
        });
        Ok(())
    }

    async fn revoke_grant(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.revoke_where(tenant_id, now, |row| {
            row.user_id == *person && row.client_id == *client
        });
        Ok(())
    }
}

/// When `used` stopped working, as storage revokes its family at: the time
/// it was rotated, or when it was issued if it never ended.
fn rotated_at(used: &OAuthRefreshToken<ResolvedTenant>) -> OffsetDateTime {
    match used.state() {
        RefreshState::Rotated { at } | RefreshState::Revoked { at } => at,
        RefreshState::Active => used.to_row().issued_at,
    }
}

impl Fake for Arc<dyn RefreshTokenStore> {
    fn fake() -> Self {
        Arc::new(FakeRefreshTokenStore::empty())
    }
}
