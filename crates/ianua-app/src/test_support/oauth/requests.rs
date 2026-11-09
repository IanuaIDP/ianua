//! Fakes for what waits to be used once: pushed authorization requests and
//! initial access tokens.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::registration::{
    InitialAccessToken, InitialAccessTokenRow,
};
use ianua_domain::domains::oauth::grants::pushed_request::{
    PushedParameters, PushedRequest, PushedRequestRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    InitialAccessTokenId, Label, OAuthClientId, PushedRequestId, Revocation, TenantId, TokenHash,
    Usage,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::oauth::{InitialAccessTokenStore, PushedRequestStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// A pushed request as the fake keeps it.
struct KeptRequest {
    tenant: TenantId,
    id: PushedRequestId,
    client_id: OAuthClientId,
    parameters: PushedParameters,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
}

impl KeptRequest {
    /// The request read back, as storage would return it.
    fn read(&self) -> Result<PushedRequest<ResolvedTenant>, DomainError> {
        PushedRequest::reconstitute(PushedRequestRow {
            id: self.id,
            client_id: self.client_id,
            parameters: self.parameters.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: self.usage,
        })
    }
}

/// In-memory store of pushed authorization requests.
#[derive(Default)]
pub struct FakePushedRequestStore {
    kept: Mutex<Vec<KeptRequest>>,
}

impl TenantScoped for FakePushedRequestStore {}

impl FakePushedRequestStore {
    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many requests are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.kept.lock().unwrap().len()
    }

    /// Whether the request `id` was used.
    #[must_use]
    pub fn is_used(&self, id: &PushedRequestId) -> bool {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .any(|kept| kept.id == *id && kept.usage.is_used())
    }
}

#[async_trait]
impl PushedRequestStore for FakePushedRequestStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PushedRequestId,
    ) -> Result<Option<PushedRequest<ResolvedTenant>>, DomainError> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .find(|kept| kept.tenant == **tenant_id && kept.id == *id)
            .map(KeptRequest::read)
            .transpose()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.kept.lock().unwrap().push(KeptRequest {
            tenant: **tenant_id,
            id: *request.id(),
            client_id: *request.client_id(),
            parameters: request.parameters().clone(),
            created_at: request.created_at(),
            expires_at: request.expires_at(),
            usage: request.usage(),
        });
        Ok(())
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        request: &PushedRequest<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let Some(stored) = kept
            .iter_mut()
            .find(|kept| kept.tenant == **tenant_id && kept.id == *request.id())
        else {
            return Ok(false);
        };
        if stored.usage.is_used() {
            return Ok(false);
        }
        stored.usage = request.usage();
        Ok(true)
    }
}

impl Fake for Arc<dyn PushedRequestStore> {
    fn fake() -> Self {
        Arc::new(FakePushedRequestStore::empty())
    }
}

/// An initial access token as the fake keeps it.
struct KeptToken {
    tenant: TenantId,
    id: InitialAccessTokenId,
    name: Label,
    token_hash: TokenHash,
    uses_left: u32,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: Revocation,
}

impl KeptToken {
    /// `token` as the fake keeps it in `tenant`.
    fn of(tenant: TenantId, token: &InitialAccessToken<ResolvedTenant>) -> Self {
        Self {
            tenant,
            id: *token.id(),
            name: token.name().clone(),
            token_hash: token.token_hash().clone(),
            uses_left: token.uses_left(),
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            revocation: token.revocation(),
        }
    }

    /// The token read back, as storage would return it.
    fn read(&self) -> Result<InitialAccessToken<ResolvedTenant>, DomainError> {
        InitialAccessToken::reconstitute(InitialAccessTokenRow {
            id: self.id,
            name: self.name.clone(),
            token_hash: self.token_hash.clone(),
            uses_left: self.uses_left,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revocation: self.revocation,
        })
    }
}

/// In-memory store of initial access tokens.
#[derive(Default)]
pub struct FakeInitialAccessTokenStore {
    kept: Mutex<Vec<KeptToken>>,
}

impl TenantScoped for FakeInitialAccessTokenStore {}

impl FakeInitialAccessTokenStore {
    /// A store holding no token.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many tokens are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.kept.lock().unwrap().len()
    }

    /// How many uses the token `id` has left.
    #[must_use]
    pub fn uses_left(&self, id: &InitialAccessTokenId) -> Option<u32> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .find(|kept| kept.id == *id)
            .map(|kept| kept.uses_left)
    }

    /// The first kept token of `tenant` that `matches`, read back.
    fn first(
        &self,
        tenant: &ScopedTenant,
        matches: impl Fn(&KeptToken) -> bool,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .find(|kept| kept.tenant == **tenant && matches(kept))
            .map(KeptToken::read)
            .transpose()
    }
}

#[async_trait]
impl InitialAccessTokenStore for FakeInitialAccessTokenStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError> {
        self.first(tenant_id, |kept| kept.id == *id)
    }

    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<InitialAccessToken<ResolvedTenant>>, DomainError> {
        self.first(tenant_id, |kept| kept.token_hash == *token_hash)
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<InitialAccessToken<ResolvedTenant>>, DomainError> {
        self.kept
            .lock()
            .unwrap()
            .iter()
            .rev()
            .filter(|kept| kept.tenant == **tenant_id)
            .map(KeptToken::read)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut kept = self.kept.lock().unwrap();
        kept.retain(|kept| !(kept.tenant == **tenant_id && kept.id == *token.id()));
        kept.push(KeptToken::of(**tenant_id, token));
        Ok(())
    }

    async fn spend_use(
        &self,
        tenant_id: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let mut kept = self.kept.lock().unwrap();
        let Some(stored) = kept
            .iter_mut()
            .find(|kept| kept.tenant == **tenant_id && kept.id == *token.id())
        else {
            return Ok(false);
        };
        let one_more = stored.uses_left == token.uses_left().saturating_add(1);
        if !one_more || stored.revocation.is_revoked() {
            return Ok(false);
        }
        stored.uses_left = token.uses_left();
        Ok(true)
    }
}

impl Fake for Arc<dyn InitialAccessTokenStore> {
    fn fake() -> Self {
        Arc::new(FakeInitialAccessTokenStore::empty())
    }
}
