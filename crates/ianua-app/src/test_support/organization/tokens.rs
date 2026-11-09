//! In-memory single-use links mailed to members, and the API keys members
//! make for their organization.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::organization::access::api_key::{
    MintedThrough, OrgApiKey, OrgApiKeyRow, OrgApiKeyStatus,
};
use ianua_domain::domains::organization::access::token::{OrgToken, OrgTokenRow};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::fakes::FakeRefreshTokenGenerator;
use ianua_domain::types::{
    Expiry, KeyPrefix, Label, OrgApiKeyId, OrgUserId, OrganizationId, Scope, TokenHash, Usage,
};
use time::{Duration, OffsetDateTime};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::organization::{OrgApiKeySortField, OrgApiKeyStore, OrgTokenStore};
use crate::test_support::Fake;
use crate::test_support::identity::verification_policy;
use crate::test_support::listing::page;
use crate::use_cases::identity::email::VerificationPolicy;

/// A copy of `token` used as `usage` says, read back the way storage reads
/// it.
fn copy_token<Purpose: TokenPurpose>(
    token: &OrgToken<Purpose>,
    usage: Usage,
) -> Result<OrgToken<Purpose>, DomainError> {
    OrgToken::reconstitute(OrgTokenRow {
        token_hash: token.token_hash().clone(),
        org_user_id: *token.org_user_id(),
        sent_to: token.sent_to().clone(),
        created_at: token.created_at(),
        expires_at: token.expires_at(),
        usage,
    })
}

/// A copy of `token` as it stands.
fn copy_as_stored<Purpose: TokenPurpose>(
    token: &OrgToken<Purpose>,
) -> Result<OrgToken<Purpose>, DomainError> {
    copy_token(token, Usage::from_stored(token.consumed_at()))
}

/// Whether `token` could still be followed at `now`.
fn is_outstanding<Purpose: TokenPurpose>(token: &OrgToken<Purpose>, now: OffsetDateTime) -> bool {
    token.consumed_at().is_none() && now < token.expires_at()
}

/// In-memory store for the single-use links of one `Purpose`, keeping every
/// token it is handed.
pub struct FakeOrgTokenStore<Purpose: TokenPurpose> {
    tokens: Mutex<Vec<OrgToken<Purpose>>>,
    rival_spends: AtomicBool,
}

impl<Purpose: TokenPurpose> FakeOrgTokenStore<Purpose> {
    /// A store holding no token.
    #[must_use]
    pub fn empty() -> Self {
        Self::holding([])
    }

    /// A store already holding `tokens`.
    #[must_use]
    pub fn holding(tokens: impl IntoIterator<Item = OrgToken<Purpose>>) -> Self {
        Self {
            tokens: Mutex::new(tokens.into_iter().collect()),
            rival_spends: AtomicBool::new(false),
        }
    }

    /// A store holding `tokens`, where another request following the same
    /// link spends it just before the first spend asked of the store.
    #[must_use]
    pub fn raced(tokens: impl IntoIterator<Item = OrgToken<Purpose>>) -> Self {
        Self {
            rival_spends: AtomicBool::new(true),
            ..Self::holding(tokens)
        }
    }

    /// How many tokens are held, spent ones included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tokens.lock().unwrap().len()
    }
}

impl<Purpose: TokenPurpose> Default for FakeOrgTokenStore<Purpose> {
    fn default() -> Self {
        Self::empty()
    }
}

#[async_trait]
impl<Purpose: TokenPurpose + Send + Sync + 'static> OrgTokenStore<Purpose>
    for FakeOrgTokenStore<Purpose>
{
    async fn find_by_hash(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError> {
        self.tokens
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.token_hash() == hash)
            .map(copy_as_stored)
            .transpose()
    }

    async fn save(&self, token: &OrgToken<Purpose>) -> Result<(), DomainError> {
        let copy = copy_as_stored(token)?;
        let mut tokens = self.tokens.lock().unwrap();
        let Some(held) = tokens
            .iter_mut()
            .find(|held| held.token_hash() == token.token_hash())
        else {
            tokens.push(copy);
            return Ok(());
        };
        if held.consumed_at().is_some() {
            return Err(DomainError::conflict("the link was used already"));
        }
        *held = copy;
        Ok(())
    }

    async fn spend(&self, token: &OrgToken<Purpose>) -> Result<bool, DomainError> {
        let Some(used_at) = token.consumed_at() else {
            return Err(DomainError::invalid("only a link just used is spent"));
        };
        let mut tokens = self.tokens.lock().unwrap();
        let Some(held) = tokens
            .iter_mut()
            .find(|held| held.token_hash() == token.token_hash() && held.consumed_at().is_none())
        else {
            return Ok(false);
        };
        *held = copy_token(held, Usage::Used { at: used_at })?;
        Ok(!self.rival_spends.swap(false, Ordering::SeqCst))
    }

    async fn consume_outstanding(&self, org_user_id: &OrgUserId) -> Result<(), DomainError> {
        let now = clock::now();
        let mut tokens = self.tokens.lock().unwrap();
        for held in tokens
            .iter_mut()
            .filter(|held| held.org_user_id() == org_user_id && is_outstanding(held, now))
        {
            *held = copy_token(held, Usage::Used { at: now })?;
        }
        Ok(())
    }

    async fn find_latest_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Option<OrgToken<Purpose>>, DomainError> {
        self.tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.org_user_id() == org_user_id)
            .max_by_key(|held| held.created_at())
            .map(copy_as_stored)
            .transpose()
    }
}

/// An unused link `raw` for `member`, mailed to the address they have now,
/// issued an hour before `expires_at` or now, whichever is earlier, as
/// storage would hand it back. Its hash is the one the fake token generator
/// gives `raw`.
///
/// # Panics
///
/// Never in practice: the token's fields are consistent.
#[must_use]
pub fn stored_org_token<Purpose: TokenPurpose>(
    member: &OrgUser,
    raw: &str,
    expires_at: OffsetDateTime,
) -> OrgToken<Purpose> {
    OrgToken::reconstitute(OrgTokenRow {
        token_hash: FakeRefreshTokenGenerator::new().hash_raw(raw),
        org_user_id: *member.id(),
        sent_to: member.email().clone(),
        created_at: expires_at.min(clock::now()) - Duration::hours(1),
        expires_at,
        usage: Usage::Unused,
    })
    .expect("an unused token is a consistent row")
}

impl Fake for VerificationPolicy {
    fn fake() -> Self {
        verification_policy()
    }
}

/// An active key of `created_by` in `organization_id`, named `name` and
/// carrying `org:tenants:view`, minted through `minted_through`, as storage
/// holds it.
///
/// # Panics
///
/// Never in practice: the key's fields are fixed and valid.
#[must_use]
pub fn stored_org_api_key(
    organization_id: OrganizationId,
    created_by: OrgUserId,
    name: &str,
    minted_through: MintedThrough,
) -> OrgApiKey {
    OrgApiKey::reconstitute(OrgApiKeyRow {
        id: OrgApiKeyId::new(),
        organization_id,
        name: Label::new("api_key_name", name).expect("a valid name"),
        key_prefix: KeyPrefix::new(format!("oak_acme_{name}")).expect("a valid prefix"),
        key_hash: TokenHash::from_stored(format!("hash_{name}")),
        scopes: vec![Scope::new("org:tenants:view").expect("a valid scope")],
        created_by,
        minted_through,
        expires_at: Expiry::Never,
        last_used_at: None,
        status: OrgApiKeyStatus::Active,
        created_at: clock::now(),
    })
    .expect("an active key is a consistent row")
}

/// In-memory store that keeps every API key members make.
#[derive(Default)]
pub struct FakeOrgApiKeyStore {
    keys: Mutex<Vec<OrgApiKey>>,
}

impl FakeOrgApiKeyStore {
    /// A store holding no key.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `keys`.
    #[must_use]
    pub fn holding(keys: impl IntoIterator<Item = OrgApiKey>) -> Self {
        Self {
            keys: Mutex::new(keys.into_iter().collect()),
        }
    }

    /// How many keys are held, revoked ones included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    /// The key `id` as last saved.
    #[must_use]
    pub fn stored(&self, id: &OrgApiKeyId) -> Option<OrgApiKey> {
        self.keys
            .lock()
            .unwrap()
            .iter()
            .find(|key| key.id() == id)
            .cloned()
    }
}

#[async_trait]
impl OrgApiKeyStore for FakeOrgApiKeyStore {
    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgApiKeySortField>,
        request: &PageRequest,
    ) -> Result<Page<OrgApiKey>, DomainError> {
        let keys: Vec<OrgApiKey> = self
            .keys
            .lock()
            .unwrap()
            .iter()
            .filter(|key| key.organization_id() == organization_id)
            .cloned()
            .collect();
        page(keys, sort, request)
    }

    async fn list_minted_through(
        &self,
        organization_id: &OrganizationId,
        parent: &OrgApiKeyId,
    ) -> Result<Vec<OrgApiKey>, DomainError> {
        let keys = self.keys.lock().unwrap();
        let mut parents = vec![*parent];
        let mut found: Vec<OrgApiKey> = Vec::new();
        while let Some(parent) = parents.pop() {
            let children = keys.iter().filter(|key| {
                key.organization_id() == organization_id
                    && key.minted_through() == MintedThrough::Key(parent)
            });
            for child in children {
                parents.push(*child.id());
                found.push(child.clone());
            }
        }
        Ok(found)
    }

    async fn find_by_id(&self, id: &OrgApiKeyId) -> Result<Option<OrgApiKey>, DomainError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .find(|key| key.id() == id)
            .cloned())
    }

    async fn save(&self, key: &OrgApiKey) -> Result<(), DomainError> {
        let mut keys = self.keys.lock().unwrap();
        match keys.iter_mut().find(|held| held.id() == key.id()) {
            Some(held) => *held = key.clone(),
            None => keys.push(key.clone()),
        }
        Ok(())
    }
}

impl Fake for Arc<dyn OrgApiKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgApiKeyStore::empty())
    }
}

impl<Purpose: TokenPurpose + Send + Sync + 'static> Fake for Arc<dyn OrgTokenStore<Purpose>> {
    fn fake() -> Self {
        Arc::new(FakeOrgTokenStore::<Purpose>::empty())
    }
}
