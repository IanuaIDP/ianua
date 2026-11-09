//! In-memory stores for the single-use links mailed to a user: email
//! verification, and the links that sign in or finish a sign-in.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::purpose::TenantLinkPurpose;
use ianua_domain::domains::identity::tokens::secure::{SecureToken, SecureTokenRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::fakes::FakeRefreshTokenGenerator;
use ianua_domain::types::{Email, TokenHash, Usage, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::identity::{EmailVerificationToken, SignInLinkStore, VerificationTokenStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::identity::held::{TenantRows, seeded_tenant};
use crate::test_support::{Fake, ReadBeforeWrite};

/// In-memory email verification links: keeps every link saved under its
/// tenant, and spends a user's unused links when a new one replaces them.
#[derive(Default)]
pub struct FakeTokenStore {
    tokens: TenantRows<EmailVerificationToken>,
}

impl TenantScoped for FakeTokenStore {}

impl FakeTokenStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `token` for the tenant [`test_ctx`] carries.
    ///
    /// [`test_ctx`]: crate::test_support::test_ctx
    #[must_use]
    pub fn holding(token: EmailVerificationToken) -> Self {
        let store = Self::empty();
        store.tokens.insert(seeded_tenant(), token);
        store
    }

    /// Number of stored links, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tokens.count()
    }
}

#[async_trait]
impl VerificationTokenStore for FakeTokenStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<EmailVerificationToken>, DomainError> {
        self.tokens
            .find(
                tenant_id,
                |token| token.token_hash() == token_hash,
                copy_token,
            )
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &EmailVerificationToken,
    ) -> Result<(), DomainError> {
        let kept = copy_token(token)?;
        let same = |held: &EmailVerificationToken| held.token_hash() == token.token_hash();
        self.tokens.upsert(**tenant_id, same, kept);
        Ok(())
    }

    async fn consume_outstanding(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        let outstanding =
            |token: &EmailVerificationToken| token.user_id() == user_id && is_outstanding(token);
        let mut refused = None;
        self.tokens
            .update(tenant_id, outstanding, |token| match spent_now(token) {
                Ok(spent) => *token = spent,
                Err(error) => refused = Some(error),
            });
        refused.map_or(Ok(()), Err)
    }

    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<EmailVerificationToken>, DomainError> {
        let mut theirs = self.tokens.collect(
            tenant_id,
            |token| token.user_id() == user_id,
            |token| (token.created_at(), copy_token(token)),
        );
        theirs.sort_by_key(|(created_at, _)| *created_at);
        theirs.pop().map(|(_, token)| token).transpose()
    }
}

impl Fake for Arc<dyn VerificationTokenStore> {
    fn fake() -> Self {
        Arc::new(FakeTokenStore::empty())
    }
}

/// One stored sign-in link, filed with its purpose as storage keeps it.
struct HeldLink {
    purpose: &'static str,
    row: SecureTokenRow,
}

impl HeldLink {
    fn of<P: TenantLinkPurpose>(link: &SecureToken<ResolvedTenant, P>) -> Self {
        Self {
            purpose: purpose_of::<P>(),
            row: row_of(link, Usage::from_stored(link.consumed_at())),
        }
    }

    /// Whether this is the link of purpose `P` hashing to `hash`.
    fn is<P: TenantLinkPurpose>(&self, hash: &TokenHash) -> bool {
        self.purpose == purpose_of::<P>() && self.row.token_hash == *hash
    }

    /// The link read back as a real store would.
    fn read<P: TenantLinkPurpose>(&self) -> Result<SecureToken<ResolvedTenant, P>, DomainError> {
        SecureToken::reconstitute(SecureTokenRow {
            token_hash: self.row.token_hash.clone(),
            sent_to: self.row.sent_to.clone(),
            ..self.row
        })
    }
}

/// The name a link of purpose `P` is filed under.
fn purpose_of<P: TenantLinkPurpose>() -> &'static str {
    std::any::type_name::<P>()
}

/// In-memory sign-in links of every purpose, in one table as storage keeps
/// them: each filed with its purpose under its tenant, found only by a
/// lookup for that purpose, and removed when consumed.
#[derive(Default)]
pub struct FakeSignInLinks {
    links: TenantRows<HeldLink>,
}

impl TenantScoped for FakeSignInLinks {}

impl FakeSignInLinks {
    /// Nothing held.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding `link` for the tenant [`test_ctx`] carries.
    ///
    /// [`test_ctx`]: crate::test_support::test_ctx
    #[must_use]
    pub fn holding<P: TenantLinkPurpose>(link: &SecureToken<ResolvedTenant, P>) -> Self {
        let store = Self::new();
        store.links.insert(seeded_tenant(), HeldLink::of(link));
        store
    }

    /// How many links are held, of every purpose and across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.links.count()
    }
}

#[async_trait]
impl<P: TenantLinkPurpose + Send + Sync + 'static> SignInLinkStore<P> for FakeSignInLinks {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SecureToken<ResolvedTenant, P>>, DomainError> {
        self.links
            .find(tenant_id, |held| held.is::<P>(token_hash), HeldLink::read)
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &SecureToken<ResolvedTenant, P>,
    ) -> Result<(), DomainError> {
        let same = |held: &HeldLink| held.is::<P>(token.token_hash());
        self.links.upsert(**tenant_id, same, HeldLink::of(token));
        Ok(())
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        let removed = self
            .links
            .remove(tenant_id, |held| held.is::<P>(token_hash));
        Ok(removed > 0)
    }
}

#[async_trait]
impl<P: TenantLinkPurpose + Send + Sync + 'static> SignInLinkStore<P>
    for ReadBeforeWrite<FakeSignInLinks>
{
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SecureToken<ResolvedTenant, P>>, DomainError> {
        SignInLinkStore::<P>::find_by_hash(&self.seen, tenant_id, token_hash).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &SecureToken<ResolvedTenant, P>,
    ) -> Result<(), DomainError> {
        SignInLinkStore::<P>::save(self.live.as_ref(), tenant_id, token).await
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<bool, DomainError> {
        SignInLinkStore::<P>::consume(self.live.as_ref(), tenant_id, token_hash).await
    }
}

impl<P: TenantLinkPurpose + Send + Sync + 'static> Fake for Arc<dyn SignInLinkStore<P>> {
    fn fake() -> Self {
        Arc::new(FakeSignInLinks::new())
    }
}

impl Fake for Arc<dyn RefreshTokenGenerator> {
    fn fake() -> Self {
        Arc::new(FakeRefreshTokenGenerator::new())
    }
}

/// The hash the fake token generator gives the raw token `raw`.
#[must_use]
pub fn hash_of_link(raw: &str) -> TokenHash {
    FakeRefreshTokenGenerator::new().hash_raw(raw)
}

/// An unused verification link `raw` for `user_id`, mailed to `sent_to`
/// two hours before `expires_at` or now, whichever is earlier, as storage
/// would hand it back.
///
/// # Panics
///
/// If `sent_to` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn stored_verification_link(
    raw: &str,
    user_id: UserId,
    sent_to: &str,
    expires_at: OffsetDateTime,
) -> EmailVerificationToken {
    SecureToken::reconstitute(SecureTokenRow {
        token_hash: hash_of_link(raw),
        user_id,
        sent_to: Email::new(sent_to).expect("a valid address"),
        created_at: expires_at.min(clock::now()) - time::Duration::hours(2),
        expires_at,
        usage: Usage::from_stored(None),
    })
    .expect("an unused link is a consistent row")
}

/// Whether `token` is unused and still in date, so a replacement spends it.
fn is_outstanding<P: TenantLinkPurpose>(token: &SecureToken<ResolvedTenant, P>) -> bool {
    token.consumed_at().is_none() && clock::now() < token.expires_at()
}

/// `token`, spent now.
fn spent_now<P: TenantLinkPurpose>(
    token: &SecureToken<ResolvedTenant, P>,
) -> Result<SecureToken<ResolvedTenant, P>, DomainError> {
    SecureToken::reconstitute(row_of(token, Usage::Used { at: clock::now() }))
}

/// A copy of `token`, which does not implement `Clone`, read back as a real
/// store would.
fn copy_token<P: TenantLinkPurpose>(
    token: &SecureToken<ResolvedTenant, P>,
) -> Result<SecureToken<ResolvedTenant, P>, DomainError> {
    SecureToken::reconstitute(row_of(token, Usage::from_stored(token.consumed_at())))
}

fn row_of<P: TenantLinkPurpose>(
    token: &SecureToken<ResolvedTenant, P>,
    usage: Usage,
) -> SecureTokenRow {
    SecureTokenRow {
        token_hash: token.token_hash().clone(),
        user_id: *token.user_id(),
        sent_to: token.sent_to().clone(),
        created_at: token.created_at(),
        expires_at: token.expires_at(),
        usage,
    }
}
