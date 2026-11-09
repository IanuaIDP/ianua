//! Fakes for passwords: reset requests, the history of retired hashes, and
//! a hasher that counts its work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::recovery::reset::{
    PasswordResetRequest, PasswordResetRow, ResetState, ResetStatus,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::password_policy::CommonPassword;
use ianua_domain::types::{PasswordHash, TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::ports::authentication::{
    CommonPasswordList, PasswordHashFormat, PasswordHistory, ResetRequestStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::Plane;
use crate::test_support::{Fake, ReadBeforeWrite};
use crate::use_cases::authentication::password::{ChangePolicy, ChangeUseCase};

/// In-memory password reset store: keeps each request in its tenant as it
/// was last saved, expires a user's pending links when asked, and records
/// whose links were superseded.
#[derive(Default)]
pub struct FakeResetRequestStore {
    rows: Mutex<Vec<(Plane, PasswordResetRow)>>,
    superseded: Mutex<Vec<UserId>>,
}

impl FakeResetRequestStore {
    /// No reset requests.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `request` in the test tenant.
    #[must_use]
    pub fn with_request(request: &PasswordResetRequest) -> Self {
        Self {
            rows: Mutex::new(vec![(Plane::test_tenant(), row_of(request))]),
            ..Self::default()
        }
    }

    /// How many requests are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    /// The status of the first request held, if any.
    #[must_use]
    pub fn status(&self) -> Option<ResetStatus> {
        self.rows
            .lock()
            .unwrap()
            .first()
            .map(|(_, row)| row.state.status())
    }

    /// Users whose outstanding links were superseded.
    #[must_use]
    pub fn superseded(&self) -> Vec<UserId> {
        self.superseded.lock().unwrap().clone()
    }

    /// Backdates every held request, as waiting out the cooldown would.
    pub fn age_by(&self, elapsed: time::Duration) {
        for (_, row) in self.rows.lock().unwrap().iter_mut() {
            row.created_at -= elapsed;
        }
    }

    fn find(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&PasswordResetRow) -> bool,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        let plane = Plane::of(tenant_id);
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_on, row)| *held_on == plane && matches(row))
            .max_by_key(|(_, row)| row.created_at)
            .map(|(_, row)| PasswordResetRequest::reconstitute(copy_row(row)))
            .transpose()
    }
}

/// The stored row of `request`.
fn row_of(request: &PasswordResetRequest) -> PasswordResetRow {
    PasswordResetRow {
        id: *request.id(),
        user_id: *request.user_id(),
        email: request.email().clone(),
        initiator: request.initiator(),
        state: request.reset_state(),
        token_hash: request.token_hash().clone(),
        created_at: request.created_at(),
        expires_at: request.expires_at(),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &PasswordResetRow) -> PasswordResetRow {
    PasswordResetRow {
        id: row.id,
        user_id: row.user_id,
        email: row.email.clone(),
        initiator: row.initiator,
        state: row.state,
        token_hash: row.token_hash.clone(),
        created_at: row.created_at,
        expires_at: row.expires_at,
    }
}

impl TenantScoped for FakeResetRequestStore {}

#[async_trait]
impl ResetRequestStore for FakeResetRequestStore {
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        self.find(tenant_id, |row| &row.token_hash == hash)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<(), DomainError> {
        let plane = Plane::of(tenant_id);
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|(held_on, row)| !(*held_on == plane && row.id == *request.id()));
        rows.push((plane, row_of(request)));
        Ok(())
    }

    async fn complete(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<bool, DomainError> {
        let plane = Plane::of(tenant_id);
        let mut rows = self.rows.lock().unwrap();
        let Some((_, stored)) = rows.iter_mut().find(|(held_on, row)| {
            *held_on == plane && row.id == *request.id() && row.state == ResetState::Pending
        }) else {
            return Ok(false);
        };
        *stored = row_of(request);
        Ok(true)
    }

    async fn expire_pending_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        let plane = Plane::of(tenant_id);
        let mut rows = self.rows.lock().unwrap();
        let pending = rows.iter_mut().filter(|(held_on, row)| {
            *held_on == plane && row.user_id == *user_id && row.state == ResetState::Pending
        });
        for (_, row) in pending {
            row.state = ResetState::Expired;
        }
        self.superseded.lock().unwrap().push(*user_id);
        Ok(())
    }

    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        self.find(tenant_id, |row| row.user_id == *user_id)
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasswordResetRequest>, DomainError> {
        let plane = Plane::of(tenant_id);
        let mut held: Vec<PasswordResetRequest> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_on, row)| *held_on == plane && row.user_id == *user_id)
            .map(|(_, row)| PasswordResetRequest::reconstitute(copy_row(row)))
            .collect::<Result<_, _>>()?;
        held.sort_by_key(|request| std::cmp::Reverse(request.created_at()));
        Ok(held)
    }
}

#[async_trait]
impl ResetRequestStore for ReadBeforeWrite<FakeResetRequestStore> {
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        self.seen.find_by_token_hash(tenant_id, hash).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<(), DomainError> {
        self.live.save(tenant_id, request).await
    }

    async fn complete(
        &self,
        tenant_id: &ScopedTenant,
        request: &PasswordResetRequest,
    ) -> Result<bool, DomainError> {
        self.live.complete(tenant_id, request).await
    }

    async fn expire_pending_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        self.live.expire_pending_for_user(tenant_id, user_id).await
    }

    async fn find_latest_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<PasswordResetRequest>, DomainError> {
        self.seen.find_latest_by_user(tenant_id, user_id).await
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<PasswordResetRequest>, DomainError> {
        self.seen.list_by_user(tenant_id, user_id).await
    }
}

/// In-memory record of each user's retired password hashes, kept in their
/// tenant, oldest first.
#[derive(Default)]
pub struct FakePasswordHistory {
    entries: Mutex<Vec<(Plane, UserId, PasswordHash)>>,
}

impl FakePasswordHistory {
    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A history holding `hash` as a retired password of `user_id`, in the
    /// test tenant.
    #[must_use]
    pub fn with_entry(user_id: UserId, hash: PasswordHash) -> Self {
        Self {
            entries: Mutex::new(vec![(Plane::test_tenant(), user_id, hash)]),
        }
    }

    /// How many hashes are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Every retired hash held, oldest first, as storage writes it.
    #[must_use]
    pub fn retired(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(_, _, hash)| hash.as_str().to_owned())
            .collect()
    }
}

impl TenantScoped for FakePasswordHistory {}

#[async_trait]
impl PasswordHistory for FakePasswordHistory {
    async fn recent(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        count: u32,
    ) -> Result<Vec<PasswordHash>, DomainError> {
        let plane = Plane::of(tenant_id);
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .rev()
            .filter(|(held_on, who, _)| *held_on == plane && who == user_id)
            .take(usize::try_from(count).unwrap_or(usize::MAX))
            .map(|(_, _, hash)| hash.clone())
            .collect())
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        hash: &PasswordHash,
    ) -> Result<(), DomainError> {
        self.entries
            .lock()
            .unwrap()
            .push((Plane::of(tenant_id), *user_id, hash.clone()));
        Ok(())
    }
}

/// Hashes as [`FakeHasher`] does and counts every hash it makes, so a test
/// can show that a refusal did as much work as a real check.
#[derive(Default)]
pub struct CountingHasher {
    hashes: AtomicUsize,
}

impl CountingHasher {
    /// How many passwords it hashed.
    #[must_use]
    pub fn hashed(&self) -> usize {
        self.hashes.load(Ordering::Relaxed)
    }
}

impl PasswordHasher for CountingHasher {
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        self.hashes.fetch_add(1, Ordering::Relaxed);
        FakeHasher.hash(raw_password)
    }

    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        self.hashes.fetch_add(1, Ordering::Relaxed);
        FakeHasher.verify(raw_password, hash)
    }
}

/// A list of common passwords holding only the words it was given.
#[derive(Default)]
pub struct FakeCommonPasswords {
    listed: Vec<&'static str>,
}

impl FakeCommonPasswords {
    /// A list holding `listed`.
    #[must_use]
    pub fn holding(listed: &[&'static str]) -> Self {
        Self {
            listed: listed.to_vec(),
        }
    }
}

impl CommonPasswordList for FakeCommonPasswords {
    fn verdict(&self, password: &Secret) -> CommonPassword {
        CommonPassword::among(password.expose(), &self.listed)
    }
}

impl Fake for Arc<dyn CommonPasswordList> {
    fn fake() -> Self {
        Arc::new(FakeCommonPasswords::default())
    }
}

/// Takes every hash as in the platform's own format: nothing is rehashed.
pub struct HouseHashFormat;

impl PasswordHashFormat for HouseHashFormat {
    fn needs_rehash(&self, _hash: &PasswordHash) -> bool {
        false
    }
}

/// Takes every hash as another system's, so each one proved is rehashed.
pub struct ForeignHashFormat;

impl PasswordHashFormat for ForeignHashFormat {
    fn needs_rehash(&self, _hash: &PasswordHash) -> bool {
        true
    }
}

impl Fake for Arc<dyn PasswordHashFormat> {
    fn fake() -> Self {
        Arc::new(HouseHashFormat)
    }
}

impl Fake for Arc<dyn ResetRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeResetRequestStore::empty())
    }
}

impl Fake for Arc<dyn PasswordHistory> {
    fn fake() -> Self {
        Arc::new(FakePasswordHistory::empty())
    }
}

/// A password change over its neutral ports that lets a password change at
/// any time and checks no history.
impl Fake for Arc<ChangeUseCase> {
    fn fake() -> Self {
        let policy = ChangePolicy {
            history_check_count: 0,
            min_age_seconds: 0,
        };
        Arc::new(ChangeUseCase::new(policy, Fake::fake()))
    }
}
