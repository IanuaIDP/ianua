//! Fakes for the operator ports: in-memory stores for operators, their
//! impersonation grants and their keys, a checker that says whether a
//! tenant user exists, and the operator callers tests act as.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::operator::api_key::{OperatorApiKey, OperatorApiKeyRow};
use ianua_domain::domains::operator::identity::{Operator, OperatorRow};
use ianua_domain::domains::operator::impersonation::{ImpersonationGrant, ImpersonationGrantRow};
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    Email, Expiry, ImpersonationGrantId, KeyPrefix, OperatorId, PasswordHash, Revocation, TenantId,
    Text, TokenHash, UserId,
};
use time::OffsetDateTime;

use crate::context::{CallerContext, CallerIdentity, Credential, OperatorCaller};
use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::operator::{
    ImpersonationGrantStore, OperatorFilter, OperatorKeyStore, OperatorSortField, OperatorStore,
};
use crate::test_support::listing::page;
use crate::test_support::{Fake, test_ctx};

/// In-memory operator store that keeps every operator it is handed.
#[derive(Default)]
pub struct FakeOperatorStore {
    operators: Mutex<Vec<Operator>>,
}

impl FakeOperatorStore {
    /// A store holding no operator.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `operators`.
    #[must_use]
    pub fn holding(operators: impl IntoIterator<Item = Operator>) -> Self {
        let store = Self::default();
        store.operators.lock().unwrap().extend(operators);
        store
    }

    /// How many operators are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.operators.lock().unwrap().len()
    }

    fn first(&self, matches: impl Fn(&Operator) -> bool) -> Result<Option<Operator>, DomainError> {
        self.operators
            .lock()
            .unwrap()
            .iter()
            .find(|operator| matches(operator))
            .map(copy_operator)
            .transpose()
    }
}

#[async_trait]
impl OperatorStore for FakeOperatorStore {
    async fn find_by_id(&self, id: &OperatorId) -> Result<Option<Operator>, DomainError> {
        self.first(|operator| operator.id() == id)
    }

    async fn find_by_email(&self, email: &Email) -> Result<Option<Operator>, DomainError> {
        self.first(|operator| operator.email() == email)
    }

    async fn list(
        &self,
        filter: &OperatorFilter,
        sort: &SortOrder<OperatorSortField>,
        request: &PageRequest,
    ) -> Result<Page<Operator>, DomainError> {
        let kept = self
            .operators
            .lock()
            .unwrap()
            .iter()
            .filter(|operator| filter.admits(operator))
            .map(copy_operator)
            .collect::<Result<Vec<_>, _>>()?;
        page(kept, sort, request)
    }

    async fn any_exists(&self) -> Result<bool, DomainError> {
        Ok(!self.operators.lock().unwrap().is_empty())
    }

    async fn save(&self, operator: &Operator) -> Result<(), DomainError> {
        let copy = copy_operator(operator)?;
        let mut operators = self.operators.lock().unwrap();
        let taken = operators
            .iter()
            .any(|held| held.email() == operator.email() && held.id() != operator.id());
        if taken {
            return Err(DomainError::conflict(
                "another operator signs in with this address",
            ));
        }
        match operators.iter_mut().find(|held| held.id() == operator.id()) {
            Some(held) => *held = copy,
            None => operators.push(copy),
        }
        Ok(())
    }
}

/// A copy of `operator`, read back the way storage reads it.
fn copy_operator(operator: &Operator) -> Result<Operator, DomainError> {
    Operator::reconstitute(OperatorRow {
        id: *operator.id(),
        email: operator.email().clone(),
        password_hash: operator.password_hash().clone(),
        status: operator.status(),
        created_at: operator.created_at(),
    })
}

/// In-memory impersonation grant store that keeps every grant it is handed.
#[derive(Default)]
pub struct FakeGrantStore {
    grants: Mutex<Vec<ImpersonationGrant>>,
}

impl FakeGrantStore {
    /// A store holding no grant.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `grants`.
    #[must_use]
    pub fn holding(grants: impl IntoIterator<Item = ImpersonationGrant>) -> Self {
        let store = Self::default();
        store.grants.lock().unwrap().extend(grants);
        store
    }

    /// How many grants are held, revoked ones included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.grants.lock().unwrap().len()
    }

    /// How many held grants were revoked.
    #[must_use]
    pub fn revoked(&self) -> usize {
        self.grants
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| grant.is_revoked())
            .count()
    }
}

#[async_trait]
impl ImpersonationGrantStore for FakeGrantStore {
    async fn find_by_id(
        &self,
        id: &ImpersonationGrantId,
    ) -> Result<Option<ImpersonationGrant>, DomainError> {
        self.grants
            .lock()
            .unwrap()
            .iter()
            .find(|grant| grant.id() == id)
            .map(|grant| copy_grant(grant, grant_revocation(grant)))
            .transpose()
    }

    async fn find_active(
        &self,
        operator_id: &OperatorId,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<ImpersonationGrant>, DomainError> {
        let now = clock::now();
        self.grants
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| !grant.is_revoked() && now < grant.expires_at())
            .find(|grant| {
                grant.operator_id() == operator_id
                    && grant.tenant_id() == tenant_id
                    && grant.user_id() == user_id
            })
            .map(|grant| copy_grant(grant, Revocation::InForce))
            .transpose()
    }

    async fn save(&self, grant: &ImpersonationGrant) -> Result<(), DomainError> {
        let copy = copy_grant(grant, grant_revocation(grant))?;
        let mut grants = self.grants.lock().unwrap();
        match grants.iter_mut().find(|held| held.id() == grant.id()) {
            Some(held) => *held = copy,
            None => grants.push(copy),
        }
        Ok(())
    }

    async fn revoke_all_for_operator(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        let revoked_now = Revocation::Revoked { at: clock::now() };
        let mut grants = self.grants.lock().unwrap();
        let mut count = 0;
        for grant in grants
            .iter_mut()
            .filter(|grant| grant.operator_id() == operator_id && !grant.is_revoked())
        {
            *grant = copy_grant(grant, revoked_now)?;
            count += 1;
        }
        Ok(count)
    }
}

/// Whether `grant` was revoked, and when, as storage keeps it.
fn grant_revocation(grant: &ImpersonationGrant) -> Revocation {
    Revocation::from_stored(grant.revoked_at())
}

/// A copy of `grant` standing as `revocation` says, read back the way
/// storage reads it.
fn copy_grant(
    grant: &ImpersonationGrant,
    revocation: Revocation,
) -> Result<ImpersonationGrant, DomainError> {
    ImpersonationGrant::reconstitute(ImpersonationGrantRow {
        id: *grant.id(),
        operator_id: *grant.operator_id(),
        tenant_id: *grant.tenant_id(),
        user_id: *grant.user_id(),
        reason: grant.reason().clone(),
        expires_at: grant.expires_at(),
        revocation,
        created_at: grant.created_at(),
    })
}

/// In-memory operator key store that keeps every key it is handed.
#[derive(Default)]
pub struct FakeOperatorKeyStore {
    keys: Mutex<Vec<OperatorApiKey>>,
    revoked_meanwhile: Mutex<Option<KeyPrefix>>,
}

impl FakeOperatorKeyStore {
    /// A store holding no key.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `keys`.
    #[must_use]
    pub fn holding(keys: impl IntoIterator<Item = OperatorApiKey>) -> Self {
        let store = Self::default();
        store.keys.lock().unwrap().extend(keys);
        store
    }

    /// A store holding `keys`, where the key `prefix` is revoked by another
    /// request just before the first revocation of several keys together.
    #[must_use]
    pub fn revoking_meanwhile(
        keys: impl IntoIterator<Item = OperatorApiKey>,
        prefix: &str,
    ) -> Self {
        let store = Self::holding(keys);
        *store.revoked_meanwhile.lock().unwrap() =
            Some(KeyPrefix::new(prefix).expect("a valid key prefix"));
        store
    }

    /// Revokes the key another request revokes meanwhile, when there is one.
    fn other_request_revokes(&self, keys: &mut [OperatorApiKey]) -> Result<(), DomainError> {
        let Some(prefix) = self.revoked_meanwhile.lock().unwrap().take() else {
            return Ok(());
        };
        for held in keys.iter_mut().filter(|held| *held.key_prefix() == prefix) {
            *held = revoked_copy(held, clock::now())?;
        }
        Ok(())
    }

    /// How many keys are held, revoked ones included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

#[async_trait]
impl OperatorKeyStore for FakeOperatorKeyStore {
    async fn find_by_prefix(
        &self,
        prefix: &KeyPrefix,
    ) -> Result<Option<OperatorApiKey>, DomainError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .find(|key| key.key_prefix() == prefix)
            .cloned())
    }

    async fn list_by_operator(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Vec<OperatorApiKey>, DomainError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .filter(|key| key.operator_id() == operator_id)
            .cloned()
            .collect())
    }

    async fn save(&self, key: &OperatorApiKey) -> Result<(), DomainError> {
        let mut keys = self.keys.lock().unwrap();
        match keys
            .iter_mut()
            .find(|held| held.key_prefix() == key.key_prefix())
        {
            Some(held) => *held = key.clone(),
            None => keys.push(key.clone()),
        }
        Ok(())
    }

    async fn revoke_together(
        &self,
        operator_id: &OperatorId,
        keys: &[OperatorApiKey],
    ) -> Result<(), DomainError> {
        if keys.iter().any(|key| !key.revocation().is_revoked()) {
            return Err(DomainError::invalid("only keys just revoked are written"));
        }
        let mut held = self.keys.lock().unwrap();
        self.other_request_revokes(&mut held)?;
        let all_live = keys.iter().all(|key| {
            held.iter().any(|stored| {
                stored.key_prefix() == key.key_prefix()
                    && stored.operator_id() == operator_id
                    && !stored.revocation().is_revoked()
            })
        });
        if !all_live {
            return Err(DomainError::conflict(
                "a key was revoked meanwhile, or is another operator's",
            ));
        }
        for key in keys {
            held.retain(|stored| stored.key_prefix() != key.key_prefix());
            held.push(key.clone());
        }
        Ok(())
    }
}

/// `key` as storage holds it once revoked at `at`.
fn revoked_copy(key: &OperatorApiKey, at: OffsetDateTime) -> Result<OperatorApiKey, DomainError> {
    OperatorApiKey::reconstitute(OperatorApiKeyRow {
        operator_id: *key.operator_id(),
        key_prefix: key.key_prefix().clone(),
        key_hash: key.key_hash().clone(),
        expires_at: key.expires_at(),
        revocation: Revocation::Revoked { at },
        created_at: key.created_at(),
    })
}

/// The key prefix every test operator signs in with.
const OPERATOR_KEY: &str = "opk_abcd1234";

/// The operator every [`test_operator_caller`] is.
const TEST_OPERATOR: uuid::Uuid = uuid::uuid!("019f0000-0000-7000-8000-00000000090b");

/// The operator a test acts as on the platform.
#[must_use]
pub fn test_operator_id() -> OperatorId {
    OperatorId::from_uuid(TEST_OPERATOR)
}

/// The test operator on the platform, signed in with their own key.
#[must_use]
pub fn test_operator_caller() -> OperatorCaller {
    OperatorCaller::new(test_operator_id(), operator_key())
}

/// An operator calling a tenant endpoint of the test tenant with their own
/// key and no impersonation grant.
#[must_use]
pub fn operator_without_grant() -> CallerContext {
    let tenant = test_ctx();
    CallerContext::new(
        CallerIdentity::Operator(test_operator_id()),
        Credential::OperatorKey(operator_key()),
        tenant.organization_id(),
        tenant.tenant_id(),
        tenant.plan_limits().clone(),
    )
    .expect("an operator key fits an operator")
}

/// The prefix of the test operator's own key.
#[must_use]
pub fn operator_key() -> KeyPrefix {
    KeyPrefix::new(OPERATOR_KEY).expect("a valid key prefix")
}

/// The operator `id` as storage holds them, signing in as `email` and
/// standing as `status`.
#[must_use]
pub fn stored_operator(id: OperatorId, email: &str, status: OperatorStatus) -> Operator {
    Operator::reconstitute(OperatorRow {
        id,
        email: Email::new(email).expect("a valid address"),
        password_hash: PasswordHash::from_stored("hash".to_owned()),
        status,
        created_at: clock::now(),
    })
    .expect("a stored operator reads back")
}

/// A grant in force for an hour more, letting `operator` act as `user` in
/// `tenant`, as storage holds it.
#[must_use]
pub fn stored_grant(operator: OperatorId, tenant: TenantId, user: UserId) -> ImpersonationGrant {
    let now = clock::now();
    ImpersonationGrant::reconstitute(ImpersonationGrantRow {
        id: ImpersonationGrantId::new(),
        operator_id: operator,
        tenant_id: tenant,
        user_id: user,
        reason: Text::new("reason", "Support ticket").expect("a valid reason"),
        expires_at: now + time::Duration::hours(1),
        revocation: Revocation::InForce,
        created_at: now,
    })
    .expect("a grant in force reads back")
}

/// A working key of `owner`'s, found by `prefix`, that never ends.
#[must_use]
pub fn stored_operator_key(owner: OperatorId, prefix: &str) -> OperatorApiKey {
    OperatorApiKey::reconstitute(OperatorApiKeyRow {
        operator_id: owner,
        key_prefix: KeyPrefix::new(prefix).expect("a valid key prefix"),
        key_hash: TokenHash::from_stored(format!("hash of {prefix}")),
        expires_at: Expiry::Never,
        revocation: Revocation::InForce,
        created_at: clock::now(),
    })
    .expect("a stored operator key reads back")
}

impl Fake for Arc<dyn ImpersonationGrantStore> {
    fn fake() -> Self {
        Arc::new(FakeGrantStore::empty())
    }
}

impl Fake for Arc<dyn OperatorKeyStore> {
    fn fake() -> Self {
        Arc::new(FakeOperatorKeyStore::empty())
    }
}

impl Fake for Arc<dyn OperatorStore> {
    fn fake() -> Self {
        Arc::new(FakeOperatorStore::empty())
    }
}
