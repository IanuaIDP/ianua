//! Assertion keys: the stores of the assertion key ports in
//! `ports/crypto.rs`, sharing one mapping.
//!
//! A tenant's assertion keys are tenant rows, under row-level security. The
//! private half is sealed by the platform's secret sealer for its row
//! before it is written; the database never holds it in clear.
//!
//! The app's role keeps the keys through [`PgAssertionKeyStore`], which
//! reads the public half and the standing alone and seals each new key as
//! it writes it. The gateway's role reads them through
//! [`PgAssertionSigningKeys`], which opens the private half of the one key
//! that signs and nothing else. The gateway's role may read the table and
//! may not write it, so a gateway broken into can neither plant a key nor
//! retire one.
//!
//! The sweeps read every tenant's keys: those of the tenants in the
//! platform database in one query, as platform work, and each tenant with
//! a database of its own from that database, all at once.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::crypto::{AssertionKeyStore, AssertionSigningKeys, CrossTenantAssertionKeys};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::assertion_key::{
    AssertionKey, AssertionKeySet, AssertionSigningKey, PrivateHalf,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SealedSecret, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{
    AddedColumns, AssertionKeyRecord, SealedAssertionKeyRecord, StandingColumns, is_new,
};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Where `tenant`'s assertion key `kid` keeps its private half sealed.
fn key_place(tenant: &ScopedTenant, kid: &str) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::AssertionKey, kid)
}

/// The Postgres store of assertion keys, for the app's role.
pub struct PgAssertionKeyStore {
    databases: Arc<Databases>,
    sealer: Arc<dyn SecretEncryptor>,
}

impl TenantScoped for PgAssertionKeyStore {}

impl PgAssertionKeyStore {
    /// A store keeping assertion keys in `databases`, every new private
    /// half sealed by `sealer`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, sealer: Arc<dyn SecretEncryptor>) -> Self {
        Self { databases, sealer }
    }

    /// The new `key` of `tenant` with its private half sealed for storage.
    async fn sealed(
        &self,
        tenant: &ScopedTenant,
        key: &AssertionKey,
        private: &Secret,
    ) -> Result<SealedSecret, DomainError> {
        self.sealer
            .encrypt(
                private.expose().as_bytes(),
                &key_place(tenant, key.kid().as_str()),
            )
            .await
    }

    /// Each new key of `keys`, with its private half sealed.
    async fn added<'k>(
        &self,
        tenant: &ScopedTenant,
        keys: &'k AssertionKeySet<ResolvedTenant>,
    ) -> Result<Vec<(&'k AssertionKey, SealedSecret)>, DomainError> {
        let sealing = keys
            .keys()
            .iter()
            .filter_map(|key| match key.private_half() {
                PrivateHalf::Fresh(private) => Some(async move {
                    self.sealed(tenant, key, private)
                        .await
                        .map(|sealed| (key, sealed))
                }),
                PrivateHalf::Stored => None,
            });
        try_join_all(sealing).await
    }
}

#[async_trait]
impl AssertionKeyStore for PgAssertionKeyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionKeySet<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AssertionKeyRecord,
                    "queries/assertion_keys/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        if records.is_empty() {
            return Ok(None);
        }
        let keys = records
            .into_iter()
            .map(AssertionKeyRecord::into_key)
            .collect::<Result<Vec<_>, _>>()?;
        AssertionKeySet::from_keys(keys).map(Some)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        keys: &AssertionKeySet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let added = self.added(tenant_id, keys).await?;
        let known: Vec<&AssertionKey> = keys.keys().iter().filter(|key| !is_new(key)).collect();
        let standing = StandingColumns::of(known.iter().copied());
        let columns = AddedColumns::of(&added);
        let updated = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let updated = update_standing(connection, tenant_id, &standing).await?;
                sqlx::query_file!(
                    "queries/assertion_keys/add.sql",
                    tenant_id.as_uuid(),
                    &columns.kids,
                    &columns.algorithms,
                    &columns.public_keys,
                    &columns.private_keys,
                    &columns.statuses,
                    &columns.rotated_at as &[Option<OffsetDateTime>],
                    &columns.created_at,
                )
                .execute(connection)
                .await?;
                Ok(updated)
            },
        )
        .await?;
        ensure_known_keys_updated(updated, known.len())
    }
}

/// Requires every key read from storage to remain present when its standing is updated.
fn ensure_known_keys_updated(updated: u64, expected: usize) -> Result<(), DomainError> {
    if usize::try_from(updated).ok() != Some(expected) {
        return Err(DomainError::infra_msg(
            "an assertion key read back from storage is no longer stored",
        ));
    }
    Ok(())
}

/// Updates existing keys before adding fresh keys, preserving the active-key constraint.
async fn update_standing(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    standing: &StandingColumns,
) -> Result<u64, sqlx::Error> {
    sqlx::query_file!(
        "queries/assertion_keys/standing.sql",
        tenant.as_uuid(),
        &standing.kids,
        &standing.statuses,
        &standing.rotated_at as &[Option<OffsetDateTime>],
    )
    .execute(connection)
    .await
    .map(|updated| updated.rows_affected())
}

/// The Postgres read of the key that signs a tenant's assertions, for the
/// gateway's role.
pub struct PgAssertionSigningKeys {
    databases: Arc<Databases>,
    sealer: Arc<dyn SecretEncryptor>,
}

impl TenantScoped for PgAssertionSigningKeys {}

impl PgAssertionSigningKeys {
    /// A read of the assertion keys in `databases`, the gateway's, the
    /// signing key's private half opened by `sealer`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, sealer: Arc<dyn SecretEncryptor>) -> Self {
        Self { databases, sealer }
    }

    /// The private half sealed as `sealed` for `tenant`'s key `kid`,
    /// opened.
    async fn opened(
        &self,
        tenant: &ScopedTenant,
        kid: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret, DomainError> {
        let opened = self.sealer.decrypt(sealed, &key_place(tenant, kid)).await?;
        String::from_utf8(opened)
            .map(Secret::new)
            .map_err(DomainError::infra)
    }

    /// Reads both halves under the gateway's tenant-scoped database role.
    async fn sealed_records(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<Vec<SealedAssertionKeyRecord>, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    SealedAssertionKeyRecord,
                    "queries/assertion_keys/sealed_of_tenant.sql",
                    tenant.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl AssertionSigningKeys for PgAssertionSigningKeys {
    async fn signing(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AssertionSigningKey>, DomainError> {
        let records = self.sealed_records(tenant_id).await?;
        let mut keys = Vec::with_capacity(records.len());
        let mut sealed_halves = Vec::with_capacity(records.len());
        for record in records {
            let (public, sealed) = record.split()?;
            let key = public.into_key()?;
            sealed_halves.push((key.kid().clone(), sealed));
            keys.push(key);
        }
        let set = AssertionKeySet::<ResolvedTenant>::from_keys(keys)?;
        let Some(signing) = set.signing_key() else {
            return Ok(None);
        };
        let (_, sealed) = sealed_halves
            .iter()
            .find(|(kid, _)| kid == signing.kid())
            .ok_or_else(|| DomainError::infra_msg("the signing key left its set"))?;
        let private = self
            .opened(tenant_id, signing.kid().as_str(), sealed)
            .await?;
        Ok(AssertionSigningKey::of(&set, private))
    }
}

/// The Postgres read of assertion keys across every tenant, for the
/// sweeps.
pub struct PgCrossTenantAssertionKeys {
    databases: Arc<Databases>,
}

impl PgCrossTenantAssertionKeys {
    /// A read of the assertion keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The tenants in the platform database holding a rotated key.
    async fn shared_rotated(&self) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/assertion_keys/rotated.sql")
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Whether `tenant`, in its own database, holds a rotated key.
    async fn own_rotated(&self, tenant: TenantId) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/assertion_keys/rotated_of_tenant.sql",
                    tenant.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    /// The tenants in the platform database with no active key made at or
    /// after `cutoff`.
    async fn shared_due(&self, cutoff: OffsetDateTime) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/assertion_keys/due.sql", cutoff)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// The active tenants holding no assertion key in the platform
    /// database, those living apart among them.
    async fn shared_keyless(&self) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/assertion_keys/keyless.sql")
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Whether `tenant`, in its own database, holds no assertion key at
    /// all.
    async fn own_keyless(&self, tenant: TenantId) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/assertion_keys/none_of_tenant.sql",
                    tenant.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    /// The active tenants holding no assertion key at all: those the
    /// platform database finds none for, each living apart asked again in
    /// its own database.
    async fn keyless(&self, own: &[TenantId]) -> Result<Vec<TenantId>, DomainError> {
        let found = self.shared_keyless().await?;
        let (apart, here): (Vec<TenantId>, Vec<TenantId>) = found
            .into_iter()
            .map(TenantId::from_uuid)
            .partition(|tenant| own.contains(tenant));
        let none = try_join_all(apart.iter().map(|tenant| self.own_keyless(*tenant))).await?;
        let keyless_apart = apart
            .into_iter()
            .zip(none)
            .filter_map(|(tenant, none)| none.then_some(tenant));
        Ok(here.into_iter().chain(keyless_apart).collect())
    }

    /// Whether `tenant`, in its own database, holds keys but no active one
    /// made at or after `cutoff`.
    async fn own_due(&self, tenant: TenantId, cutoff: OffsetDateTime) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/assertion_keys/due_of_tenant.sql",
                    tenant.as_uuid(),
                    cutoff
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }
}

/// The tenants `shared` names, and those of `own` whose answer at the same
/// place in `held` is yes.
pub(super) fn every_tenant(
    shared: Vec<Uuid>,
    own: Vec<TenantId>,
    held: Vec<bool>,
) -> Vec<TenantId> {
    let holding = own
        .into_iter()
        .zip(held)
        .filter_map(|(tenant, holds)| holds.then_some(tenant));
    shared
        .into_iter()
        .map(TenantId::from_uuid)
        .chain(holding)
        .collect()
}

#[async_trait]
impl CrossTenantAssertionKeys for PgCrossTenantAssertionKeys {
    async fn tenants_with_rotated_keys(&self) -> Result<Vec<TenantId>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, held) = futures_util::try_join!(
            self.shared_rotated(),
            try_join_all(own.iter().map(|tenant| self.own_rotated(*tenant)))
        )?;
        Ok(every_tenant(shared, own, held))
    }

    async fn tenants_due(&self, cutoff: OffsetDateTime) -> Result<Vec<TenantId>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, held, keyless) = futures_util::try_join!(
            self.shared_due(cutoff),
            try_join_all(own.iter().map(|tenant| self.own_due(*tenant, cutoff))),
            self.keyless(&own)
        )?;
        let mut due = every_tenant(shared, own, held);
        due.extend(keyless);
        Ok(due)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_domain::domains::crypto::assertion_key::NewAssertionKey;
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::causes;
    use ianua_domain::types::{KeyId, PublicKeyPem};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};

    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----";

    struct Fixture {
        db: TestDb,
        store: PgAssertionKeyStore,
        gateway: PgAssertionSigningKeys,
        tenant: ScopedTenant,
    }

    impl Fixture {
        /// Saves a tenant's initial key set with the fixture's real sealer.
        async fn save_key(&self, tenant: &ScopedTenant, key: AssertionKey) {
            self.store
                .save(tenant, &AssertionKeySet::new(key))
                .await
                .unwrap();
        }
    }

    /// A fresh database, the app's store and the gateway's read on it, both
    /// sealing with one real sealer, and one tenant to keep keys for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let sealer: Arc<dyn SecretEncryptor> = Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [7; 32]).unwrap(),
            Vec::new(),
        ));
        Fixture {
            store: PgAssertionKeyStore::new(Arc::clone(&db.databases), Arc::clone(&sealer)),
            gateway: PgAssertionSigningKeys::new(Arc::clone(&db.gateway), sealer),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn key(kid: &str) -> AssertionKey {
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(PUBLIC).unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    fn made_ago(kid: &str, ago: time::Duration) -> AssertionKey {
        let _frozen = clock::freeze(clock::now() - ago);
        key(kid)
    }

    fn kids(set: &AssertionKeySet<ResolvedTenant>) -> Vec<&str> {
        set.keys().iter().map(|key| key.kid().as_str()).collect()
    }

    /// A tenant's first key is found again as it was saved, with no
    /// private half: the app's side never reads one back.
    #[tokio::test]
    async fn a_saved_key_is_found_without_its_private_half() {
        let fx = fixture().await;
        let saved = AssertionKeySet::new(key("a1"));

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        let key = &found.keys()[0];
        assert_eq!(kids(&found), ["a1"]);
        assert_eq!(key.algorithm(), AssertionKey::ALGORITHM);
        assert_eq!(key.public_key().as_str(), PUBLIC);
        assert!(key.is_active());
        assert!(matches!(key.private_half(), PrivateHalf::Stored));
    }

    /// The gateway reads the key that signs, its private half opened as it
    /// was made.
    #[tokio::test]
    async fn the_gateway_reads_the_signing_key_opened() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &AssertionKeySet::new(key("a1")))
            .await
            .unwrap();

        let signing = fx.gateway.signing(&fx.tenant).await.unwrap().unwrap();

        assert_eq!(signing.kid().as_str(), "a1");
        assert_eq!(signing.private_key().expose(), "private-a1");
    }

    /// A tenant without assertion keys gives the gateway no key, so nothing
    /// is signed for it, and the app's side finds none.
    #[tokio::test]
    async fn a_tenant_without_keys_has_none() {
        let fx = fixture().await;

        let signing = fx.gateway.signing(&fx.tenant).await.unwrap();
        let found = fx.store.find(&fx.tenant).await.unwrap();

        assert!(signing.is_none());
        assert!(found.is_none());
    }

    /// Acme rotates: the old key is kept rotated out, the new one signs,
    /// and the gateway opens the new one.
    #[tokio::test]
    async fn a_rotation_is_kept_and_the_gateway_signs_with_the_new_key() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &AssertionKeySet::new(made_ago("old", time::Duration::days(31))),
            )
            .await
            .unwrap();
        let mut set = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        set.rotate_by_age(
            &KeyRotationSchedule::FOR_ASSERTION_KEYS,
            key("new"),
            clock::now(),
        )
        .unwrap();

        fx.store.save(&fx.tenant, &set).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        let signing = fx.gateway.signing(&fx.tenant).await.unwrap().unwrap();
        assert_eq!(kids(&found), ["old", "new"]);
        assert_eq!(found.keys()[0].status(), KeyStatus::Rotated);
        assert_eq!(signing.kid().as_str(), "new");
        assert_eq!(signing.private_key().expose(), "private-new");
    }

    /// Sealing an assertion key for storage hides its private text.
    #[tokio::test]
    async fn a_private_half_is_never_written_in_clear() {
        let fx = fixture().await;
        let made = key("a1");
        let private = Secret::new("private-a1");

        let written = fx.store.sealed(&fx.tenant, &made, &private).await.unwrap();

        assert!(!written.as_str().contains("private-a1"));
    }

    /// Copying Globex's sealed private half into Acme's row makes the
    /// gateway's signing-key read fail as corrupt storage.
    #[tokio::test]
    async fn a_private_half_moved_to_another_tenant_does_not_open() {
        let fx = fixture().await;
        let globex = ScopedTenant::for_background(TenantId::new());
        for tenant in [&fx.tenant, &globex] {
            fx.store
                .save(tenant, &AssertionKeySet::new(key("a1")))
                .await
                .unwrap();
        }
        fx.db
            .tamper(&format!(
                "UPDATE assertion_keys SET private_key_sealed = globex.private_key_sealed \
                 FROM assertion_keys globex \
                 WHERE globex.tenant_id = '{}' AND assertion_keys.tenant_id = '{}'",
                globex.as_uuid(),
                fx.tenant.as_uuid()
            ))
            .await;

        let moved = fx.gateway.signing(&fx.tenant).await;

        assert!(matches!(moved, Err(DomainError::Infrastructure(_))));
    }

    /// Saving a second active assertion key fails, and the gateway still
    /// selects the first key for signing.
    #[tokio::test]
    async fn a_second_key_that_signs_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &AssertionKeySet::new(key("a1")))
            .await
            .unwrap();

        let saved = fx
            .store
            .save(&fx.tenant, &AssertionKeySet::new(key("a2")))
            .await;

        let signing = fx.gateway.signing(&fx.tenant).await.unwrap().unwrap();
        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert_eq!(signing.kid().as_str(), "a1");
    }

    /// The database denies an assertion-key save through the gateway's
    /// role, even when that role is wired into the writable store.
    #[tokio::test]
    async fn saving_as_the_gateway_role_is_refused() {
        let fx = fixture().await;
        let gateway_store =
            PgAssertionKeyStore::new(Arc::clone(&fx.db.gateway), Arc::new(FakeEncryptor));

        let saved = gateway_store
            .save(&fx.tenant, &AssertionKeySet::new(key("a1")))
            .await;

        assert!(saved.is_err_and(|error| causes(&error).contains("permission denied")));
    }

    /// The rotation sweep finds a tenant whose key is old and one where
    /// nothing signs, and passes over one with a young key.
    #[tokio::test]
    async fn the_sweep_finds_the_tenants_due() {
        let fx = fixture().await;
        let young = ScopedTenant::for_background(TenantId::new());
        let silent = ScopedTenant::for_background(TenantId::new());
        fx.save_key(&fx.tenant, made_ago("old", time::Duration::days(31)))
            .await;
        fx.save_key(&young, key("a1")).await;
        fx.save_key(&silent, key("a1")).await;
        fx.db
            .tamper(&format!(
                "UPDATE assertion_keys SET status = 'revoked' WHERE tenant_id = '{}'",
                silent.as_uuid()
            ))
            .await;
        let sweep = PgCrossTenantAssertionKeys::new(Arc::clone(&fx.db.databases));
        let cutoff = KeyRotationSchedule::FOR_ASSERTION_KEYS.due_before(clock::now());

        let mut due = sweep.tenants_due(cutoff).await.unwrap();
        due.sort_by_key(|tenant| *tenant.as_uuid());
        let mut expected = vec![*fx.tenant, *silent];
        expected.sort_by_key(|tenant| *tenant.as_uuid());

        assert_eq!(due, expected);
    }

    /// The rotation sweep includes an active tenant without assertion
    /// keys and excludes a tenant with a young key.
    #[tokio::test]
    async fn the_sweep_finds_an_active_tenant_without_keys() {
        let fx = fixture().await;
        let organization = saved_organization(&fx.db.databases).await;
        let keyless = saved_tenant_of(&fx.db.databases, organization).await;
        let keyed = saved_tenant_of(&fx.db.databases, organization).await;
        fx.store
            .save(&keyed, &AssertionKeySet::new(key("a1")))
            .await
            .unwrap();
        let sweep = PgCrossTenantAssertionKeys::new(Arc::clone(&fx.db.databases));
        let cutoff = KeyRotationSchedule::FOR_ASSERTION_KEYS.due_before(clock::now());

        let due = sweep.tenants_due(cutoff).await.unwrap();

        assert_eq!(due, [*keyless]);
    }

    /// The retiring sweep finds a tenant holding a rotated key, and passes
    /// over one whose only key signs.
    #[tokio::test]
    async fn the_sweep_finds_the_tenants_holding_a_rotated_key() {
        let fx = fixture().await;
        let calm = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(
                &fx.tenant,
                &AssertionKeySet::new(made_ago("old", time::Duration::days(31))),
            )
            .await
            .unwrap();
        let mut set = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        set.rotate_by_age(
            &KeyRotationSchedule::FOR_ASSERTION_KEYS,
            key("new"),
            clock::now(),
        )
        .unwrap();
        fx.store.save(&fx.tenant, &set).await.unwrap();
        fx.store
            .save(&calm, &AssertionKeySet::new(key("a1")))
            .await
            .unwrap();
        let sweep = PgCrossTenantAssertionKeys::new(Arc::clone(&fx.db.databases));

        let found = sweep.tenants_with_rotated_keys().await.unwrap();

        assert_eq!(found, [*fx.tenant]);
    }
}
