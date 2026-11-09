//! Registered custom domains, and the claims on their names: the two stores
//! of `ports/domain/registrations.rs`, sharing one mapping.
//!
//! A tenant's registrations are tenant rows, under row-level security, in
//! the database the tenant lives in. A hostname belongs to the whole
//! deployment: registering it stops every other tenant from registering
//! it. So the claim on it is kept apart, in `domain_claims`, always in the
//! platform database: its primary key keeps a name to one registration
//! across every tenant, whichever database the registrations live in. A
//! unique index on the registrations could not, since a tenant with a
//! database of its own keeps them there.
//!
//! A save claims the name first, so a taken name is refused before
//! anything of the registration is written, then writes the registration;
//! a delete releases the claim with the row. The two are written by two
//! store calls, which a unit of work keeps or drops together. A new
//! registration claims through `register`, which also refuses a name above
//! or below another tenant's claim, in one transaction under a lock on the
//! name's registrable domain (see `claims`).
//!
//! The claim keeps whether its registration proved the name, written with
//! every save, so the nameservers serve a delegated zone only once its name
//! is proved and stop the moment the proof is lost.
//!
//! A registration's claim follows its id: saving the same registration
//! under another tenant moves the claim to it, and the certificates beside
//! the claim follow by their foreign key. That is how a handover keeps the
//! verification and the certificate of the domain it moves; it saves the
//! registration under the receiving tenant before deleting it from the
//! giving one.
//!
//! The questions no tenant owns read the claim first, one indexed read,
//! then the registration from the database its tenant lives in. The sweeps
//! read every tenant's registrations, one query per database.

mod claims;
mod record;
mod sweeps;
mod words;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::domain::{CrossTenantDomainStore, DomainSortField, RegisteredDomainStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ClaimLifetimes, RegisteredDomain,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use self::claims::StillHeld;
use self::record::{Claim, DomainColumns, DomainRecord};
use self::sweeps::{AWAITING_PROOF_AT_MOST, Sweep};
use crate::postgres::foundation::errors::Uniqueness;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of one tenant's registered domains.
pub struct PgRegisteredDomainStore {
    databases: Arc<Databases>,
}

impl PgRegisteredDomainStore {
    /// A store keeping registrations, and the claims on their names, in
    /// `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `domain` itself, in the tenant's database.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = DomainColumns::of(domain);
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/registered_domains/save.sql",
                    tenant.as_uuid(),
                    columns.id,
                    columns.domain,
                    columns.connection,
                    columns.verification_status,
                    columns.verified_at,
                    columns.failed_at,
                    columns.dns_challenge_token,
                    columns.tls_status,
                    columns.created_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

impl TenantScoped for PgRegisteredDomainStore {}

/// The records of the registrations of `tenant` that `ids` names, in no
/// order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

/// The registrations of `tenant` that `ids` names, read from the database
/// the tenant lives in.
async fn read(
    databases: &Databases,
    tenant: TenantId,
    ids: &[Uuid],
) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, DomainError> {
    let records = scoped(databases, RowScope::Tenant(tenant), async |connection| {
        records_of(connection, tenant.as_uuid(), ids).await
    })
    .await?;
    records.into_iter().map(DomainRecord::into_domain).collect()
}

impl SortColumns for DomainSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Domain => "domain",
            Self::VerificationStatus => "verification_status",
            Self::VerifiedAt => "verified_at",
        }
    }

    fn nullable(self) -> Nullable {
        match self {
            Self::VerifiedAt => Nullable::Maybe,
            Self::CreatedAt | Self::Domain | Self::VerificationStatus => Nullable::Never,
        }
    }
}

#[async_trait]
impl RegisteredDomainStore for PgRegisteredDomainStore {
    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        domains: &[DomainName],
    ) -> Result<Vec<RegisteredDomain<ResolvedTenant>>, DomainError> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<_> = domains
            .iter()
            .map(|domain| domain.as_str().to_owned())
            .collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DomainRecord,
                    "queries/registered_domains/by_names.sql",
                    tenant_id.as_uuid(),
                    &names
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(DomainRecord::into_domain).collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if claims::claim(&self.databases, tenant_id, domain).await? == Uniqueness::Taken {
            return Err(DomainError::conflict(message!(
                "infra-is-already-claimed",
                format!("{} is already claimed", domain.domain())
            )));
        }
        self.write(tenant_id, domain).await
    }

    async fn register(
        &self,
        tenant_id: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let held = StillHeld::at(now, lifetimes);
        if claims::claim_new(&self.databases, tenant_id, domain, &held).await? == Uniqueness::Taken
        {
            return Err(DomainError::conflict(message!(
                "infra-or-a-name-above-or-below",
                format!(
                    "{} or a name above or below it is already claimed",
                    domain.domain()
                )
            )));
        }
        self.write(tenant_id, domain).await
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DomainId,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let found = read(&self.databases, **tenant_id, &[*id.as_uuid()]).await?;
        Ok(found.into_iter().next())
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<DomainSortField>,
        page: &PageRequest,
    ) -> Result<Page<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = PageQuery::ids("id", "registered_domains")
                    .filter("tenant_id = ?", tenant)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                let records = records_of(connection, &tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let domains = records
            .into_iter()
            .map(DomainRecord::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(domains))
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &DomainId) -> Result<bool, DomainError> {
        let deleted = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/registered_domains/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        claims::release(&self.databases, tenant_id, id).await?;
        Ok(deleted.rows_affected() > 0)
    }

    async fn find_by_tenant_and_name(
        &self,
        tenant_id: &ScopedTenant,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DomainRecord,
                    "queries/registered_domains/by_name.sql",
                    tenant_id.as_uuid(),
                    domain.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(DomainRecord::into_domain).transpose()
    }
}

/// The Postgres store of the registered-domain questions no single tenant
/// owns.
pub struct PgCrossTenantDomainStore {
    databases: Arc<Databases>,
}

impl PgCrossTenantDomainStore {
    /// A store reading registrations, and the claims on their names, from
    /// `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The registrations `claims` stand for, each with its tenant, read
    /// from the database each tenant lives in.
    async fn behind(
        &self,
        claims: Vec<Claim>,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        let mut by_tenant: HashMap<TenantId, Vec<Uuid>> = HashMap::new();
        for claim in claims {
            by_tenant
                .entry(claim.tenant)
                .or_default()
                .push(*claim.domain_id.as_uuid());
        }
        let reads = by_tenant.into_iter().map(|(tenant, ids)| async move {
            let domains = read(&self.databases, tenant, &ids).await?;
            Ok::<_, DomainError>(domains.into_iter().map(move |domain| (tenant, domain)))
        });
        Ok(try_join_all(reads).await?.into_iter().flatten().collect())
    }

    /// Deletes the registration `claim` stands for while it is still lapsed
    /// by `now` under `lifetimes`. Answers whether it did.
    async fn delete_lapsed(
        &self,
        claim: &Claim,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let unproved_before = now.saturating_sub(lifetimes.unproved.duration());
        let lost_before = now.saturating_sub(lifetimes.failed_grace.duration());
        let deleted = scoped(
            &self.databases,
            RowScope::Tenant(claim.tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/registered_domains/delete_lapsed.sql",
                    claim.tenant.as_uuid(),
                    claim.domain_id.as_uuid(),
                    unproved_before,
                    lost_before
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(deleted.rows_affected() > 0)
    }

    /// Every tenant's registrations `sweep` works through.
    async fn swept(
        &self,
        sweep: Sweep,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        sweep
            .everywhere(&self.databases)
            .await?
            .into_iter()
            .map(DomainRecord::into_listed)
            .collect()
    }
}

#[async_trait]
impl CrossTenantDomainStore for PgCrossTenantDomainStore {
    async fn find_by_domain(
        &self,
        domain: &DomainName,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let Some(claim) = claims::of_hostname(&self.databases, domain).await? else {
            return Ok(None);
        };
        let found = read(&self.databases, claim.tenant, &[*claim.domain_id.as_uuid()]).await?;
        Ok(found.into_iter().next())
    }

    async fn find_overlapping(
        &self,
        domain: &DomainName,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        let claims = claims::overlapping(&self.databases, domain).await?;
        self.behind(claims).await
    }

    async fn release_lapsed_claim(
        &self,
        domain: &DomainName,
        lifetimes: &ClaimLifetimes,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let Some(claim) = claims::of_hostname(&self.databases, domain).await? else {
            return Ok(false);
        };
        if !self.delete_lapsed(&claim, lifetimes, now).await? {
            return Ok(false);
        }
        claims::release(&self.databases, &claim.tenant, &claim.domain_id).await?;
        Ok(true)
    }

    async fn find_by_domain_id(&self, id: &DomainId) -> Result<Option<DomainName>, DomainError> {
        let claim = claims::of_domain(&self.databases, id).await?;
        Ok(claim.map(|claim| claim.hostname))
    }

    async fn mark_checked(&self, id: &DomainId) -> Result<(), DomainError> {
        let Some(claim) = claims::of_domain(&self.databases, id).await? else {
            return Ok(());
        };
        let now = clock::now();
        scoped(
            &self.databases,
            RowScope::Tenant(claim.tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/registered_domains/mark_checked.sql",
                    claim.tenant.as_uuid(),
                    id.as_uuid(),
                    now
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn list_pending_verification(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        let mut pending = self.swept(Sweep::AwaitingProof(clock::now())).await?;
        pending.sort_by_key(|(_, domain)| domain.created_at());
        pending.truncate(AWAITING_PROOF_AT_MOST);
        Ok(pending)
    }

    async fn list_verified(
        &self,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        self.swept(Sweep::Proved).await
    }

    async fn list_awaiting_certificate(
        &self,
        stale_after_minutes: u32,
    ) -> Result<Vec<(TenantId, RegisteredDomain<ResolvedTenant>)>, DomainError> {
        let cutoff = clock::now().saturating_sub(Duration::minutes(i64::from(stale_after_minutes)));
        self.swept(Sweep::AwaitingCertificate(cutoff)).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainProof, RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::{
        TlsStatus, VerificationStatus,
    };
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::domain::{
        domain_name, proved_domain_row, registered_domain_row, saved_tenant,
    };

    /// Seconds from the fixed moment to a time long past, for the sweeps,
    /// which compare against the real clock.
    const LONG_AGO: i64 = -100_000_000;

    struct Fixture {
        database: TestDb,
        store: PgRegisteredDomainStore,
        across: PgCrossTenantDomainStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one saved tenant, and both stores on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let tenant = saved_tenant(&database.databases).await;
        Fixture {
            store: PgRegisteredDomainStore::new(Arc::clone(&database.databases)),
            across: PgCrossTenantDomainStore::new(Arc::clone(&database.databases)),
            tenant,
            database,
        }
    }

    fn domain(row: RegisteredDomainRow) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(row).unwrap()
    }

    fn named(name: &str) -> RegisteredDomain<ResolvedTenant> {
        domain(registered_domain_row(name))
    }

    /// A registration of `name` never proved, made long ago.
    fn old_claim(name: &str) -> RegisteredDomain<ResolvedTenant> {
        domain(RegisteredDomainRow {
            created_at: at(LONG_AGO),
            ..registered_domain_row(name)
        })
    }

    /// A registration of `name` proved long ago, still waiting for its
    /// certificate.
    fn proved_long_ago(name: &str) -> RegisteredDomain<ResolvedTenant> {
        domain(RegisteredDomainRow {
            created_at: at(LONG_AGO),
            proof: DomainProof::Verified {
                at: at(LONG_AGO + 1),
            },
            ..proved_domain_row(name)
        })
    }

    fn lifetimes() -> ClaimLifetimes {
        ClaimLifetimes {
            unproved: Lifetime::seconds(3600).unwrap(),
            failed_grace: Lifetime::seconds(3600).unwrap(),
        }
    }

    fn names(listed: &[(TenantId, RegisteredDomain<ResolvedTenant>)]) -> Vec<(TenantId, String)> {
        let mut names: Vec<_> = listed
            .iter()
            .map(|(tenant, domain)| (*tenant, domain.domain().as_str().to_owned()))
            .collect();
        names.sort_by(|a, b| a.1.cmp(&b.1));
        names
    }

    /// Requires a batch lookup to expose no registrations in this tenant.
    async fn assert_no_names(db: &Fixture, tenant: &ScopedTenant, names: &[DomainName]) {
        assert!(
            db.store
                .find_by_names(tenant, names)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Reads the returned page's hostnames in their database order.
    fn listed_names(page: &Page<RegisteredDomain<ResolvedTenant>>) -> Vec<String> {
        page.items
            .iter()
            .map(|domain| domain.domain().as_str().to_owned())
            .collect()
    }

    /// A saved registration is found by its id and by its name, as saved.
    #[tokio::test]
    async fn a_saved_registration_is_found_by_id_and_by_name() {
        let db = fixture().await;
        let login = domain(proved_domain_row("login.acme.example"));

        db.store.save(&db.tenant, &login).await.unwrap();

        let by_id = db.store.find_by_id(&db.tenant, login.id()).await.unwrap();
        let by_name = db
            .store
            .find_by_tenant_and_name(&db.tenant, login.domain())
            .await
            .unwrap();
        for found in [by_id.unwrap(), by_name.unwrap()] {
            assert_eq!(found.id(), login.id());
            assert_eq!(found.domain(), login.domain());
            assert_eq!(found.connection(), login.connection());
            assert_eq!(found.proof(), login.proof());
            assert_eq!(found.tls_status(), login.tls_status());
            assert_eq!(found.dns_challenge_token(), login.dns_challenge_token());
            assert_eq!(found.created_at(), login.created_at());
        }
    }

    /// Requested registrations are read once each with their proofs intact;
    /// foreign and missing names are omitted and an empty request returns none.
    #[tokio::test]
    async fn domain_name_batches_keep_the_tenant_boundary() {
        let db = fixture().await;
        let login = domain(proved_domain_row("login.acme.example"));
        let foreign = named("login.globex.example");
        let other = saved_tenant(&db.database.databases).await;
        db.store.save(&db.tenant, &login).await.unwrap();
        db.store
            .save(&db.tenant, &named("omitted.acme.example"))
            .await
            .unwrap();
        db.store.save(&other, &foreign).await.unwrap();

        let found = db
            .store
            .find_by_names(
                &db.tenant,
                &[
                    login.domain().clone(),
                    foreign.domain().clone(),
                    DomainName::new("missing.example").unwrap(),
                    login.domain().clone(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), login.id());
        assert_eq!(found[0].proof(), login.proof());
        assert_no_names(&db, &db.tenant, &[]).await;
        assert_no_names(&db, &other, std::slice::from_ref(login.domain())).await;
    }

    /// An id nobody has finds nothing, and another tenant finds none of
    /// this tenant's registrations.
    #[tokio::test]
    async fn a_registration_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let login = named("login.acme.example");
        db.store.save(&db.tenant, &login).await.unwrap();
        let other = saved_tenant(&db.database.databases).await;

        let unknown = db.store.find_by_id(&db.tenant, &DomainId::new()).await;
        let theirs = db.store.find_by_id(&other, login.id()).await;
        let by_name = db
            .store
            .find_by_tenant_and_name(&other, login.domain())
            .await;

        assert!(unknown.unwrap().is_none());
        assert!(theirs.unwrap().is_none());
        assert!(by_name.unwrap().is_none());
    }

    /// Saving a second tenant's registration for a claimed hostname returns
    /// a conflict and leaves that tenant without the rival registration.
    #[tokio::test]
    async fn a_name_another_tenant_holds_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &named("login.acme.example"))
            .await
            .unwrap();
        let other = saved_tenant(&db.database.databases).await;
        let rival = named("login.acme.example");

        let second = db.store.save(&other, &rival).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert!(
            db.store
                .find_by_id(&other, rival.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The tenant's registrations list by name, page by page, and another
    /// tenant's are left out.
    #[tokio::test]
    async fn registrations_are_listed_page_by_page_by_name() {
        let db = fixture().await;
        for name in ["c.acme.example", "a.acme.example", "b.acme.example"] {
            db.store.save(&db.tenant, &named(name)).await.unwrap();
        }
        let other = saved_tenant(&db.database.databases).await;
        db.store
            .save(&other, &named("aa.acme.example"))
            .await
            .unwrap();
        let order = SortOrder::single(Sort::ascending(DomainSortField::Domain));

        let first = PageRequest::first(Limit::new(2).unwrap());
        let page_one = db
            .store
            .list_by_tenant(&db.tenant, &order, &first)
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .list_by_tenant(&db.tenant, &order, &after)
            .await
            .unwrap();

        assert_eq!(
            listed_names(&page_one),
            ["a.acme.example", "b.acme.example"]
        );
        assert_eq!(listed_names(&page_two), ["c.acme.example"]);
        assert!(!page_two.has_next());
    }

    /// Sorted by when they were proved, the registrations never proved come
    /// after the proved ones, and paging loses none.
    #[tokio::test]
    async fn a_list_by_proof_pages_past_the_unproved() {
        let db = fixture().await;
        let proved = domain(proved_domain_row("a.acme.example"));
        db.store.save(&db.tenant, &proved).await.unwrap();
        for name in ["b.acme.example", "c.acme.example"] {
            db.store.save(&db.tenant, &named(name)).await.unwrap();
        }
        let order = SortOrder::single(Sort::ascending(DomainSortField::VerifiedAt));

        let first = PageRequest::first(Limit::new(2).unwrap());
        let page_one = db
            .store
            .list_by_tenant(&db.tenant, &order, &first)
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db
            .store
            .list_by_tenant(&db.tenant, &order, &after)
            .await
            .unwrap();

        assert_eq!(page_one.items[0].id(), proved.id());
        assert_eq!(page_one.items.len() + page_two.items.len(), 3);
        assert!(!page_two.has_next());
    }

    /// A proof made later is kept when the registration is saved again, and
    /// when it was registered stays.
    #[tokio::test]
    async fn saving_again_keeps_the_new_proof() {
        let db = fixture().await;
        let login = named("login.acme.example");
        db.store.save(&db.tenant, &login).await.unwrap();
        let proved = domain(RegisteredDomainRow {
            id: *login.id(),
            ..proved_domain_row("login.acme.example")
        });

        db.store.save(&db.tenant, &proved).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, login.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.verification_status(), VerificationStatus::Verified);
        assert_eq!(found.tls_status(), TlsStatus::Provisioning);
        assert_eq!(found.created_at(), login.created_at());
    }

    /// A deleted registration is gone, says it was there once and not
    /// twice, and its name is free for another tenant.
    #[tokio::test]
    async fn a_deleted_registration_releases_its_name() {
        let db = fixture().await;
        let login = named("login.acme.example");
        db.store.save(&db.tenant, &login).await.unwrap();

        let first = db.store.delete(&db.tenant, login.id()).await.unwrap();
        let second = db.store.delete(&db.tenant, login.id()).await.unwrap();

        let other = saved_tenant(&db.database.databases).await;
        assert!(first);
        assert!(!second);
        assert!(
            db.store
                .find_by_id(&db.tenant, login.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .save(&other, &named("login.acme.example"))
                .await
                .is_ok()
        );
    }

    /// A handover saves the registration under the receiving tenant, then
    /// deletes it from the giving one: the name stays claimed, now by the
    /// receiver, and the giver holds nothing.
    #[tokio::test]
    async fn a_handed_over_registration_keeps_its_claim() {
        let db = fixture().await;
        let login = domain(proved_domain_row("login.acme.example"));
        db.store.save(&db.tenant, &login).await.unwrap();
        let receiver = saved_tenant(&db.database.databases).await;

        db.store.save(&receiver, &login).await.unwrap();
        let deleted = db.store.delete(&db.tenant, login.id()).await.unwrap();

        let held = db.across.find_overlapping(login.domain()).await.unwrap();
        let theirs = db.store.find_by_id(&receiver, login.id()).await.unwrap();
        assert!(deleted);
        assert_eq!(names(&held), [(*receiver, "login.acme.example".to_owned())]);
        assert_eq!(theirs.unwrap().proof(), login.proof());
        assert!(
            db.store
                .find_by_id(&db.tenant, login.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Any tenant's registration is found by its name and its name by its
    /// id, with no tenant in hand; a name nobody holds finds nothing.
    #[tokio::test]
    async fn a_registration_is_found_by_name_across_tenants() {
        let db = fixture().await;
        let login = named("login.acme.example");
        db.store.save(&db.tenant, &login).await.unwrap();

        let by_name = db.across.find_by_domain(login.domain()).await.unwrap();
        let name = db.across.find_by_domain_id(login.id()).await.unwrap();
        let nobody = db
            .across
            .find_by_domain(&domain_name("free.acme.example"))
            .await
            .unwrap();

        assert_eq!(by_name.unwrap().id(), login.id());
        assert_eq!(name.as_ref(), Some(login.domain()));
        assert!(nobody.is_none());
        assert!(
            db.across
                .find_by_domain_id(&DomainId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The names at, above and below one are found whichever tenant holds
    /// them, wildcards by the name they stand in front of; a name that only
    /// ends in the same letters is not.
    #[tokio::test]
    async fn the_names_above_and_below_one_are_found() {
        let db = fixture().await;
        let other = saved_tenant(&db.database.databases).await;
        for name in [
            "acme.example",
            "*.login.acme.example",
            "eu.login.acme.example",
        ] {
            db.store.save(&other, &named(name)).await.unwrap();
        }
        for name in ["blogin.acme.example", "login.globex.example"] {
            db.store.save(&db.tenant, &named(name)).await.unwrap();
        }

        let held = db
            .across
            .find_overlapping(&domain_name("login.acme.example"))
            .await
            .unwrap();

        assert_eq!(
            names(&held),
            [
                (*other, "*.login.acme.example".to_owned()),
                (*other, "acme.example".to_owned()),
                (*other, "eu.login.acme.example".to_owned()),
            ]
        );
    }

    /// A claim never proved in its lifetime is released, name and row, so
    /// the owner can register the name.
    #[tokio::test]
    async fn a_lapsed_claim_is_released() {
        let db = fixture().await;
        let squatted = named("login.acme.example");
        db.store.save(&db.tenant, &squatted).await.unwrap();

        let released = db
            .across
            .release_lapsed_claim(squatted.domain(), &lifetimes(), at(7200))
            .await
            .unwrap();

        let other = saved_tenant(&db.database.databases).await;
        assert!(released);
        assert!(
            db.store
                .find_by_id(&db.tenant, squatted.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .save(&other, &named("login.acme.example"))
                .await
                .is_ok()
        );
    }

    /// Releasing a proved claim or an unexpired unproved claim returns
    /// false, as does releasing an unknown name. The proved registration
    /// remains readable.
    #[tokio::test]
    async fn a_claim_still_holding_its_name_is_not_released() {
        let db = fixture().await;
        let proved = domain(proved_domain_row("login.acme.example"));
        let young = named("shop.acme.example");
        db.store.save(&db.tenant, &proved).await.unwrap();
        db.store.save(&db.tenant, &young).await.unwrap();

        let kept_proved = db
            .across
            .release_lapsed_claim(proved.domain(), &lifetimes(), at(7200))
            .await
            .unwrap();
        let kept_young = db
            .across
            .release_lapsed_claim(young.domain(), &lifetimes(), at(60))
            .await
            .unwrap();
        let unknown = db
            .across
            .release_lapsed_claim(&domain_name("free.acme.example"), &lifetimes(), at(7200))
            .await
            .unwrap();

        assert!(!kept_proved);
        assert!(!kept_young);
        assert!(!unknown);
        assert!(
            db.across
                .find_by_domain(proved.domain())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The claims still to be proved are swept once they are due, oldest
    /// first; one checked just now waits for its next turn, and a new one
    /// waits two minutes.
    #[tokio::test]
    async fn the_claims_due_for_a_check_are_swept() {
        let db = fixture().await;
        let due = old_claim("due.acme.example");
        let checked = old_claim("checked.acme.example");
        let fresh = domain(RegisteredDomainRow {
            created_at: clock::now(),
            ..registered_domain_row("fresh.acme.example")
        });
        for registration in [&due, &checked, &fresh] {
            db.store.save(&db.tenant, registration).await.unwrap();
        }
        db.store
            .save(&db.tenant, &proved_long_ago("proved.acme.example"))
            .await
            .unwrap();

        db.across.mark_checked(checked.id()).await.unwrap();
        db.across.mark_checked(&DomainId::new()).await.unwrap();
        let pending = db.across.list_pending_verification().await.unwrap();

        assert_eq!(
            names(&pending),
            [(*db.tenant, "due.acme.example".to_owned())]
        );
    }

    /// The proved registrations of every tenant are swept, and those still
    /// waiting for a certificate once they waited past the cutoff.
    #[tokio::test]
    async fn the_proved_registrations_are_swept() {
        let db = fixture().await;
        let other = saved_tenant(&db.database.databases).await;
        db.store
            .save(&db.tenant, &proved_long_ago("a.acme.example"))
            .await
            .unwrap();
        db.store
            .save(&other, &proved_long_ago("b.acme.example"))
            .await
            .unwrap();
        db.store
            .save(&db.tenant, &old_claim("c.acme.example"))
            .await
            .unwrap();
        let just_proved = domain(RegisteredDomainRow {
            created_at: clock::now(),
            proof: DomainProof::Verified { at: clock::now() },
            ..proved_domain_row("d.acme.example")
        });
        db.store.save(&db.tenant, &just_proved).await.unwrap();

        let proved = db.across.list_verified().await.unwrap();
        let waiting = db.across.list_awaiting_certificate(10).await.unwrap();

        assert_eq!(proved.len(), 3);
        assert_eq!(
            names(&waiting),
            [
                (*db.tenant, "a.acme.example".to_owned()),
                (*other, "b.acme.example".to_owned()),
            ]
        );
    }

    /// A tenant's registration in a dedicated database remains findable
    /// and appears beside shared-database registrations in the proof sweep.
    /// Another tenant's attempt to claim the same name returns a conflict.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_claimed_found_and_swept() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant(&db.database.databases).await;
        db.database.databases.register(*apart, own.as_dedicated());
        let login = proved_long_ago("login.apart.example");
        db.store.save(&apart, &login).await.unwrap();
        db.store
            .save(&db.tenant, &proved_long_ago("shop.acme.example"))
            .await
            .unwrap();

        let clash = db
            .store
            .save(&db.tenant, &named("login.apart.example"))
            .await;
        let found = db.across.find_by_domain(login.domain()).await.unwrap();
        let proved = db.across.list_verified().await.unwrap();

        assert!(matches!(clash, Err(DomainError::Conflict(_))));
        assert_eq!(found.unwrap().id(), login.id());
        assert_eq!(
            names(&proved),
            [
                (*apart, "login.apart.example".to_owned()),
                (*db.tenant, "shop.acme.example".to_owned()),
            ]
        );
    }

    /// A stored challenge token containing spaces makes reading the
    /// registration return an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_registration_is_refused() {
        let db = fixture().await;
        let login = domain(proved_domain_row("login.acme.example"));
        db.store.save(&db.tenant, &login).await.unwrap();
        db.database
            .tamper("UPDATE registered_domains SET dns_challenge_token = 'two words'")
            .await;

        let read = db.store.find_by_id(&db.tenant, login.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// The moment the registrations in these tests are made at, which
    /// leaves a claim made at the fixed moment holding its name.
    fn soon() -> OffsetDateTime {
        at(10)
    }

    /// The settlement of a unit whose one registration `kept` says how it
    /// went.
    fn settled(kept: &Result<(), DomainError>) -> Settlement {
        match kept {
            Ok(()) => Settlement::Commit,
            Err(_) => Settlement::Rollback,
        }
    }

    /// Announces the first claim while keeping its transaction open for the rival.
    async fn register_before_commit(
        store: &PgRegisteredDomainStore,
        tenant: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        claimed: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), DomainError> {
        let kept = store.register(tenant, domain, &lifetimes(), soon()).await;
        claimed.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        kept
    }

    /// While Globex's registration of `acme.example` awaits commit, Acme
    /// attempts `login.acme.example` in another transaction. Globex commits,
    /// Acme receives a conflict, and only Globex's overlapping claim remains.
    #[tokio::test]
    async fn two_overlapping_registrations_at_once_let_exactly_one_win() {
        let db = fixture().await;
        let globex = saved_tenant(&db.database.databases).await;
        let (store, acme) = (&db.store, &db.tenant);
        let (apex, login) = (named("acme.example"), named("login.acme.example"));
        let (claimed, first_claimed) = tokio::sync::oneshot::channel();
        let first = atomically(
            &PgUnitOfWork,
            register_before_commit(store, &globex, &apex, claimed),
            settled,
        );
        let second = atomically(
            &PgUnitOfWork,
            async {
                first_claimed.await.unwrap();
                store.register(acme, &login, &lifetimes(), soon()).await
            },
            settled,
        );

        let (first, second) = tokio::join!(first, second);

        assert!(first.unwrap().is_ok());
        assert!(matches!(second.unwrap(), Err(DomainError::Conflict(_))));
        let held = db
            .across
            .find_overlapping(&domain_name("acme.example"))
            .await
            .unwrap();
        assert_eq!(names(&held), [(*globex, "acme.example".to_owned())]);
    }

    /// With Globex's proved claim on `login.acme.example`, Acme's attempts
    /// to register its parent or a child name return conflicts. The child
    /// registration remains absent.
    #[tokio::test]
    async fn a_name_above_or_below_another_tenants_claim_is_refused() {
        let db = fixture().await;
        let globex = saved_tenant(&db.database.databases).await;
        let held = domain(proved_domain_row("login.acme.example"));
        db.store.save(&globex, &held).await.unwrap();
        let (above, below) = (named("acme.example"), named("eu.login.acme.example"));

        let refused_above = db
            .store
            .register(&db.tenant, &above, &lifetimes(), soon())
            .await;
        let refused_below = db
            .store
            .register(&db.tenant, &below, &lifetimes(), soon())
            .await;

        assert!(matches!(refused_above, Err(DomainError::Conflict(_))));
        assert!(matches!(refused_below, Err(DomainError::Conflict(_))));
        assert!(
            db.store
                .find_by_id(&db.tenant, below.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Globex's claim on `acme.example` was never proved and lapsed long
    /// ago, and Acme's own claim on `shop.acme.example` never stands in its
    /// way: Acme registers `login.acme.example`, judged from the claims
    /// alone.
    #[tokio::test]
    async fn a_lapsed_or_own_claim_does_not_stand_in_the_way() {
        let db = fixture().await;
        let globex = saved_tenant(&db.database.databases).await;
        db.store
            .save(&globex, &old_claim("acme.example"))
            .await
            .unwrap();
        db.store
            .save(&db.tenant, &named("shop.acme.example"))
            .await
            .unwrap();
        let login = named("login.acme.example");

        let registered = db
            .store
            .register(&db.tenant, &login, &lifetimes(), soon())
            .await;

        assert!(registered.is_ok(), "{registered:?}");
        assert!(
            db.store
                .find_by_id(&db.tenant, login.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// After Globex loses proof of `acme.example`, Acme's attempt to
    /// register `login.acme.example` conflicts during the grace period
    /// and succeeds after that period expires.
    #[tokio::test]
    async fn a_claim_whose_proof_was_lost_holds_its_name_through_its_grace() {
        let db = fixture().await;
        let globex = saved_tenant(&db.database.databases).await;
        let lost = domain(RegisteredDomainRow {
            proof: DomainProof::Lost {
                verified_at: at(1),
                failed_at: at(5),
            },
            ..registered_domain_row("acme.example")
        });
        db.store.save(&globex, &lost).await.unwrap();
        let login = named("login.acme.example");

        let in_grace = db
            .store
            .register(&db.tenant, &login, &lifetimes(), soon())
            .await;
        let after_grace = db
            .store
            .register(&db.tenant, &login, &lifetimes(), at(5 + 3601))
            .await;

        assert!(matches!(in_grace, Err(DomainError::Conflict(_))));
        assert!(after_grace.is_ok(), "{after_grace:?}");
    }
}
