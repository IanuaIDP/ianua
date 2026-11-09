//! The DNS zones tenants delegated to us: the manager the control plane
//! writes them through, and the reader the nameservers load them with, the
//! two stores of `ports/domain/dns.rs`, sharing one mapping.
//!
//! Zones and their record sets are platform rows, in the platform database
//! beside the claim on the name each zone answers for. A zone points at
//! that claim by tenant and hostname, so releasing the claim closes the
//! zone, and a handover moving the claim to another tenant moves the zone
//! and its records with it before the handover asks. Every call runs as
//! platform work and names the tenant it is for, so a zone another tenant
//! holds is a miss, never a write.
//!
//! A zone keeps the nameservers its delegation names, worked out from the
//! registration's label when it was opened. The reader reads only the
//! zones whose registration proved the name, each with that proof, which
//! the domain's catalog checks again before serving it. A zone's serial
//! is read from when what it answers last changed, and every change moves
//! that on by a second at least, so each change reads as a new serial.

mod record;
mod values;
mod words;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::domain::{DnsZoneReader, DnsZoneWriter};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, HeldZone, RecordKind, RecordName, RecordSet,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{HolderRecord, RecordSetColumns, RecordSetRecord, ZoneRecord};
use self::values::{NextSet, ValueChange};
use crate::postgres::domain::platform::served_zones;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// Persists tenants' delegated zones and record changes in Postgres.
pub struct PgDnsZoneWriter {
    databases: Arc<Databases>,
    nameservers: Vec<DomainName>,
}

impl PgDnsZoneWriter {
    /// Keeps zones in `databases`, naming each zone's
    /// nameservers after its registration under the shared `nameservers`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, nameservers: Vec<DomainName>) -> Self {
        Self {
            databases,
            nameservers,
        }
    }

    /// Opens the zone of `hostname` for `tenant` unless it is open, and
    /// reads who holds it.
    async fn opened(
        &self,
        tenant: &TenantId,
        hostname: &DomainName,
        nameservers: &[String],
    ) -> Result<Option<HolderRecord>, DomainError> {
        let now = clock::now();
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/dns_zones/open.sql",
                tenant.as_uuid(),
                hostname.as_str(),
                nameservers,
                now
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query_file_as!(
                HolderRecord,
                "queries/dns_zones/holder.sql",
                hostname.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    /// Applies `change` to the set it names in the zone `tenant` holds for
    /// `hostname`. The zone stays locked from reading the set to writing
    /// it, so two changes at once both land. Answers whether the tenant
    /// holds the zone.
    async fn changed_values(
        &self,
        tenant: &TenantId,
        hostname: &DomainName,
        change: ValueChange<'_>,
    ) -> Result<bool, DomainError> {
        let at = SetAt {
            tenant,
            hostname,
            set: change.set(),
            now: clock::now(),
        };
        scoped(&self.databases, RowScope::Platform, async |connection| {
            if !lock_zone(connection, &at).await? {
                return Ok(false);
            }
            let held = sqlx::query_file_as!(
                RecordSetRecord,
                "queries/dns_records/one.sql",
                at.tenant.as_uuid(),
                at.hostname.as_str(),
                at.set.name().as_str(),
                at.set.kind().word()
            )
            .fetch_optional(&mut *connection)
            .await?;
            let next = next_set(change, held).map_err(undecodable)?;
            write_change(connection, &at, &next).await?;
            Ok(true)
        })
        .await
    }
}

/// Where a change to one set's values lands: the zone, the set naming the
/// question it answers, and when.
struct SetAt<'a> {
    tenant: &'a TenantId,
    hostname: &'a DomainName,
    set: &'a RecordSet,
    now: OffsetDateTime,
}

/// Holds the owning tenant's zone until its record change finishes.
async fn lock_zone(connection: &mut PgConnection, at: &SetAt<'_>) -> Result<bool, sqlx::Error> {
    sqlx::query_file_scalar!(
        "queries/dns_zones/lock.sql",
        at.tenant.as_uuid(),
        at.hostname.as_str()
    )
    .fetch_optional(connection)
    .await
    .map(|zone| zone.is_some())
}

/// What the set `held` holds becomes under `change`.
fn next_set(
    change: ValueChange<'_>,
    held: Option<RecordSetRecord>,
) -> Result<NextSet, DomainError> {
    let held = held
        .map(RecordSetRecord::into_held)
        .transpose()?
        .map(|(_, set)| set);
    change.applied_to(held)
}

/// Writes `next` at `at`, moving the zone's serial on when it changes what
/// the zone answers.
async fn write_change(
    connection: &mut PgConnection,
    at: &SetAt<'_>,
    next: &NextSet,
) -> Result<(), sqlx::Error> {
    match next {
        NextSet::Unchanged => Ok(()),
        NextSet::Written(set) => write_set(connection, at, set).await,
        NextSet::Removed => sqlx::query_file!(
            "queries/dns_records/remove.sql",
            at.tenant.as_uuid(),
            at.hostname.as_str(),
            at.set.name().as_str(),
            at.set.kind().word(),
            at.now
        )
        .execute(connection)
        .await
        .map(|_| ()),
    }
}

/// Replaces a record set and advances the serial within the held zone.
async fn write_set(
    connection: &mut PgConnection,
    at: &SetAt<'_>,
    set: &RecordSet,
) -> Result<(), sqlx::Error> {
    let columns = RecordSetColumns::of(set).map_err(undecodable)?;
    sqlx::query_file_scalar!(
        "queries/dns_records/replace.sql",
        at.tenant.as_uuid(),
        at.hostname.as_str(),
        columns.name,
        columns.kind,
        columns.ttl,
        &columns.record_values,
        at.now
    )
    .fetch_one(connection)
    .await
    .map(|_| ())
}

/// `error` carried through the database call it was found in, kept as its
/// cause.
fn undecodable(error: DomainError) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(error))
}

/// The record sets `records` hold, each with the hostname of the zone it is
/// in, ordered by name and then type.
fn in_answer_order(records: Vec<RecordSetRecord>) -> Result<Vec<(String, RecordSet)>, DomainError> {
    let mut held = records
        .into_iter()
        .map(RecordSetRecord::into_held)
        .collect::<Result<Vec<_>, _>>()?;
    held.sort_by(|(_, a), (_, b)| a.name().cmp(b.name()).then_with(|| a.kind().cmp(&b.kind())));
    Ok(held)
}

#[async_trait]
impl DnsZoneWriter for PgDnsZoneWriter {
    async fn create_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        label: &DelegationLabel,
    ) -> Result<Vec<DomainName>, DomainError> {
        let nameservers: Vec<String> = label
            .nameservers(&self.nameservers)?
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let Some(holder) = self.opened(tenant_id, hostname, &nameservers).await? else {
            return Err(DomainError::conflict(message!(
                "infra-is-not-claimed-by-the-tenant",
                format!("{} is not claimed by the tenant", hostname.as_str())
            )));
        };
        holder.into_nameservers_of(tenant_id)
    }

    async fn replace_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        set: &RecordSet,
    ) -> Result<(), DomainError> {
        let columns = RecordSetColumns::of(set)?;
        let now = clock::now();
        let held = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/dns_records/replace.sql",
                tenant_id.as_uuid(),
                hostname.as_str(),
                columns.name,
                columns.kind,
                columns.ttl,
                &columns.record_values,
                now
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        if !held {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    async fn add_to_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        addition: &RecordSet,
    ) -> Result<(), DomainError> {
        let held = self
            .changed_values(tenant_id, hostname, ValueChange::Add(addition))
            .await?;
        if !held {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    async fn remove_from_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        removal: &RecordSet,
    ) -> Result<(), DomainError> {
        self.changed_values(tenant_id, hostname, ValueChange::Remove(removal))
            .await
            .map(|_| ())
    }

    async fn remove_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        name: &RecordName,
        kind: RecordKind,
    ) -> Result<(), DomainError> {
        let now = clock::now();
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/dns_records/remove.sql",
                tenant_id.as_uuid(),
                hostname.as_str(),
                name.as_str(),
                kind.word(),
                now
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn record_sets(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<Vec<RecordSet>, DomainError> {
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                RecordSetRecord,
                "queries/dns_records/of_zone.sql",
                tenant_id.as_uuid(),
                hostname.as_str()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        let held = in_answer_order(records)?;
        Ok(held.into_iter().map(|(_, set)| set).collect())
    }

    async fn delete_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/dns_zones/close.sql",
                tenant_id.as_uuid(),
                hostname.as_str()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn transfer_zone(
        &self,
        from: &TenantId,
        to: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/dns_zones/transfer.sql",
                from.as_uuid(),
                to.as_uuid(),
                hostname.as_str()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

/// The most zones the nameservers hold. A deployment with more proven zones
/// serves the first this many, by tenant and hostname, and every load that
/// leaves some out says so in the log.
const MOST_ZONES_SERVED: usize = 100_000;

/// The Postgres reader of every zone the nameservers may answer for.
///
/// Reads only the zones, their records and whether each claim was proved,
/// so the nameserver's own role, which holds nothing more, can run it.
pub struct PgDnsZoneReader {
    databases: Arc<Databases>,
}

impl PgDnsZoneReader {
    /// A reader of the zones kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl DnsZoneReader for PgDnsZoneReader {
    async fn load_all_zones(&self) -> Result<Vec<HeldZone>, DomainError> {
        let (zones, records) = scoped(&self.databases, RowScope::Platform, async |connection| {
            let zones = within_the_cap(proven_zones(&mut *connection).await?);
            let records = records_of(connection, &zones).await?;
            Ok((zones, records))
        })
        .await?;
        let mut sets: HashMap<String, Vec<RecordSet>> = HashMap::new();
        for (hostname, set) in in_answer_order(records)? {
            sets.entry(hostname).or_default().push(set);
        }
        let mut held = zones
            .into_iter()
            .map(|zone| zone.into_held(&mut sets))
            .collect::<Result<Vec<_>, _>>()?;
        held.extend(served_zones(&self.databases).await?);
        Ok(held)
    }
}

/// The proven zones, one past [`MOST_ZONES_SERVED`] at most, so a load
/// past the cap is seen.
async fn proven_zones(connection: &mut PgConnection) -> Result<Vec<ZoneRecord>, sqlx::Error> {
    let most = i64::try_from(MOST_ZONES_SERVED + 1).unwrap_or(i64::MAX);
    sqlx::query_file_as!(ZoneRecord, "queries/dns_zones/served.sql", most)
        .fetch_all(connection)
        .await
}

/// `zones` cut to [`MOST_ZONES_SERVED`], logged when some are left out.
fn within_the_cap(mut zones: Vec<ZoneRecord>) -> Vec<ZoneRecord> {
    if zones.len() <= MOST_ZONES_SERVED {
        return zones;
    }
    tracing::error!(
        cap = MOST_ZONES_SERVED,
        "more zones are proven than the nameservers hold; the zones past the cap are not served"
    );
    zones.truncate(MOST_ZONES_SERVED);
    zones
}

/// The record sets of `zones`.
async fn records_of(
    connection: &mut PgConnection,
    zones: &[ZoneRecord],
) -> Result<Vec<RecordSetRecord>, sqlx::Error> {
    let tenants: Vec<Uuid> = zones.iter().map(|zone| zone.tenant_id).collect();
    let hostnames: Vec<&str> = zones.iter().map(|zone| zone.hostname.as_str()).collect();
    sqlx::query_file_as!(
        RecordSetRecord,
        "queries/dns_records/of_zones.sql",
        &tenants,
        &hostnames as &[&str]
    )
    .fetch_all(connection)
    .await
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::domain::RegisteredDomainStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::tenant::custom_domains::dns_zone::ZoneStanding;
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        RegisteredDomain, RegisteredDomainRow,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::DomainId;

    use super::*;
    use crate::postgres::domain::PgRegisteredDomainStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::{
        delegated_domain_row, domain_name, lost_domain_row, nameserver_bases, proved_domain_row,
        record_set, saved_tenant,
    };

    const HOST: &str = "auth.acme.example";

    struct Fixture {
        db: TestDb,
        zones: PgDnsZoneWriter,
        reader: PgDnsZoneReader,
        registrations: PgRegisteredDomainStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one saved tenant, and the manager, the reader and
    /// the registrations on it, the reader signed in as the nameservers'
    /// own role.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = saved_tenant(&db.databases).await;
        Fixture {
            zones: PgDnsZoneWriter::new(Arc::clone(&db.databases), nameserver_bases()),
            reader: PgDnsZoneReader::new(Arc::clone(&db.nameserver)),
            registrations: PgRegisteredDomainStore::new(Arc::clone(&db.databases)),
            tenant,
            db,
        }
    }

    fn registration(row: RegisteredDomainRow) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(row).unwrap()
    }

    fn host() -> DomainName {
        domain_name(HOST)
    }

    fn address(name: &str, value: &str) -> RecordSet {
        record_set(name, RecordKind::A, value)
    }

    impl Fixture {
        /// Registers `row` for `tenant`, which claims its name, and opens
        /// its zone.
        async fn delegated(
            &self,
            tenant: &ScopedTenant,
            row: RegisteredDomainRow,
        ) -> RegisteredDomain<ResolvedTenant> {
            let registered = registration(row);
            self.registrations.save(tenant, &registered).await.unwrap();
            let label = DelegationLabel::for_registration(registered.id());
            self.zones
                .create_zone(tenant, registered.domain(), &label)
                .await
                .unwrap();
            registered
        }

        async fn sets_of(&self, tenant: &ScopedTenant) -> Vec<RecordSet> {
            self.zones.record_sets(tenant, &host()).await.unwrap()
        }

        async fn served(&self) -> Vec<HeldZone> {
            self.reader.load_all_zones().await.unwrap()
        }
    }

    /// Checks the proved zone's owner, records and registration-specific delegation.
    fn assert_proved_zone(
        fx: &Fixture,
        registered: &RegisteredDomain<ResolvedTenant>,
        served: &[HeldZone],
    ) {
        let label = DelegationLabel::for_registration(registered.id());
        let standings: Vec<ZoneStanding> = served.iter().map(|held| held.standing).collect();
        assert_eq!(standings, [ZoneStanding::Proven]);
        assert_eq!(served[0].owner, *fx.tenant);
        assert_eq!(served[0].zone.apex(), &host());
        assert_eq!(served[0].zone.sets(), [address(HOST, "203.0.113.7")]);
        assert_eq!(
            served[0].zone.nameservers(),
            label.nameservers(&nameserver_bases()).unwrap()
        );
    }

    /// A zone opened for a name the tenant claims answers with its
    /// registration's own nameservers, and opening it again answers the
    /// same rather than failing.
    #[tokio::test]
    async fn a_zone_answers_with_its_registrations_nameservers() {
        let fx = fixture().await;
        let registered = registration(delegated_domain_row(HOST));
        fx.registrations
            .save(&fx.tenant, &registered)
            .await
            .unwrap();
        let label = DelegationLabel::for_registration(registered.id());

        let first = fx.zones.create_zone(&fx.tenant, &host(), &label).await;
        let again = fx.zones.create_zone(&fx.tenant, &host(), &label).await;

        let expected = label.nameservers(&nameserver_bases()).unwrap();
        assert_eq!(first.unwrap(), expected);
        assert_eq!(again.unwrap(), expected);
    }

    /// Opening a zone for another tenant's claimed name or an unclaimed
    /// name returns a conflict.
    #[tokio::test]
    async fn a_zone_for_a_name_the_tenant_does_not_claim_is_refused() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        let other = saved_tenant(&fx.db.databases).await;
        let label = DelegationLabel::for_registration(&DomainId::new());

        let taken = fx.zones.create_zone(&other, &host(), &label).await;
        let unclaimed = fx
            .zones
            .create_zone(&fx.tenant, &domain_name("nobody.acme.example"), &label)
            .await;

        assert!(matches!(taken, Err(DomainError::Conflict(_))));
        assert!(matches!(unclaimed, Err(DomainError::Conflict(_))));
    }

    /// A zone's sets are read back by name and then type; writing a set
    /// again replaces it whole, and removing one leaves the rest.
    #[tokio::test]
    async fn record_sets_are_replaced_whole_and_removed() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        let txt = record_set(
            "_acme-challenge.auth.acme.example",
            RecordKind::Txt,
            "token",
        );
        for set in [
            address(HOST, "203.0.113.7"),
            txt.clone(),
            address(HOST, "203.0.113.8"),
        ] {
            fx.zones
                .replace_record_set(&fx.tenant, &host(), &set)
                .await
                .unwrap();
        }

        let written = fx.sets_of(&fx.tenant).await;
        fx.zones
            .remove_record_set(&fx.tenant, &host(), txt.name(), RecordKind::Txt)
            .await
            .unwrap();
        fx.zones
            .remove_record_set(&fx.tenant, &host(), txt.name(), RecordKind::Txt)
            .await
            .unwrap();

        assert_eq!(written, [txt, address(HOST, "203.0.113.8")]);
        assert_eq!(fx.sets_of(&fx.tenant).await, [address(HOST, "203.0.113.8")]);
    }

    /// Two TXT values added concurrently to one challenge name share one
    /// record set. Removing the first keeps the second; removing the second
    /// leaves the zone without record sets.
    #[tokio::test]
    async fn values_added_at_once_are_all_kept_and_taken_out_one_by_one() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        let name = "_acme-challenge.auth.acme.example";
        let first = record_set(name, RecordKind::Txt, "first");
        let second = record_set(name, RecordKind::Txt, "second");

        let zone = host();
        let (one, two) = tokio::join!(
            fx.zones.add_to_record_set(&fx.tenant, &zone, &first),
            fx.zones.add_to_record_set(&fx.tenant, &zone, &second)
        );
        let both = fx.sets_of(&fx.tenant).await;
        fx.zones
            .remove_from_record_set(&fx.tenant, &host(), &first)
            .await
            .unwrap();
        let left = fx.sets_of(&fx.tenant).await;
        fx.zones
            .remove_from_record_set(&fx.tenant, &host(), &second)
            .await
            .unwrap();

        one.unwrap();
        two.unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].values().len(), 2);
        assert_eq!(left, [second]);
        assert!(fx.sets_of(&fx.tenant).await.is_empty());
    }

    /// Adding a proof to another tenant's zone returns not found. Removing
    /// that proof succeeds without changing the owner's empty record sets.
    #[tokio::test]
    async fn a_value_for_another_tenants_zone_is_a_miss() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        let other = saved_tenant(&fx.db.databases).await;
        let proof = record_set("_acme-challenge.auth.acme.example", RecordKind::Txt, "x");

        let added = fx.zones.add_to_record_set(&other, &host(), &proof).await;
        let removed = fx
            .zones
            .remove_from_record_set(&other, &host(), &proof)
            .await;

        assert!(matches!(added, Err(DomainError::NotFound)));
        assert!(removed.is_ok());
        assert!(fx.sets_of(&fx.tenant).await.is_empty());
    }

    /// Replacing another tenant's zone records returns not found, and its
    /// record list is empty for that caller. The owner's original record
    /// remains after the caller also attempts to delete the zone.
    #[tokio::test]
    async fn another_tenants_zone_is_a_miss() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &address(HOST, "203.0.113.7"))
            .await
            .unwrap();
        let other = saved_tenant(&fx.db.databases).await;

        let write = fx
            .zones
            .replace_record_set(&other, &host(), &address(HOST, "198.51.100.1"))
            .await;
        fx.zones.delete_zone(&other, &host()).await.unwrap();

        assert!(matches!(write, Err(DomainError::NotFound)));
        assert!(fx.sets_of(&other).await.is_empty());
        assert_eq!(fx.sets_of(&fx.tenant).await, [address(HOST, "203.0.113.7")]);
    }

    /// A delegated zone is absent from nameserver reads before proof and
    /// after proof is lost. While proved, it appears with its owner, apex,
    /// address record and registration-specific nameservers.
    #[tokio::test]
    async fn a_zone_is_read_only_while_its_name_is_proved() {
        let fx = fixture().await;
        let registered = fx.delegated(&fx.tenant, delegated_domain_row(HOST)).await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &address(HOST, "203.0.113.7"))
            .await
            .unwrap();
        let before = fx.served().await;
        let proved = registration(RegisteredDomainRow {
            id: *registered.id(),
            ..proved_domain_row(HOST)
        });

        fx.registrations.save(&fx.tenant, &proved).await.unwrap();
        let served = fx.served().await;
        let lost = registration(RegisteredDomainRow {
            id: *registered.id(),
            ..lost_domain_row(HOST)
        });
        fx.registrations.save(&fx.tenant, &lost).await.unwrap();
        let after = fx.served().await;

        assert!(before.is_empty());
        assert_proved_zone(&fx, &registered, &served);
        assert!(after.is_empty());
    }

    /// Every change to what a zone answers moves its serial on, even two
    /// within one second, and writing the set it holds already does not.
    #[tokio::test]
    async fn every_change_moves_the_serial_on() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, proved_domain_row(HOST)).await;
        let set = address(HOST, "203.0.113.7");
        let serial = async || fx.served().await[0].zone.serial();
        let opened = serial().await;

        fx.zones
            .replace_record_set(&fx.tenant, &host(), &set)
            .await
            .unwrap();
        let written = serial().await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &set)
            .await
            .unwrap();
        let unchanged = serial().await;
        fx.zones
            .remove_record_set(&fx.tenant, &host(), set.name(), RecordKind::A)
            .await
            .unwrap();

        assert!(written > opened);
        assert_eq!(unchanged, written);
        assert!(serial().await > written);
    }

    /// Releasing the claim, by deleting the registration, closes its zone
    /// and every record in it.
    #[tokio::test]
    async fn releasing_the_claim_closes_the_zone() {
        let fx = fixture().await;
        let registered = fx.delegated(&fx.tenant, proved_domain_row(HOST)).await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &address(HOST, "203.0.113.7"))
            .await
            .unwrap();

        fx.registrations
            .delete(&fx.tenant, registered.id())
            .await
            .unwrap();

        assert!(fx.sets_of(&fx.tenant).await.is_empty());
        assert!(fx.served().await.is_empty());
    }

    /// A handover that moves the claim moves the zone and its records with
    /// it, so the transfer after it finds nothing left to move and the
    /// receiving tenant holds the zone.
    #[tokio::test]
    async fn a_handover_moves_the_zone_with_its_claim() {
        let fx = fixture().await;
        let registered = fx.delegated(&fx.tenant, proved_domain_row(HOST)).await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &address(HOST, "203.0.113.7"))
            .await
            .unwrap();
        let target = saved_tenant(&fx.db.databases).await;

        fx.registrations.save(&target, &registered).await.unwrap();
        fx.registrations
            .delete(&fx.tenant, registered.id())
            .await
            .unwrap();
        fx.zones
            .transfer_zone(&fx.tenant, &target, &host())
            .await
            .unwrap();

        let served = fx.served().await;
        assert!(fx.sets_of(&fx.tenant).await.is_empty());
        assert_eq!(fx.sets_of(&target).await, [address(HOST, "203.0.113.7")]);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].owner, *target);
    }

    /// Nameserver reads include proved zones from both a tenant with a
    /// dedicated database and one using the shared database.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_is_served() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = saved_tenant(&fx.db.databases).await;
        fx.db.databases.register(*apart, own.as_dedicated());
        fx.delegated(&fx.tenant, proved_domain_row(HOST)).await;
        fx.delegated(&apart, proved_domain_row("login.globex.example"))
            .await;

        let mut apexes: Vec<String> = fx
            .served()
            .await
            .iter()
            .map(|held| held.zone.apex().as_str().to_owned())
            .collect();
        apexes.sort();

        assert_eq!(apexes, ["auth.acme.example", "login.globex.example"]);
    }

    /// An invalid stored address makes both the writer's record-set read
    /// and the nameserver's zone load return infrastructure errors.
    #[tokio::test]
    async fn a_value_that_does_not_read_as_its_type_is_refused() {
        let fx = fixture().await;
        fx.delegated(&fx.tenant, proved_domain_row(HOST)).await;
        fx.zones
            .replace_record_set(&fx.tenant, &host(), &address(HOST, "203.0.113.7"))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE dns_records SET record_values = '{not-an-address}'")
            .await;

        let read = fx.zones.record_sets(&fx.tenant, &host()).await;
        let served = fx.reader.load_all_zones().await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        assert!(matches!(served, Err(DomainError::Infrastructure(_))));
    }

    /// Passing one more zone than the cap to the trimming helper returns
    /// exactly the cap and retains the first zone.
    #[test]
    fn a_load_past_the_cap_keeps_the_cap() {
        let read: Vec<ZoneRecord> = (0..=MOST_ZONES_SERVED)
            .map(|index| ZoneRecord {
                hostname: format!("zone-{index}.example"),
                tenant_id: Uuid::nil(),
                nameservers: Vec::new(),
                changed_at: OffsetDateTime::UNIX_EPOCH,
                verified: true,
            })
            .collect();

        let kept = within_the_cap(read);

        assert_eq!(kept.len(), MOST_ZONES_SERVED);
        assert_eq!(kept[0].hostname, "zone-0.example");
    }
}
