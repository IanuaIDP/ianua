//! The claims on hostnames, kept in the platform database for the whole
//! deployment, whichever database the registrations live in.
//!
//! Every call runs as platform work: the claims are platform rows, and a
//! tenant with a database of its own would otherwise be sent to that
//! database, which holds none. Each query names the tenant it is for.
//!
//! The names above and below one are found by the claim's overlap key, its
//! labels in reverse with a leading `*.` set aside, so `login.acme.com` is
//! `com.acme.login`. A name above has a key that is a whole number of
//! labels at the start of it; a name below has a key that starts with it
//! and a dot, so it sorts between the key followed by `.` and the key
//! followed by `/`, the character after the dot.
//!
//! A new registration claims its name in one step: under a lock on its
//! registrable domain, which every name that can overlap it shares, it
//! checks the names at, above and below it and claims in the same
//! transaction. Two tenants claiming `acme.com` and `login.acme.com` at once
//! wait for each other, and the second finds the first. Whether another
//! tenant's claim still holds its name is judged from the claim itself,
//! which keeps when its registration was made, whether it is proved and
//! when its proof was lost, so no tenant's database is read under the lock.

use std::iter;

use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ClaimLifetimes, DomainProof, RegisteredDomain,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::domain::registrations::record::{Claim, ClaimRecord};
use crate::postgres::foundation::errors::Uniqueness;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::{scoped, scoped_holding};

/// What a claim keeps of the registration it is for.
struct ClaimColumns<'a> {
    hostname: &'a str,
    key: String,
    tenant: &'a Uuid,
    domain_id: &'a Uuid,
    verified: bool,
    claimed_at: OffsetDateTime,
    failed_at: Option<OffsetDateTime>,
}

impl<'a> ClaimColumns<'a> {
    /// The claim `domain` holds as `tenant`'s.
    fn of(tenant: &'a TenantId, domain: &'a RegisteredDomain<ResolvedTenant>) -> Self {
        let (verified, failed_at) = proof_columns(domain.proof());
        Self {
            hostname: domain.domain().as_str(),
            key: overlap_key(domain.domain()),
            tenant: tenant.as_uuid(),
            domain_id: domain.id().as_uuid(),
            verified,
            claimed_at: domain.created_at(),
            failed_at,
        }
    }
}

/// Whether `proof` stands now, and when it was lost if it was.
fn proof_columns(proof: DomainProof) -> (bool, Option<OffsetDateTime>) {
    match proof {
        DomainProof::Unproved => (false, None),
        DomainProof::Verified { .. } => (true, None),
        DomainProof::Lost { failed_at, .. } => (false, Some(failed_at)),
    }
}

/// The moments a claim still holds its name after at one time: one never
/// proved holds it while it was made after `unproved_after`, and one whose
/// proof was lost while it was lost after `lost_after`. A proved claim
/// always holds it.
pub(super) struct StillHeld {
    unproved_after: OffsetDateTime,
    lost_after: OffsetDateTime,
}

impl StillHeld {
    /// The cutoffs of `now` under `lifetimes`, as
    /// [`RegisteredDomain::has_lapsed`] judges a claim.
    pub(super) fn at(now: OffsetDateTime, lifetimes: &ClaimLifetimes) -> Self {
        Self {
            unproved_after: now.saturating_sub(lifetimes.unproved.duration()),
            lost_after: now.saturating_sub(lifetimes.failed_grace.duration()),
        }
    }
}

/// Claims the name of `domain` for it, as `tenant`'s, with whether it is
/// proved, so the nameservers answer for it only once it is: refused when
/// another registration holds the name.
pub(super) async fn claim(
    databases: &Databases,
    tenant: &TenantId,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<Uniqueness, DomainError> {
    let c = ClaimColumns::of(tenant, domain);
    let written = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file!(
            "queries/domain_claims/claim.sql",
            c.hostname,
            c.key,
            c.tenant,
            c.domain_id,
            c.verified,
            c.claimed_at,
            c.failed_at
        )
        .execute(connection)
        .await
    })
    .await?;
    match written.rows_affected() {
        0 => Ok(Uniqueness::Taken),
        _ => Ok(Uniqueness::Kept),
    }
}

/// Claims the name of the new registration `domain` for `tenant`, in one
/// transaction under the lock on its registrable domain: refused when
/// another registration holds the name itself, or another tenant's claim
/// still held by `held` sits at, above or below it.
///
/// Every name that can overlap another shares its registrable domain, so
/// two claims that could clash wait for each other, and the second checks
/// once the first is kept or dropped. Inside a unit of work the lock holds
/// until the unit settles, with the claim it allowed.
pub(super) async fn claim_new(
    databases: &Databases,
    tenant: &TenantId,
    domain: &RegisteredDomain<ResolvedTenant>,
    held: &StillHeld,
) -> Result<Uniqueness, DomainError> {
    let c = ClaimColumns::of(tenant, domain);
    let site = registrable(domain.domain());
    let at_and_above = keys_at_and_above(&c.key);
    let (from, until) = (format!("{}.", c.key), format!("{}/", c.key));
    let written = scoped_holding(databases, RowScope::Platform, async |connection| {
        hold_site(connection, &site).await?;
        sqlx::query_file!(
            "queries/domain_claims/claim_new.sql",
            c.hostname,
            c.key,
            c.tenant,
            c.domain_id,
            c.verified,
            c.claimed_at,
            c.failed_at,
            &at_and_above as &[String],
            from,
            until,
            held.unproved_after,
            held.lost_after
        )
        .execute(connection)
        .await
    })
    .await?;
    Ok(uniqueness(written.rows_affected()))
}

/// Locks the registrable domain until the surrounding transaction settles.
async fn hold_site(connection: &mut PgConnection, site: &str) -> Result<(), sqlx::Error> {
    sqlx::query_file_scalar!("queries/domain_claims/hold_site.sql", site)
        .fetch_one(connection)
        .await
        .map(|_| ())
}

/// Interprets whether the conditional claim write inserted or updated a row.
fn uniqueness(rows: u64) -> Uniqueness {
    match rows {
        0 => Uniqueness::Taken,
        _ => Uniqueness::Kept,
    }
}

/// The registrable domain `name` is claimed under, a leading `*.` set
/// aside: `acme.com` for `login.acme.com` and `*.acme.com`. A name with
/// none, a public suffix itself, which a registration never is, falls back
/// to its last label, which every name under it shares.
fn registrable(name: &DomainName) -> String {
    let bare = name.as_str().strip_prefix("*.").unwrap_or(name.as_str());
    psl::domain_str(bare)
        .or_else(|| bare.rsplit('.').next())
        .unwrap_or(bare)
        .to_owned()
}

/// Releases the name the registration `id` of `tenant` holds, and the
/// certificates that serve it.
pub(super) async fn release(
    databases: &Databases,
    tenant: &TenantId,
    id: &DomainId,
) -> Result<(), DomainError> {
    scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file!(
            "queries/domain_claims/release.sql",
            tenant.as_uuid(),
            id.as_uuid()
        )
        .execute(connection)
        .await
        .map(|_| ())
    })
    .await
}

/// The claim on `hostname`, if anyone holds it.
pub(super) async fn of_hostname(
    databases: &Databases,
    hostname: &DomainName,
) -> Result<Option<Claim>, DomainError> {
    let record = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_as!(
            ClaimRecord,
            "queries/domain_claims/of_hostname.sql",
            hostname.as_str()
        )
        .fetch_optional(connection)
        .await
    })
    .await?;
    record.map(ClaimRecord::into_claim).transpose()
}

/// The claim the registration `id` holds, if it holds one.
pub(super) async fn of_domain(
    databases: &Databases,
    id: &DomainId,
) -> Result<Option<Claim>, DomainError> {
    let record = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_as!(
            ClaimRecord,
            "queries/domain_claims/of_domain.sql",
            id.as_uuid()
        )
        .fetch_optional(connection)
        .await
    })
    .await?;
    record.map(ClaimRecord::into_claim).transpose()
}

/// Every claim on a name at, above or below `name`.
pub(super) async fn overlapping(
    databases: &Databases,
    name: &DomainName,
) -> Result<Vec<Claim>, DomainError> {
    let key = overlap_key(name);
    let at_and_above = keys_at_and_above(&key);
    let (from, until) = (format!("{key}."), format!("{key}/"));
    let records = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_as!(
            ClaimRecord,
            "queries/domain_claims/overlapping.sql",
            &at_and_above as &[String],
            from,
            until
        )
        .fetch_all(connection)
        .await
    })
    .await?;
    records.into_iter().map(ClaimRecord::into_claim).collect()
}

/// The key `name` is claimed under: its labels in reverse, a leading `*.`
/// set aside.
fn overlap_key(name: &DomainName) -> String {
    let bare = name.as_str().strip_prefix("*.").unwrap_or(name.as_str());
    bare.rsplit('.').collect::<Vec<_>>().join(".")
}

/// `key` and the keys of every name above it: `com.acme.login`,
/// `com.acme` and `com`.
fn keys_at_and_above(key: &str) -> Vec<String> {
    key.match_indices('.')
        .filter_map(|(at, _)| key.get(..at))
        .map(str::to_owned)
        .chain(iter::once(key.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> DomainName {
        DomainName::new(text).unwrap()
    }

    /// A name is keyed by its labels in reverse, and a wildcard by the name
    /// it stands in front of.
    #[test]
    fn a_name_is_keyed_by_its_labels_in_reverse() {
        assert_eq!(overlap_key(&name("login.acme.com")), "com.acme.login");
        assert_eq!(overlap_key(&name("*.acme.com")), "com.acme");
    }

    /// Names that can overlap share the registrable domain their lock is
    /// taken on, a wildcard by the name it stands in front of, and a name
    /// under a public suffix of two labels by the name registered under it.
    #[test]
    fn overlapping_names_share_one_lock() {
        assert_eq!(registrable(&name("acme.com")), "acme.com");
        assert_eq!(registrable(&name("login.acme.com")), "acme.com");
        assert_eq!(registrable(&name("*.login.acme.com")), "acme.com");
        assert_eq!(registrable(&name("eu.shop.acme.co.uk")), "acme.co.uk");
    }

    /// The names above one are the whole labels it ends in, and never a
    /// name that merely ends in the same letters.
    #[test]
    fn the_names_above_are_whole_labels() {
        let keys = keys_at_and_above("com.acme.login");

        assert_eq!(keys, ["com", "com.acme", "com.acme.login"]);
        assert!(!keys.contains(&overlap_key(&name("blogin.acme.com"))));
    }
}
