//! Reading DNS and managing the zones Ianua hosts.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, HeldZone, RecordKind, RecordName, RecordSet, TxtValue,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

/// Dyn-safe port for verifying DNS records (TXT and CNAME).
///
/// Asked inside a tenant's request, when they press verify. The adapter
/// gives each lookup a few seconds at most, retries included, and reports a
/// resolver that does not answer in time as `DomainError::Infrastructure`,
/// so a name server that hangs never holds the request or a worker.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Checks whether `name` has a TXT record whose value equals `expected`.
    ///
    /// Looks up `name` exactly as given. The caller builds both, for example
    /// `_ianua-verify.{domain}` and `ianua-verify={token}`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn verify_txt_record(
        &self,
        name: &RecordName,
        expected: &TxtValue,
    ) -> Result<bool, DomainError>;

    /// Verifies that a CNAME record for the domain points to the expected target.
    ///
    /// Used to check that a custom Auth domain has a CNAME pointing
    /// to the tenant's subdomain (e.g. `{slug}.ianua.cloud`).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn verify_cname(
        &self,
        domain: &DomainName,
        expected_target: &DomainName,
    ) -> Result<bool, DomainError>;

    /// Whether `domain` has been delegated to `expected_nameservers`.
    ///
    /// What proves ownership for a delegated domain, and it proves rather
    /// more than a `TXT` record does: writing an `NS` record that hands us a
    /// name is only possible for whoever runs the parent zone, and unlike a
    /// token it also *does* something, the delegation that makes the name
    /// ours to answer is the same act that demonstrates the right to give it.
    ///
    /// Every expected nameserver must be present. A partial delegation
    /// resolves intermittently, which is worse than not resolving at all
    /// because it looks like a flaky service rather than a setup mistake.
    ///
    /// Read from the parent zone's own referral, never from a recursive
    /// answer. A recursive resolver asks the delegated zone itself for its
    /// `NS` records, and that zone is ours: it would answer with the names
    /// of whichever registration holds the zone now, not with the names the
    /// parent's operator wrote. Our nameservers also answer nothing for a
    /// zone not yet proved, so a recursive lookup could never prove one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn verify_delegation(
        &self,
        domain: &DomainName,
        expected_nameservers: &[DomainName],
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for the DNS zones tenants have delegated to us.
///
/// A tenant delegates one hostname with a single `NS` record. From then on we
/// are authoritative for that name and write its records ourselves, which is
/// what turns "the tenant must get DNS right" into "we get DNS right".
///
/// Deliberately says nothing about who answers the queries. Whether that is
/// our own nameservers or a rented provider is a decision behind this port,
/// and swapping it should touch one adapter and nothing above it.
///
/// Every method carries the owning tenant. A hostname is globally unique, so
/// it alone would be enough to find a zone, and that is exactly the problem:
/// it would also be enough to write into somebody else's. The tenant is the
/// authorization, not the lookup key, and an operation against a zone the
/// tenant does not own is a miss rather than a write.
///
/// Called inside a tenant's request, as they add, accept or remove a domain
/// or change its records. Where the zones live with a provider, the adapter
/// gives each call to it a few seconds at most, connecting and in all, and
/// reports one that does not answer in time as
/// `DomainError::Infrastructure`, so a provider that hangs never holds the
/// request past its deadline.
#[async_trait]
pub trait DnsZoneWriter: Send + Sync {
    /// Creates a zone for `hostname` and returns the nameservers a tenant
    /// must delegate to.
    ///
    /// `label` is the registration's own, and the returned nameservers are
    /// named after it, they belong to this registration and no other. That is
    /// what lets a delegation prove *whose* it is: without it, every tenant is
    /// told to point at the same names, and a name still delegated after its
    /// registration was deleted would verify for whoever claimed it next.
    ///
    /// The zone answers with the same names, because a resolver asking a zone
    /// for its `NS` records is answered by the zone rather than by its
    /// parent's referral.
    ///
    /// Idempotent for the owner: creating a zone that exists returns the same
    /// nameservers rather than failing, so a retried registration is not a
    /// dead end.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` if another tenant already holds the
    /// zone, and `DomainError::Infrastructure` if it cannot be created.
    async fn create_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        label: &DelegationLabel,
    ) -> Result<Vec<DomainName>, DomainError>;

    /// Replaces every answer a zone gives to one question.
    ///
    /// The set is the unit of change because it is the unit of resolution: a
    /// resolver asks for a name and a type, caches what comes back, and
    /// replaces it whole. Writing one value at a time would let a zone hold a
    /// half-updated set that no cache anywhere would ever reflect.
    ///
    /// Idempotent. Writing the set a zone already holds changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::NotFound` if the tenant holds no such zone, and
    /// `DomainError::Infrastructure` if the write fails.
    async fn replace_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        set: &RecordSet,
    ) -> Result<(), DomainError>;

    /// Adds the values of `addition` to the answers a zone gives for its
    /// name and type, beside the values held there, as
    /// [`RecordSet::merged_with`] does.
    ///
    /// For a set whose values belong to different writers, such as two
    /// certificate orders proving `auth.acme.com` and `*.auth.acme.com`
    /// under one `_acme-challenge` name: replacing the set would drop the
    /// other writer's value. Changes to one zone's sets run one after
    /// another, so two writers adding at once both keep their value.
    ///
    /// Idempotent. Adding a value the set holds changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::NotFound` if the tenant holds no such zone, and
    /// `DomainError::Infrastructure` if the write fails or the merged set
    /// breaks a rule a set keeps.
    async fn add_to_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        addition: &RecordSet,
    ) -> Result<(), DomainError>;

    /// Takes the values of `removal` out of the answers a zone gives for its
    /// name and type, leaving any other value, and removes the set once
    /// none is left.
    ///
    /// A value or a zone that is not there is not an error, as with
    /// [`remove_record_set`](Self::remove_record_set).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the removal fails.
    async fn remove_from_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        removal: &RecordSet,
    ) -> Result<(), DomainError>;

    /// Removes every answer to one question.
    ///
    /// Removing a set that is not there is not an error, the caller wanted
    /// the zone to stop answering, and it does not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the removal fails.
    async fn remove_record_set(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
        name: &RecordName,
        kind: RecordKind,
    ) -> Result<(), DomainError>;

    /// Every set a zone answers with, ordered by name and then type.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn record_sets(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<Vec<RecordSet>, DomainError>;

    /// Deletes a zone and everything in it.
    ///
    /// Called when a tenant removes a delegated domain. The `NS` record at
    /// their end is theirs to withdraw; ours is to stop answering.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the deletion fails.
    async fn delete_zone(
        &self,
        tenant_id: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError>;

    /// Moves a zone's ownership without touching what it answers.
    ///
    /// Follows a domain moved between tenants. Deleting and re-creating would
    /// drop the records with it, taking a live hostname off the air for as
    /// long as the gap lasts; the delegation the tenant wrote does not care
    /// which of our tenants holds the zone, so neither should this.
    ///
    /// Doing nothing when `from` does not hold the zone is deliberate: a
    /// tenant-managed domain has no zone to move, and that is the common
    /// case rather than an error.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the move fails.
    async fn transfer_zone(
        &self,
        from: &TenantId,
        to: &TenantId,
        hostname: &DomainName,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for reading every zone the nameservers may answer for.
///
/// Deliberately not tenant-scoped, and deliberately separate from
/// [`DnsZoneWriter`]. A resolver arrives with a name and nothing else, no
/// session, no tenant, no way to be asked which one it belongs to, so the
/// read path the nameservers use cannot be the write path the control plane
/// uses. Keeping them apart also keeps the nameservers incapable of changing
/// a zone, which is what they should be.
///
/// Read by the nameservers on a timer, never inside a query: a load that
/// is slow or fails leaves the catalog loaded before it answering.
#[async_trait]
pub trait DnsZoneReader: Send + Sync {
    /// Every zone whose delegation was proved, with everything it answers
    /// with, the tenant holding it and its standing.
    ///
    /// A store may leave unproven zones out, since none of them is ever
    /// served, and may cap how many it loads; which of the zones it gives
    /// answer is still the domain's decision, made by `ZoneCatalog::new`.
    ///
    /// Loaded whole. A nameserver holds the result in memory and replaces it
    /// wholesale, because answering half of one version and half of another
    /// is worse than answering a version that is a few seconds old.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the zones cannot be read.
    async fn load_all_zones(&self) -> Result<Vec<HeldZone>, DomainError>;
}
