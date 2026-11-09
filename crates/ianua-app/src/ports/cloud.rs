//! Ports for reaching a customer's own cloud account.
//!
//! Four clouds, one shape. The pattern is an abstract factory: a
//! [`CloudProviderRegistry`] resolves a [`CloudProvider`] to a
//! [`CloudProviderFactory`], and that factory produces the capabilities as a
//! set. Because the members only ever come out together, a network discovered
//! in AWS can never be paired with Azure credentials, the consistency is
//! structural rather than something each call site has to remember.
//!
//! # What is deliberately not here
//!
//! Creating the database itself. That already has a port,
//! [`crate::ports::tenant::TenantDatabaseProvisioner`], and it is at the right
//! altitude for a use case: a tenant, an organization, an isolation level. A
//! second per-cloud provisioning port beside it would carry instance classes,
//! engine versions and CLI authentication across the boundary, and no use case
//! in this layer wants to create one RDS instance. The infrastructure factory
//! still builds that member, so the family cannot be mixed, and hands it
//! down to the orchestrator instead of up to here.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::organization::cloud::account::{CloudAccount, CloudIdentity};
use ianua_domain::domains::organization::cloud::credential::{CloudCredential, ExternalId};
use ianua_domain::domains::tenant::provisioning::infrastructure::{
    CloudNetwork, CloudProvider, DeploymentRegion,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

/// Proves a credential opens the account it claims to.
///
/// Asked inside an organization member's request, when they verify a
/// connection. The adapter gives its calls to the cloud a few seconds at most
/// and gives up once they pass, reporting the timeout as
/// `DomainError::Infrastructure`, so a cloud that hangs never holds the
/// request past its deadline.
#[async_trait]
pub trait CredentialVerifier: Send + Sync {
    /// Calls the cheapest identity endpoint the cloud offers and reports whose
    /// account answered.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if the cloud rejected the credential. The
    ///   customer's to fix, a missing external id, a trust policy that does
    ///   not name us, a deleted role.
    /// - [`DomainError::Infrastructure`] if the cloud could not be reached at
    ///   all. Ours to fix, and emphatically not the same answer: telling a
    ///   customer their credentials are wrong because our egress was down
    ///   sends them to rebuild something that was never broken.
    async fn verify(&self, credential: &CloudCredential) -> Result<CloudIdentity, DomainError>;
}

/// Lists the places inside a customer's account a database could live.
///
/// Asked inside an organization member's request, as the connect screen
/// fills its lists. Each call is held to the bound
/// [`CredentialVerifier`] keeps: a few seconds at most, given up once they
/// pass, and the timeout reported as
/// `DomainError::Infrastructure`.
#[async_trait]
pub trait NetworkDiscovery: Send + Sync {
    /// Regions this account has usable networks in.
    ///
    /// # Errors
    ///
    /// As [`CredentialVerifier::verify`].
    async fn regions(
        &self,
        credential: &CloudCredential,
    ) -> Result<Vec<DeploymentRegion>, DomainError>;

    /// Networks in one region, named as the customer named them.
    ///
    /// An empty result is a legitimate answer, not an error: it means the
    /// account has nothing suitable, which is precisely when we offer to build
    /// a network instead.
    ///
    /// # Errors
    ///
    /// As [`CredentialVerifier::verify`].
    async fn networks(
        &self,
        credential: &CloudCredential,
        region: DeploymentRegion,
    ) -> Result<Vec<CloudNetwork>, DomainError>;
}

/// One cloud's capabilities, produced as a set.
///
/// Members are cheap handles over a shared HTTP client, so returning them by
/// value on each call costs an `Arc` clone rather than a connection.
pub trait CloudProviderFactory: Send + Sync {
    /// Which cloud this factory speaks for.
    fn provider(&self) -> CloudProvider;

    /// Proves a credential works, and says whose account it opens.
    fn credential_verifier(&self) -> Arc<dyn CredentialVerifier>;

    /// Lists the places inside that account a database could live.
    fn network_discovery(&self) -> Arc<dyn NetworkDiscovery>;
}

/// Resolves a cloud to the factory that serves it.
///
/// Answers from what the deployment configured at startup and calls out to
/// nothing, so it never waits. The members its factories hand out do call
/// the cloud, and each says how long it may wait.
pub trait CloudProviderRegistry: Send + Sync {
    /// The factory for one cloud.
    ///
    /// # Errors
    ///
    /// [`DomainError::Validation`] if this deployment has no adapter for that
    /// cloud. A customer selecting a provider we have not configured is a
    /// rejected request with a clear reason, never a panic, and never a
    /// silent fallback to a different cloud.
    fn factory(
        &self,
        provider: CloudProvider,
    ) -> Result<Arc<dyn CloudProviderFactory>, DomainError>;

    /// Every cloud this deployment can actually drive.
    ///
    /// What the connect screen offers. Listing a provider we cannot serve
    /// would be an invitation to a dead end.
    fn available(&self) -> Vec<CloudProvider>;
}

/// Persists organizations' cloud connections.
///
/// The external id is passed alongside the aggregate rather than held on it:
/// it exists from the moment a connection is begun, which is before any
/// credential does, and it is never replaced once the customer has embedded it
/// in a trust policy.
#[async_trait]
pub trait CloudAccountStore: Send + Sync {
    /// An organization's connection to one cloud.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] on a storage failure, or if a stored
    /// row cannot be decrypted or decoded.
    async fn find(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<CloudAccount>, DomainError>;

    /// Every connection an organization has made.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    async fn list_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<CloudAccount>, DomainError>;

    /// Inserts or updates a connection.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] if sealing the credential or the write
    /// fails.
    async fn save(
        &self,
        account: &CloudAccount,
        external_id: &ExternalId,
    ) -> Result<(), DomainError>;

    /// The external id generated for a connection.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    async fn external_id(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<ExternalId>, DomainError>;

    /// Removes a connection entirely.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] on a storage failure.
    async fn delete(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<(), DomainError>;
}

/// Generates the shared secret that guards an `AssumeRole`.
///
/// A port rather than a function because it must be cryptographically random,
/// and the domain does not get to reach for an RNG.
pub trait ExternalIdGenerator: Send + Sync {
    /// A fresh, unguessable external id.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] if the system entropy source fails.
    fn generate(&self) -> Result<ExternalId, DomainError>;
}
