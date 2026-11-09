//! What an agent may reach: its compiled intent, the relationships and
//! grants on resources, and the task templates it starts from.

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{
    CapabilitySet, Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::domains::agents::authority::intent::{CompiledIntent, IntentStatement};
use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, TaskTemplateId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for the task templates people propose and approve.
#[async_trait]
pub trait TaskTemplateStore: Send + Sync + TenantScoped {
    /// Inserts or updates a template.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &TaskTemplate<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds a template by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TaskTemplateId,
    ) -> Result<Option<TaskTemplate<ResolvedTenant>>, DomainError>;

    /// Every template in the tenant, newest first, retired ones included.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<TaskTemplate<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for compiling a declared intent into a narrowed scope.
///
/// Runs once at grant, exchange or template proposal, never in the proxy hot
/// path. The returned scope is the intersection of the requested capabilities
/// and the action-classes the intent implies; the digest fingerprints the
/// intent for out-of-band drift monitoring. Intent may only *attenuate*: the
/// application re-checks that the compiled scope is a subset of what was
/// requested.
///
/// Those are requests a person is waiting on. A compiler that asks an
/// [`Embedder`] holds itself to the embedder's bound, a few seconds, and
/// reports a backend that does not answer in time as
/// `DomainError::Infrastructure`. It never falls back to a wider scope.
#[async_trait]
pub trait IntentCompiler: Send + Sync {
    /// Narrows `requested` to the scope `intent` implies, returning it with a
    /// digest of the intent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the compiler backend fails.
    async fn compile(
        &self,
        intent: &IntentStatement,
        requested: &CapabilitySet,
    ) -> Result<CompiledIntent, DomainError>;
}

/// Dyn-safe port for resolving ReBAC relationships.
///
/// The Postgres adapter reads the grants [`ResourceGrantStore`] writes and
/// matches a relation exactly: nothing records that one relation implies
/// another, so holding `owner` does not answer a question about `reader`.
/// Group membership is not resolved either (a relationship engine such as
/// OpenFGA or SpiceDB could sit behind this port for both). The port
/// answers "does `subject` have `relation` on `object`?" Deny-by-default:
/// a missing or unknown relationship returns `false`.
/// The graph is also the **source of truth for resource authority**: it is what
/// delegation consults to decide whether a caller may hand a resource
/// capability to an agent. The subject is therefore any principal, not only an
/// agent. A person's grants have to be recordable for that question to have an
/// answer.
#[async_trait]
pub trait RelationshipResolver: Send + Sync + TenantScoped {
    /// Whether `subject` has `relation` on `object` per the relationship graph.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the relationship backend fails.
    async fn check(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        relation: &Relation,
        object: &ResourceRef,
    ) -> Result<bool, DomainError>;

    /// The subset of `wanted` that `subject` actually holds.
    ///
    /// Delegation builds its resource ceiling from this. Answering in one call
    /// keeps a grant of several resources from fanning out into a query each.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the relationship backend fails.
    async fn held_subset(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError>;
}

/// Dyn-safe port for writing resource grants into the relationship graph.
///
/// Split from [`RelationshipResolver`] so the read path a decision depends on
/// cannot accidentally acquire the ability to widen itself.
#[async_trait]
pub trait ResourceGrantStore: Send + Sync + TenantScoped {
    /// Records that `subject` holds `capability`, attributing it to `granted_by`.
    ///
    /// Idempotent: re-granting what a subject already holds is not an error.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn grant(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
        granted_by: &PrincipalRef,
    ) -> Result<(), DomainError>;

    /// Removes a resource grant. Removing one that does not exist is not an error.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
    ) -> Result<(), DomainError>;
}
