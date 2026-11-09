//! Data classification ports.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::classification::ClassificationRuleSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Port the gateway's Redact stage calls to replace a field whose rule
/// says `hash` with a keyed digest of its value.
///
/// Keyed, because the values worth hiding are short and guessable: a plain
/// SHA-256 of a social security number is undone in seconds by hashing
/// every number there is. Keyed per tenant too, so the same value in two
/// tenants' answers digests apart and cannot link the two. The same value
/// in one tenant always digests the same, so an upstream's records can
/// still be matched on it.
pub trait RedactionDigest: Send + Sync {
    /// The digest of `value`, a field's JSON form, as `tenant_id`'s answers
    /// carry it, written as URL-safe base64.
    fn digest(&self, tenant_id: &TenantId, value: &[u8]) -> String;
}

/// Dyn-safe port for persisting and retrieving classification rule sets.
#[async_trait]
pub trait ClassificationStore: Send + Sync + TenantScoped {
    /// Finds the rule set for the tenant.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the store cannot be read.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated rule set.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the rule set cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rule_set: &ClassificationRuleSet<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
