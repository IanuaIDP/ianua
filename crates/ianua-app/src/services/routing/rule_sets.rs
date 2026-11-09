//! Holding stages that read classification rules to the tenant's own,
//! wherever a stage is saved: added, reconfigured, or declared in a
//! gateway document.

use ianua_domain::domains::proxy::stages::stage::{StageKind, TenantRules};

use crate::error::{AppError, OrInternal};
use crate::ports::data_classification::ClassificationStore;
use crate::tenancy::ScopedTenant;

/// Refuses `kinds` when one reads classification rules that are not
/// `tenant`'s own. The store is read once, and only when a stage reads
/// rules.
///
/// # Errors
///
/// - `AppError::Domain` when a stage reads another tenant's rules, or
///   reads rules and the tenant has classified nothing.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn ensure_reads_own_rules<'a>(
    store: &dyn ClassificationStore,
    tenant: &ScopedTenant,
    kinds: impl IntoIterator<Item = &'a StageKind>,
) -> Result<(), AppError> {
    let reading: Vec<&StageKind> = kinds
        .into_iter()
        .filter(|kind| kind.rule_set().is_some())
        .collect();
    if reading.is_empty() {
        return Ok(());
    }
    let saved = store.find(tenant).await.or_internal()?;
    let own = match &saved {
        Some(rules) => TenantRules::Classified(rules.id()),
        None => TenantRules::Unclassified,
    };
    reading
        .into_iter()
        .try_for_each(|kind| kind.ensure_reads_own_rules(own))
        .map_err(AppError::from_domain)
}
