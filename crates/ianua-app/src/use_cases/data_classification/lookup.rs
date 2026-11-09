//! Loading the tenant's classification rule set, which every use case here
//! starts with.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::ClassificationRuleId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::data_classification::ClassificationStore;
use crate::tenancy::ScopedTenant;

/// The tenant's saved rule set, or `None` when it has classified nothing
/// yet.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(super) async fn saved_rule_set(
    store: &dyn ClassificationStore,
    tenant: &ScopedTenant,
) -> Result<Option<ClassificationRuleSet<ResolvedTenant>>, AppError> {
    store.find(tenant).await.or_internal()
}

/// The tenant's rule set, or a new empty one made by `by` when it has
/// classified nothing yet.
///
/// The set is made on the first rule, so its absence is a normal state
/// rather than a missing record.
///
/// # Errors
///
/// - `AppError::Forbidden` when a new set is needed and `by` may not
///   change classification rules.
/// - `AppError::Internal` on storage failure.
pub(super) async fn current_rule_set(
    store: &dyn ClassificationStore,
    tenant: &ScopedTenant,
    by: &TenantAuthority,
) -> Result<ClassificationRuleSet<ResolvedTenant>, AppError> {
    match saved_rule_set(store, tenant).await? {
        Some(rule_set) => Ok(rule_set),
        None => ClassificationRuleSet::empty(by).map_err(AppError::from_domain),
    }
}

/// The tenant's saved rule set.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has never classified a field.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_rule_set(
    store: &dyn ClassificationStore,
    tenant: &ScopedTenant,
) -> Result<ClassificationRuleSet<ResolvedTenant>, AppError> {
    saved_rule_set(store, tenant).await?.or_not_found(message!(
        "data_classification-classification-rules-not-found",
        "classification rules not found"
    ))
}

/// The rule in `rule_set` with `rule_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the set has no such rule.
pub(super) fn existing_rule<'a>(
    rule_set: &'a ClassificationRuleSet<ResolvedTenant>,
    rule_id: &ClassificationRuleId,
) -> Result<&'a ClassificationRule, AppError> {
    rule_set
        .rules()
        .iter()
        .find(|rule| rule.id() == rule_id)
        .or_not_found(message!(
            "data_classification-rule-not-found",
            "rule not found"
        ))
}
