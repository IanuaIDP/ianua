//! Loading a tenant's clearance rules, and saving them after one change
//! with the record of it.

use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::ClearanceRuleStore;
use crate::tenancy::ScopedTenant;

/// The tenant's clearance rules, or none when nobody wrote one.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure, or a stored set that breaks
///   its rules.
pub(super) async fn current_rules(
    store: &dyn ClearanceRuleStore,
    tenant: &ScopedTenant,
) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
    let stored = store.load(tenant).await.or_internal()?;
    Ok(stored.unwrap_or_else(ClearanceRules::none))
}

/// The tenant's rules after `change`, saved, with what they raised recorded
/// as done by `editor` once they are.
///
/// # Errors
///
/// - The errors of `change`, after which nothing is saved or recorded.
/// - `AppError::Internal` when the rules cannot be read or written, or the
///   change cannot be recorded.
pub(super) async fn saved_change(
    store: &dyn ClearanceRuleStore,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    editor: &ActorRef,
    change: impl FnOnce(&mut ClearanceRules<ResolvedTenant>) -> Result<(), AppError>,
) -> Result<ClearanceRules<ResolvedTenant>, AppError> {
    let mut rules = current_rules(store, tenant).await?;
    change(&mut rules)?;
    store.save(tenant, &rules).await.or_internal()?;
    auditor
        .dispatch_by(editor, rules.take_events(tenant))
        .await
        .or_internal()?;
    Ok(rules)
}
