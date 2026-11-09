//! Asking the company's "before" rules about a guarded change: what the
//! change would do, by name and value, handed to the rules as their trigger
//! data, and their verdict turned into the change going ahead or a refusal.
//!
//! An admin role reaches people by more than one road: given to a person, to
//! a group, offered in an invitation or at registration, gained by a role
//! they hold, or handed to every new user. Each road asks the same rule
//! through [`ensure_admin_rules_allow`], so none of them goes around it.

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::triggers::before::{GuardedChange, Verdict};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, PrincipalRef};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::ChangeGuard;
use crate::tenancy::ScopedTenant;

/// Lets `change`, described by `fields`, go ahead in `tenant` once the
/// company's rules allow it.
///
/// # Errors
///
/// - `AppError::Forbidden` when a rule refuses it, ends undecided, may not
///   start or does not answer in time.
/// - `AppError::Internal` when the rules cannot be asked.
pub(crate) async fn ensure_rules_allow(
    guard: &dyn ChangeGuard,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    change: GuardedChange,
    fields: &[(&str, String)],
) -> Result<(), AppError> {
    let proposed = proposal(fields).or_internal()?;
    match guard.decide(tenant, auditor, change, proposed).await {
        Ok(Verdict::Allow) => Ok(()),
        Ok(Verdict::Refuse) => Err(AppError::Forbidden(message!(
            "workflows-a-company-rule-refused-this-change",
            "a company rule refused this change"
        ))),
        Err(error) => Err(AppError::from_domain(error)),
    }
}

/// Who an admin role reaches, as a "before admin given" rule is told it.
pub(crate) enum AdminHolder<'a> {
    /// One user, agent or consumer.
    Principal(&'a PrincipalRef),
    /// Everyone in a group and the groups under it.
    Group(&'a GroupId),
    /// Everyone who already holds the role.
    EveryHolder,
    /// Everyone the tenant gains from now on.
    EveryNewUser,
}

impl AdminHolder<'_> {
    /// The holder as the rule reads it.
    fn label(&self) -> String {
        match self {
            Self::Principal(principal) => principal.label(),
            Self::Group(group) => format!("group:{group}"),
            Self::EveryHolder => "every_holder".to_owned(),
            Self::EveryNewUser => "every_new_user".to_owned(),
        }
    }
}

/// Lets `role` reach `holder` in `tenant` once the company's "before admin
/// given" rules allow it. A role that does no admin work is not theirs to
/// decide, so it is let through unasked.
///
/// # Errors
///
/// - `AppError::Forbidden` when a rule refuses it, ends undecided, may not
///   start or does not answer in time; `Internal` when they cannot be asked.
pub(crate) async fn ensure_admin_rules_allow(
    guard: &dyn ChangeGuard,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    role: &Role<ResolvedTenant>,
    holder: AdminHolder<'_>,
) -> Result<(), AppError> {
    if !role.grants_admin_work() {
        return Ok(());
    }
    let fields = [
        ("role", role.id().to_string()),
        ("role_name", role.name().as_str().to_owned()),
        ("holder", holder.label()),
    ];
    ensure_rules_allow(guard, tenant, auditor, GuardedChange::AdminGiven, &fields).await
}

/// The change `fields` describe, as workflow data.
fn proposal(fields: &[(&str, String)]) -> Result<FlowData, DomainError> {
    let entries = fields
        .iter()
        .map(|(name, value)| Ok((FieldName::new(*name)?, FlowData::text(value.clone())?)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    FlowData::map(entries)
}
