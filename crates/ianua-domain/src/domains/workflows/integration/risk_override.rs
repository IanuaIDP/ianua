//! A tenant's own view of how risky an integration's operation is.
//!
//! An integration declares what kind of action each of its operations is,
//! and the domain cannot check that it told the truth. A tenant may know
//! better. Say "update row" in its finance sheet moves money. The tenant
//! then raises the operation's class for itself.
//!
//! It can only raise it. The class a workflow sees, through
//! [`TenantOperation`], is the stricter of the two. So no override makes an
//! operation look safer than its integration says.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    OperationRiskOverrideRemoved, OperationRiskRaised, RiskOverrideRef,
};
use crate::domains::workflows::integration::{IntegrationKey, OperationKey, OperationSpec};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{DeclaredAction, Human, OperationRiskOverrideId};

/// An integration's operation as one tenant treats it: the catalog's spec,
/// raised by every override the tenant set for it.
///
/// A workflow is published against this type, and every action runs
/// against it. A workflow is never handed the catalog's spec directly, so
/// the tenant's raised view cannot be left out by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOperation(OperationSpec);

impl TenantOperation {
    /// `spec` as the tenant treats it, raised by each of `overrides` that
    /// names its operation. A tenant that raised nothing passes none.
    #[must_use]
    pub fn of<T: TenantScope>(spec: OperationSpec, overrides: &[OperationRiskOverride<T>]) -> Self {
        Self(
            overrides
                .iter()
                .fold(spec, |spec, raised| raised.apply_to(&spec)),
        )
    }

    /// The operation as the tenant treats it.
    #[must_use]
    pub fn spec(&self) -> &OperationSpec {
        &self.0
    }
}

/// The values a tenant raises an operation's class with.
pub struct RaiseRiskParams {
    /// The integration offering the operation.
    pub integration: IntegrationKey,
    /// The catalogue action whose risk the tenant intends to raise.
    pub operation: OperationKey,
    /// What the tenant treats it as: a high-risk class, or undeclared.
    pub effect: DeclaredAction,
}

/// An override as stored.
pub struct OperationRiskOverrideRow {
    /// The persisted identity used to update or remove this tenant risk declaration.
    pub id: OperationRiskOverrideId,
    /// The integration offering the operation.
    pub integration: IntegrationKey,
    /// The catalogue action constrained by the stored risk declaration.
    pub operation: OperationKey,
    /// What the tenant treats it as.
    pub effect: DeclaredAction,
    /// The person who last raised it.
    pub raised_by: Human,
    /// When it was first set.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A tenant's raised view of how risky one integration operation is.
#[derive(Debug, Clone)]
pub struct OperationRiskOverride<T: TenantScope> {
    id: OperationRiskOverrideId,
    integration: IntegrationKey,
    operation: OperationKey,
    effect: DeclaredAction,
    raised_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> OperationRiskOverride<T> {
    /// Raises an operation's class for the tenant. Raises
    /// `workflows.operation_risk_raised`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change workflows.
    /// - [`DomainError::Validation`] when `effect` is a class that raises
    ///   nothing. Only a high-risk class, or undeclared, outranks what an
    ///   integration may declare.
    pub fn raise(params: RaiseRiskParams, by: &WorkflowControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        ensure_raises(params.effect)?;
        let now = crate::shared::clock::now();
        let mut risk = Self {
            id: OperationRiskOverrideId::new(),
            integration: params.integration,
            operation: params.operation,
            effect: params.effect,
            raised_by: by.by().clone(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        risk.raise_effect();
        Ok(risk)
    }

    /// Rebuilds an override from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds a class that
    ///   raises nothing.
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was set.
    pub fn reconstitute(row: OperationRiskOverrideRow) -> Result<Self, DomainError> {
        RowCheck::of("operation risk override")
            .holds(
                ensure_raises(row.effect).is_ok(),
                "a class that raises nothing",
            )
            .in_order(row.created_at, row.updated_at, "changed before it was set")
            .finish()?;
        Ok(Self {
            id: row.id,
            integration: row.integration,
            operation: row.operation,
            effect: row.effect,
            raised_by: row.raised_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// `by` sets what the tenant treats the operation as. Raises
    /// `workflows.operation_risk_raised`, as raising it the first time
    /// does.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change workflows.
    /// - [`DomainError::Validation`] when `effect` raises nothing.
    pub fn change(
        &mut self,
        by: &WorkflowControl<'_>,
        effect: DeclaredAction,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        ensure_raises(effect)?;
        self.effect = effect;
        self.raised_by = by.by().clone();
        self.updated_at = crate::shared::clock::now();
        self.raise_effect();
        Ok(())
    }

    /// Raises `workflows.operation_risk_raised` with what the operation
    /// counts as now.
    fn raise_effect(&mut self) {
        self.raised.raise(OperationRiskRaised {
            operation: self.risk_ref(),
            effect: self.effect,
            occurred_at: self.updated_at,
        });
    }

    /// `by` removes the override, and the operation goes back to the class
    /// its integration declares. Raises
    /// `workflows.operation_risk_override_removed`, taken once storage has
    /// removed it.
    ///
    /// Removing one lowers an operation's risk, so a step that needed an
    /// approval may stop needing one. Only someone with full control of
    /// workflows may do it. Sam may edit workflows. Without this, he removes
    /// the override that makes "update row" a payment, and his workflow moves
    /// money with no one approving.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` does not have full control of
    ///   workflows.
    pub fn remove(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Manage)?;
        self.raised.raise(OperationRiskOverrideRemoved {
            operation: self.risk_ref(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// The operation this override raises, as the audit trail names it.
    fn risk_ref(&self) -> RiskOverrideRef {
        RiskOverrideRef {
            override_id: self.id,
            integration: self.integration.clone(),
            operation: self.operation.clone(),
        }
    }

    /// `spec` raised to this override when it is the operation this
    /// override is for. Any other spec comes back unchanged.
    fn apply_to(&self, spec: &OperationSpec) -> OperationSpec {
        if spec.integration() != &self.integration || spec.operation() != &self.operation {
            return spec.clone();
        }
        spec.at_least(self.effect)
    }

    /// The stable identity used to update or remove this tenant risk declaration.
    #[must_use]
    pub fn id(&self) -> &OperationRiskOverrideId {
        &self.id
    }

    /// The integration offering the operation.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The catalogue action whose effective risk this declaration raises.
    #[must_use]
    pub fn operation(&self) -> &OperationKey {
        &self.operation
    }

    /// What the tenant treats it as.
    #[must_use]
    pub fn effect(&self) -> DeclaredAction {
        self.effect
    }

    /// The person who last raised it.
    #[must_use]
    pub fn raised_by(&self) -> &Human {
        &self.raised_by
    }
}

impl<T: TenantScope> Raises for OperationRiskOverride<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for OperationRiskOverride<T> {
    type Id = OperationRiskOverrideId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Refuses a class that cannot raise anything an integration declares.
///
/// A class that is not high-risk ranks with every other such class. Of two
/// equal ranks, the integration's own wins.
fn ensure_raises(effect: DeclaredAction) -> Result<(), DomainError> {
    if !effect.may_be_high_risk() {
        return Err(DomainError::invalid(message!(
            "workflows-only-a-high-risk-class-or",
            "only a high-risk class, or undeclared, raises how risky an operation is"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::execution::tests::fixtures::managing;
    use crate::domains::workflows::integration::{AccountNeed, OperationSpecParams};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{ActionClass, HumanAccount, PersonKey, TenantId, UserId};

    fn admin() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("admin@corp.test").unwrap(),
        )
    }

    fn update_row(effect: DeclaredAction) -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("google-sheets").unwrap(),
            operation: OperationKey::new("update-row").unwrap(),
            inputs: Vec::new(),
            effect,
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// A workflow viewer cannot raise an operation's risk. An editor cannot
    /// remove an override, while someone with full workflow control can.
    #[test]
    fn changing_risk_overrides_needs_the_right_for_it() {
        let sam = admin();
        let viewing = crate::domains::workflows::execution::tests::fixtures::viewing(&sam);
        let raised = OperationRiskOverride::<ResolvedTenant>::raise(
            RaiseRiskParams {
                integration: IntegrationKey::new("google-sheets").unwrap(),
                operation: OperationKey::new("update-row").unwrap(),
                effect: FINANCIAL,
            },
            &viewing,
        );
        let mut finance = raised_to(FINANCIAL).unwrap();
        let editor = WorkflowControl::new(assumed_authority(
            &sam,
            TenantId::new(),
            &[SystemPermission::Workflows(WorkflowAction::Update)],
            &[],
        ));

        assert!(matches!(raised, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            finance.remove(&editor),
            Err(DomainError::Forbidden(_))
        ));
        assert!(finance.remove(&managing(&sam)).is_ok());
    }

    /// Ann raises "update row" to financial. The raise is recorded with
    /// what it counts as now.
    #[test]
    fn raising_raises_workflows_operation_risk_raised() {
        let mut finance = raised_to(FINANCIAL).unwrap();

        let events = raised(&mut finance);

        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type().to_string())
                .collect::<Vec<_>>(),
            ["workflows.operation_risk_raised"]
        );
        assert_eq!(events[0].payload().get("effect"), Some(FINANCIAL.as_str()));
    }

    /// Ann changes "update row" from financial to undeclared. The change is
    /// recorded the way the first raise was, with the new class.
    #[test]
    fn changing_raises_workflows_operation_risk_raised_again() {
        let mut finance = raised_to(FINANCIAL).unwrap();
        raised_names(&mut finance);

        finance
            .change(&managing(&admin()), DeclaredAction::Undeclared)
            .unwrap();

        let events = raised(&mut finance);
        assert_eq!(
            events[0].event_type().to_string(),
            "workflows.operation_risk_raised"
        );
        assert_eq!(
            events[0].payload().get("effect"),
            Some(DeclaredAction::Undeclared.as_str())
        );
    }

    /// Ann removes the override on "update row". The removal is raised.
    #[test]
    fn removing_raises_workflows_operation_risk_override_removed() {
        let mut finance = raised_to(FINANCIAL).unwrap();
        raised_names(&mut finance);

        finance.remove(&managing(&admin())).unwrap();

        assert_eq!(
            raised_names(&mut finance),
            ["workflows.operation_risk_override_removed"]
        );
    }

    /// Changing a financial override to plain write and removing it with only
    /// workflow editing rights both fail without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let sam = admin();
        let mut finance = raised_to(FINANCIAL).unwrap();
        raised_names(&mut finance);
        let editor = WorkflowControl::new(assumed_authority(
            &sam,
            TenantId::new(),
            &[SystemPermission::Workflows(WorkflowAction::Update)],
            &[],
        ));

        let changed = finance.change(&managing(&sam), WRITE);
        let removed = finance.remove(&editor);

        assert!(changed.is_err());
        assert!(removed.is_err());
        assert!(raised_names(&mut finance).is_empty());
    }

    /// The financial override is read back from storage. Loading it is no
    /// change, so it has raised nothing.
    #[test]
    fn an_override_read_back_from_storage_has_raised_nothing() {
        let finance = raised_to(FINANCIAL).unwrap();
        let row = OperationRiskOverrideRow {
            id: finance.id,
            integration: finance.integration.clone(),
            operation: finance.operation.clone(),
            effect: FINANCIAL,
            raised_by: finance.raised_by.clone(),
            created_at: finance.created_at,
            updated_at: finance.updated_at,
        };

        let mut stored = OperationRiskOverride::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    fn raised_to(
        effect: DeclaredAction,
    ) -> Result<OperationRiskOverride<ResolvedTenant>, DomainError> {
        OperationRiskOverride::raise(
            RaiseRiskParams {
                integration: IntegrationKey::new("google-sheets").unwrap(),
                operation: OperationKey::new("update-row").unwrap(),
                effect,
            },
            &managing(&admin()),
        )
    }

    const WRITE: DeclaredAction = DeclaredAction::Declared(ActionClass::Write);
    const FINANCIAL: DeclaredAction = DeclaredAction::Declared(ActionClass::Financial);
    const DELETE: DeclaredAction = DeclaredAction::Declared(ActionClass::Delete);

    /// Google Sheets declares "update row" as a write. A tenant whose sheet
    /// moves money raises it to financial, and the operation then counts
    /// as financial.
    #[test]
    fn an_override_raises_the_operation_it_names() {
        let finance = raised_to(FINANCIAL).unwrap();

        assert_eq!(finance.apply_to(&update_row(WRITE)).effect(), FINANCIAL);
    }

    /// A financial override on an operation declared as delete leaves it a
    /// delete. On an undeclared one it stays undeclared. An undeclared
    /// override turns a delete into undeclared, the strictest class.
    #[test]
    fn an_override_never_lowers_or_swaps_a_class() {
        let finance = raised_to(FINANCIAL).unwrap();
        let undeclared = raised_to(DeclaredAction::Undeclared).unwrap();

        assert_eq!(finance.apply_to(&update_row(DELETE)).effect(), DELETE);
        assert_eq!(
            finance
                .apply_to(&update_row(DeclaredAction::Undeclared))
                .effect(),
            DeclaredAction::Undeclared
        );
        assert_eq!(
            undeclared.apply_to(&update_row(DELETE)).effect(),
            DeclaredAction::Undeclared
        );
    }

    /// A financial override on "update row" is applied to "read rows" of
    /// the same integration. "Read rows" comes back unchanged.
    #[test]
    fn an_override_leaves_other_operations_alone() {
        let finance = raised_to(FINANCIAL).unwrap();
        let other = OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("google-sheets").unwrap(),
            operation: OperationKey::new("read-rows").unwrap(),
            inputs: Vec::new(),
            effect: DeclaredAction::Declared(ActionClass::Read),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap();

        assert_eq!(finance.apply_to(&other), other);
    }

    /// An override to plain write is refused, since write outranks nothing.
    /// Changing a financial override to write is refused too, and it stays
    /// financial.
    #[test]
    fn a_class_that_raises_nothing_is_refused() {
        let mut finance = raised_to(FINANCIAL).unwrap();

        assert!(matches!(raised_to(WRITE), Err(DomainError::Validation(_))));
        assert!(matches!(
            finance.change(&managing(&admin()), WRITE),
            Err(DomainError::Validation(_))
        ));
        assert_eq!(finance.effect(), FINANCIAL);
    }

    /// A stored override holds plain write, which no valid override can
    /// hold. Reading it back is refused as corrupt.
    #[test]
    fn a_stored_override_that_raises_nothing_is_corrupt() {
        let finance = raised_to(FINANCIAL).unwrap();
        let row = OperationRiskOverrideRow {
            id: finance.id,
            integration: finance.integration.clone(),
            operation: finance.operation.clone(),
            effect: WRITE,
            raised_by: finance.raised_by.clone(),
            created_at: finance.created_at,
            updated_at: finance.updated_at,
        };

        assert!(refused_as_corrupt(
            &OperationRiskOverride::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
