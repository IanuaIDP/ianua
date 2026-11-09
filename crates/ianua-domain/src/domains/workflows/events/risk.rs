//! The records of a tenant raising how risky an operation counts as, and
//! dropping that again.

use time::OffsetDateTime;

use crate::domains::workflows::integration::{IntegrationKey, OperationKey};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{DeclaredAction, OperationRiskOverrideId};

/// The reference kind for a tenant's raised view of an operation.
const RISK_OVERRIDE: RefKind = RefKind::new("operation_risk_override");

/// Which operation a tenant's raised view is for.
#[derive(Debug, Clone)]
pub(crate) struct RiskOverrideRef {
    /// The tenant declaration that raises the catalogue operation's risk.
    pub(crate) override_id: OperationRiskOverrideId,
    /// The integration offering the operation.
    pub(crate) integration: IntegrationKey,
    /// The catalogue action whose effective risk is changed.
    pub(crate) operation: OperationKey,
}

impl RiskOverrideRef {
    fn payload(&self) -> EventData {
        let named = format!("{}.{}", self.integration, self.operation);
        EventData::new()
            .reference(
                "override",
                Reference::new(RISK_OVERRIDE, self.override_id.to_string(), &named),
            )
            .field("integration", self.integration.as_str().to_owned())
            .field("operation", self.operation.as_str().to_owned())
    }
}

/// A tenant raised how risky an operation counts as.
#[derive(Debug)]
pub struct OperationRiskRaised {
    /// The tenant declaration and catalogue action assigned a higher risk.
    pub(crate) operation: RiskOverrideRef,
    /// What it counts as now.
    pub(crate) effect: DeclaredAction,
    /// When it was raised.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OperationRiskRaised => WorkflowsEvent::OperationRiskRaised,
    fn payload(&self) -> EventData {
        self.operation.payload().field("effect", self.effect.as_str())
    }
}

/// A tenant dropped its raised view of an operation.
#[derive(Debug)]
pub struct OperationRiskOverrideRemoved {
    /// The tenant declaration removed to restore the catalogue action's risk.
    pub(crate) operation: RiskOverrideRef,
    /// When it was dropped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    OperationRiskOverrideRemoved => WorkflowsEvent::OperationRiskOverrideRemoved,
    fn payload(&self) -> EventData {
        self.operation.payload()
    }
}
