//! Risk overrides as the workflows tests raise them.

use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, RaiseRiskParams,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ActionClass, DeclaredAction, Human};

use crate::test_support::workflows::graphs::{APPEND_ROW, SHEETS, managing};

/// The spreadsheet's "append row", raised by `by` to count as a payment.
///
/// # Panics
///
/// Never: a payment raises any operation.
#[must_use]
pub fn raised_to_payment(by: &Human) -> OperationRiskOverride<ResolvedTenant> {
    OperationRiskOverride::raise(
        RaiseRiskParams {
            integration: IntegrationKey::new(SHEETS).expect("an integration key"),
            operation: OperationKey::new(APPEND_ROW).expect("an operation key"),
            effect: DeclaredAction::Declared(ActionClass::Financial),
        },
        &managing(by),
    )
    .expect("someone managing workflows raises an operation to a payment")
}
