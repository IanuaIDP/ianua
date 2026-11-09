//! An order to stop a run as its row holds it: read back through the
//! order's own checks, and written out from it.

use ianua_domain::domains::agents::execution::run::{CancelOrder, CancelOrderRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentRunId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, human_from};
use crate::postgres::foundation::stored::Stored;

const ORDER: Stored = Stored("cancel order");

/// An order as it is read. The store's checked queries fill it.
pub(super) struct OrderRecord {
    pub(super) run_id: Uuid,
    pub(super) ordered_by_kind: String,
    pub(super) ordered_by_id: Uuid,
    pub(super) ordered_by_person: String,
    pub(super) ordered_at: OffsetDateTime,
}

impl OrderRecord {
    /// The order the record holds, read back through its checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the person who gave it is
    /// no person, or the order is dated later than now.
    pub(super) fn into_order(self) -> Result<CancelOrder, DomainError> {
        let by = human_from(
            ORDER,
            &self.ordered_by_kind,
            self.ordered_by_id,
            self.ordered_by_person,
        )?;
        CancelOrder::reconstitute(CancelOrderRow {
            run_id: AgentRunId::from_uuid(self.run_id),
            by,
            at: self.ordered_at,
        })
    }
}

/// An order's columns, as they are written.
pub(super) struct OrderColumns<'a> {
    pub(super) run_id: &'a Uuid,
    pub(super) by: HumanColumns<'a>,
    pub(super) at: OffsetDateTime,
}

impl<'a> OrderColumns<'a> {
    /// The columns `order` is written to.
    pub(super) fn of(order: &'a CancelOrder) -> Self {
        Self {
            run_id: order.run_id().as_uuid(),
            by: HumanColumns::of(order.by()),
            at: order.at(),
        }
    }
}
