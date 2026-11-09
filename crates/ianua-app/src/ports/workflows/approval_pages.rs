//! Approval pages: which pages of a loop's items each person opened while
//! the loop asked them to approve every item.
//!
//! A yes to every item counts only once its approver was shown each of
//! them, so every page served to a person is kept here, beside the run,
//! and read back when they say yes.

use async_trait::async_trait;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::{ItemsSeen, SeenPage};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PersonKey, WorkflowExecutionId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The loop whose items were shown, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemsViewer {
    /// The run whose loop asks.
    pub execution_id: WorkflowExecutionId,
    /// The loop step, by its key.
    pub step: NodeKey,
    /// The person shown the items, whichever of their accounts they used.
    pub person: PersonKey,
}

/// Dyn-safe port keeping the pages of a loop's items each person opened.
///
/// The pages go with their run.
#[async_trait]
pub trait ApprovalPages: Send + Sync + TenantScoped {
    /// Keeps that `viewer` opened `page`. The same page of the same opening
    /// opened again keeps the first time it was opened.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
        page: &SeenPage,
    ) -> Result<(), DomainError>;

    /// Every page `viewer` opened, of any opening of the loop's approval.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn seen_by(
        &self,
        tenant_id: &ScopedTenant,
        viewer: &ItemsViewer,
    ) -> Result<ItemsSeen, DomainError>;
}
