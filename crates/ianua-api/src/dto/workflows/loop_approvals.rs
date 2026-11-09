//! A loop's approval of every item on the wire: the items, page by page,
//! with how far through them the caller is, and the body approving them.

use ianua_app::listing::{Cursor, PageRequest};
use ianua_app::use_cases::workflows::executions::{
    ApprovalItem, ApproveItemsRequest, ItemsPage, ShowItemsRequest,
};
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::types::WorkflowExecutionId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::dto::workflows::data::json_of;

/// One page of the items a loop asks one approval for.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ItemsPageResponse {
    /// What people are asked to approve.
    pub summary: String,
    /// The class of what the loop does: `undeclared` or an action class.
    pub action_class: String,
    /// How many different people must approve: two before a high-risk
    /// action, each with a fresh second-factor code.
    pub approvers_needed: u8,
    /// When the approval opened, fixing the items.
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
    /// When it can no longer be approved.
    #[serde(with = "time::serde::rfc3339")]
    pub closes_at: OffsetDateTime,
    /// What every pass is given beside its item.
    #[schema(value_type = Object)]
    pub shared: Value,
    /// How many items the loop will act on.
    pub total: u32,
    /// How many of them the caller was shown so far, this page included.
    /// Approving counts once it equals `total`.
    pub shown: u32,
    /// The items on this page, in the order the passes take them.
    pub items: Vec<ApprovalItemResponse>,
    /// The cursor of the next page, passed back as `?after=`, or `null` on
    /// the last one.
    pub next_cursor: Option<String>,
    /// The most items a page holds.
    pub limit: u32,
}

/// One item, at its place in the list.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalItemResponse {
    /// Its position, counted from zero: the pass for it starts with this
    /// as `trigger.index`.
    pub position: u32,
    /// The item, as the pass for it starts with it at `trigger.item`.
    #[schema(value_type = Object)]
    pub item: Value,
}

impl From<ItemsPage> for ItemsPageResponse {
    fn from(page: ItemsPage) -> Self {
        Self {
            summary: page.approval.summary().as_str().to_owned(),
            action_class: page.approval.action_class().as_str().to_owned(),
            approvers_needed: page.approval.approvers_needed(),
            opened_at: page.opening,
            closes_at: page.closes_at,
            shared: json_of(&page.shared),
            total: page.total,
            shown: page.shown,
            next_cursor: page.items.next.as_ref().map(Cursor::encode),
            limit: page.items.limit.get(),
            items: page
                .items
                .items
                .into_iter()
                .map(ApprovalItemResponse::from)
                .collect(),
        }
    }
}

impl From<ApprovalItem> for ApprovalItemResponse {
    fn from(item: ApprovalItem) -> Self {
        Self {
            position: item.position,
            item: json_of(&item.item),
        }
    }
}

/// Request body for approving every item of a loop.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ApproveItemsBody {
    /// A fresh second-factor code, needed when the loop's action may be
    /// high risk.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl ApproveItemsBody {
    /// Approving every item of the loop `step` of `execution_id`.
    #[must_use]
    pub(crate) fn request(
        self,
        execution_id: WorkflowExecutionId,
        step: NodeKey,
    ) -> ApproveItemsRequest {
        ApproveItemsRequest {
            execution_id,
            step,
            mfa_code: self.mfa_code,
        }
    }
}

/// The page asked for of the items the loop `step` of `execution_id` asks
/// about.
#[must_use]
pub(crate) fn items_listing(
    execution_id: WorkflowExecutionId,
    step: NodeKey,
    page: PageRequest,
) -> ShowItemsRequest {
    ShowItemsRequest {
        execution_id,
        step,
        page,
    }
}
