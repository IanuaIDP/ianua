//! Show items: one page of the items a loop asks one approval for, shown
//! to a person who may decide it, and kept as opened by them.
//!
//! Bob opens the approval of Ann's loop over 120 stale issues. Each page he
//! is served is kept beside the run, so his yes counts only once every
//! issue was on a page he opened, and each page says how far through the
//! list he is.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::node::{NodeKey, WorkflowApprovalStep};
use ianua_domain::domains::workflows::execution::{ItemsAsked, ItemsSeen, SeenPage};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::WorkflowExecutionId;
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::define_sort_field;
use crate::error::AppError;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::workflows::{ApprovalPages, ItemsViewer, WorkflowExecutionStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::approvals::approving::step_approver;
use crate::use_cases::workflows::lookup::existing_execution;

/// Which page of a loop's items to show.
pub struct ShowItemsRequest {
    /// The run whose loop asks.
    pub execution_id: WorkflowExecutionId,
    /// The loop step.
    pub step: NodeKey,
    /// Where the page starts and how many items it holds.
    pub page: PageRequest,
}

/// One item of a loop's list, where the passes take it.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalItem {
    /// Its position, counted from zero: pass `position` acts on it.
    pub position: u32,
    /// What the loop's pass at `position` will act on, as it was fixed when
    /// the approval opened.
    pub item: FlowData,
}

define_sort_field! {
    /// The one order a loop's items are shown in: the order the passes take
    /// them.
    pub enum ApprovalItemSortField {
        /// Order by position in the list.
        Position => "position",
    }
    default = Position;
}

impl SortKeys<ApprovalItemSortField> for ApprovalItem {
    fn sort_key(&self, field: ApprovalItemSortField) -> SortKey {
        match field {
            ApprovalItemSortField::Position => self.position.into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.position.into()
    }
}

/// One page of the items, with what the approval asks and how far through
/// the list the caller is.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemsPage {
    /// When the approval opened, fixing the items. Pages opened count only
    /// for this opening.
    pub opening: OffsetDateTime,
    /// What is asked: the summary, the class of action, the window and how
    /// many approvers it needs.
    pub approval: WorkflowApprovalStep,
    /// When it can no longer be approved.
    pub closes_at: OffsetDateTime,
    /// What every pass is given beside its item.
    pub shared: FlowData,
    /// The items on this page.
    pub items: Page<ApprovalItem>,
    /// How many items the loop will act on.
    pub total: u32,
    /// How many of them the caller was shown so far, this page included.
    pub shown: u32,
}

/// The ports [`ShowItemsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ShowItemsPorts {
    /// Keeps the executions.
    pub executions: Arc<dyn WorkflowExecutionStore>,
    /// Keeps the pages each person opened.
    pub pages: Arc<dyn ApprovalPages>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Shows approvers a loop's items, page by page.
pub struct ShowItemsUseCase {
    ports: ShowItemsPorts,
}

impl ShowItemsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ShowItemsPorts) -> Self {
        Self { ports }
    }

    /// Keeps `page`, when there is one, as opened by `viewer`, and gives
    /// back every page they opened so far.
    async fn mark_opened(
        &self,
        tenant: &ScopedTenant,
        viewer: &ItemsViewer,
        page: Option<SeenPage>,
    ) -> Result<ItemsSeen, AppError> {
        if let Some(page) = page {
            self.ports
                .pages
                .record(tenant, viewer, &page)
                .await
                .map_err(AppError::from_domain)?;
        }
        self.ports
            .pages
            .seen_by(tenant, viewer)
            .await
            .map_err(AppError::from_domain)
    }
}

impl Command for ShowItemsUseCase {
    type Caller = CallerContext;
    type Input = ShowItemsRequest;
    type Output = Result<ItemsPage, AppError>;

    /// One page of the items `request.step` asks one approval for, shown to
    /// the person `ctx` names and kept as opened by them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing execution/step.
    /// - `AppError::Forbidden` without decision rights or clearance; `Conflict` for execution expiry.
    /// - `AppError::Domain` for a step not asking about every item, or a cursor from another list.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        _auditor: &RequestAuditor,
        request: ShowItemsRequest,
    ) -> Result<ItemsPage, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Approve)
            .map_err(AppError::from_domain)?;
        let execution = existing_execution(
            self.ports.executions.as_ref(),
            &tenant,
            &request.execution_id,
        )
        .await?;
        let approver = step_approver(&authority, None)?;
        let asked = execution
            .items_shown_to(&request.step, &approver)
            .map_err(AppError::from_domain)?;
        let items = page_of(&asked, &request.page).map_err(AppError::from_domain)?;
        let viewer = ItemsViewer {
            execution_id: request.execution_id,
            step: request.step,
            person: control.by().person().clone(),
        };
        let seen = self
            .mark_opened(&tenant, &viewer, opened(&asked, &items))
            .await?;
        Ok(page_shown(asked, &seen, items))
    }
}

/// The page `items` of what `asked` covers, with how many of the items the
/// viewer saw so far, `seen` counting every page they opened.
fn page_shown(asked: ItemsAsked, seen: &ItemsSeen, items: Page<ApprovalItem>) -> ItemsPage {
    let total = count_of(&asked);
    ItemsPage {
        opening: asked.opening,
        shown: seen.items_shown(asked.opening, total),
        total,
        approval: asked.approval,
        closes_at: asked.closes_at,
        shared: asked.shared,
        items,
    }
}

/// The page of `asked`'s items `request` names.
///
/// # Errors
///
/// - `DomainError::Validation` for a cursor made for another list.
fn page_of(asked: &ItemsAsked, request: &PageRequest) -> Result<Page<ApprovalItem>, DomainError> {
    let order = SortOrder::<ApprovalItemSortField>::default();
    let items = (0..)
        .zip(&asked.items)
        .map(|(position, item)| ApprovalItem {
            position,
            item: item.clone(),
        })
        .collect();
    Ok(request.keyset(&order)?.cut(items))
}

/// The page `items` shows of `asked`'s list, opened now; `None` for a page
/// past the last item.
fn opened(asked: &ItemsAsked, items: &Page<ApprovalItem>) -> Option<SeenPage> {
    let first = items.items.first()?.position;
    let count = u32::try_from(items.items.len()).unwrap_or(u32::MAX);
    Some(SeenPage {
        opening: asked.opening,
        first,
        count,
        at: clock::now(),
    })
}

/// How many items `asked` lists.
fn count_of(asked: &ItemsAsked) -> u32 {
    u32::try_from(asked.items.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::execution::WorkflowExecution;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::listing::Limit;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeApprovalPages, FakeWorkflowExecutionStore, loop_asking_for_every_item, person, step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const APPROVES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Approve)];

    fn asking() -> WorkflowExecution<ResolvedTenant> {
        loop_asking_for_every_item(
            &person("ann@corp.test"),
            &["a", "b", "c"],
            ActionClass::Communicate,
        )
    }

    fn show(
        execution: &WorkflowExecution<ResolvedTenant>,
        pages: &Arc<FakeApprovalPages>,
        authorities: FakeTenantAuthorities,
        page: PageRequest,
    ) -> Result<ItemsPage, AppError> {
        let use_case = ShowItemsUseCase::new(ShowItemsPorts {
            executions: Arc::new(FakeWorkflowExecutionStore::holding(execution)),
            pages: pages.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ShowItemsRequest {
            execution_id: *execution.id(),
            step: step("each"),
            page,
        };
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&test_ctx(), &auditor, request))
    }

    fn two_per_page() -> PageRequest {
        PageRequest::first(Limit::new(2).unwrap())
    }

    /// Bob opens the first page of two out of three issues. He sees the
    /// first two, a cursor to the next page, and that he has seen two of
    /// three; the page is kept as opened by him.
    #[test]
    fn a_page_shows_its_items_and_how_far_through_the_list_it_is() {
        let execution = asking();
        let pages = Arc::new(FakeApprovalPages::none());

        let shown = show(
            &execution,
            &pages,
            FakeTenantAuthorities::holding(&APPROVES),
            two_per_page(),
        )
        .unwrap();

        assert_eq!(
            shown
                .items
                .items
                .iter()
                .map(|item| item.position)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert!(shown.items.next.is_some());
        assert_eq!((shown.shown, shown.total), (2, 3));
        assert_eq!(pages.all().len(), 1);
    }

    /// Bob opens the second page after the first. He has seen all three.
    #[test]
    fn opening_every_page_shows_every_item() {
        let execution = asking();
        let pages = Arc::new(FakeApprovalPages::none());
        let first = show(
            &execution,
            &pages,
            FakeTenantAuthorities::holding(&APPROVES),
            two_per_page(),
        )
        .unwrap();
        let after = two_per_page().following(&first.items).unwrap();

        let second = show(
            &execution,
            &pages,
            FakeTenantAuthorities::holding(&APPROVES),
            after,
        )
        .unwrap();

        assert_eq!(second.items.items.len(), 1);
        assert_eq!(second.shown, 3);
    }

    /// Someone who may only view workflows sees no item, and nothing is
    /// kept as opened.
    #[test]
    fn someone_who_may_not_decide_sees_no_item() {
        let execution = asking();
        let pages = Arc::new(FakeApprovalPages::none());

        let result = show(
            &execution,
            &pages,
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]),
            two_per_page(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(pages.all().is_empty());
    }
}
