//! Search request records: find the requests the gateway decided, by why
//! and by what they were refused.
//!
//! An admin asking why Ann was refused this morning searches for refusals
//! of Ann in that hour and reads which check refused her, under which rule
//! and with what reason.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{AuditLogAction, SystemPermission};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Listing, PageRequest, SortOrder};
use crate::ports::proxy::{
    ProxyRequestLog, RequestRecordFilter, RequestRecordPage, RequestRecordSortField,
};
use crate::use_case::Query;

/// Which records to find, in what order, and which stretch of them.
pub struct SearchRequestRecordsRequest {
    /// Narrows the records returned.
    pub filter: RequestRecordFilter,
    /// The order to return them in.
    pub sort: SortOrder<RequestRecordSortField>,
    /// The rows to return.
    pub page: PageRequest,
}

/// The ports [`SearchRequestRecordsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SearchRequestRecordsPorts {
    /// The records the gateway kept.
    pub request_log: Arc<dyn ProxyRequestLog>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Searches the tenant's request records.
pub struct SearchRequestRecordsUseCase {
    ports: SearchRequestRecordsPorts,
}

impl SearchRequestRecordsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SearchRequestRecordsPorts) -> Self {
        Self { ports }
    }
}

impl Query for SearchRequestRecordsUseCase {
    type Caller = CallerContext;
    type Input = SearchRequestRecordsRequest;
    type Output = Result<RequestRecordPage, AppError>;

    /// The tenant's request records that meet the filter, ordered and
    /// paged, with how many meet it in all.
    ///
    /// A record says who called what and what was decided, so reading them
    /// needs the audit log right, not only the right to view routing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the audit log.
    /// - `AppError::Internal` when the records cannot be read.
    async fn execute(
        &self,
        caller: &CallerContext,
        request: SearchRequestRecordsRequest,
    ) -> Result<RequestRecordPage, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::AuditLog(AuditLogAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .request_log
            .search(
                &caller.tenant(),
                Listing {
                    filter: &request.filter,
                    sort: &request.sort,
                    page: &request.page,
                },
            )
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, RequestOutcome,
    };
    use ianua_domain::domains::proxy::stages::stage::StageKindName;
    use ianua_domain::types::{Label, StageId, TenantId};

    use super::*;
    use crate::listing::Limit;
    use crate::ports::proxy::{DecidedByFilter, DecisionFilter, ProxyRequestRecord};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeRequestLog, test_request_record};
    use crate::test_support::{block_on, test_ctx};

    /// The tenant rule "contractors off hours".
    fn off_hours() -> Label {
        Label::new("name", "contractors off hours").unwrap()
    }

    /// A request the policy stage `stage_id` refused under "contractors off
    /// hours".
    fn refused_off_hours(stage_id: StageId) -> ProxyRequestRecord {
        test_request_record(RequestOutcome::Denied {
            status: 403,
            reason: "policy denied".to_owned(),
            decided_by: DecidingStage::Stage {
                stage_id,
                kind: StageKindName::Policy,
            },
            rule: DecidingRule::Named(off_hours()),
        })
    }

    /// A request refused because no route matched.
    fn refused_no_route() -> ProxyRequestRecord {
        test_request_record(RequestOutcome::Denied {
            status: 404,
            reason: "no route".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        })
    }

    /// A request forwarded and answered with 200.
    fn allowed() -> ProxyRequestRecord {
        test_request_record(RequestOutcome::Allowed {
            upstream_status: 200,
        })
    }

    /// Searches a log holding `records` with `filter`, as `authorities`
    /// allow.
    fn search(
        records: Vec<ProxyRequestRecord>,
        authorities: FakeTenantAuthorities,
        filter: RequestRecordFilter,
    ) -> Result<RequestRecordPage, AppError> {
        let use_case = SearchRequestRecordsUseCase::new(SearchRequestRecordsPorts {
            request_log: Arc::new(FakeRequestLog::holding(records)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(
            &test_ctx(),
            SearchRequestRecordsRequest {
                filter,
                sort: SortOrder::default(),
                page: PageRequest::first(Limit::new(50).unwrap()),
            },
        ))
    }

    /// Ann searches for refusals under "contractors off hours". She finds
    /// the one the policy stage made, not the missing route or the allowed
    /// request, and reads the stage that decided.
    #[test]
    fn refusals_are_found_by_their_rule() {
        let policy = StageId::new();
        let records = vec![refused_off_hours(policy), refused_no_route(), allowed()];

        let page = search(
            records,
            FakeTenantAuthorities::holding_everything(),
            RequestRecordFilter {
                rule: Some(off_hours()),
                ..RequestRecordFilter::default()
            },
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].outcome, refused_off_hours(policy).outcome);
    }

    /// Ann narrows to refusals made by the route check, then to refusals
    /// made by the policy stage. Each search finds its own.
    #[test]
    fn refusals_are_found_by_the_check_that_made_them() {
        let policy = StageId::new();
        let records = || vec![refused_off_hours(policy), refused_no_route(), allowed()];
        let by = |decided_by| RequestRecordFilter {
            decided_by,
            ..RequestRecordFilter::default()
        };

        let by_route = search(
            records(),
            FakeTenantAuthorities::holding_everything(),
            by(DecidedByFilter::Gateway(GatewayCheck::Route)),
        )
        .unwrap();
        let by_stage = search(
            records(),
            FakeTenantAuthorities::holding_everything(),
            by(DecidedByFilter::Stage(policy)),
        )
        .unwrap();

        assert_eq!(by_route.items[0].status(), 404);
        assert_eq!(by_route.items.len(), 1);
        assert_eq!(by_stage.items[0].status(), 403);
        assert_eq!(by_stage.items.len(), 1);
    }

    /// Ann asks for every refusal a policy stage made, in whichever
    /// pipeline. She finds those, and none made by a rate limit stage.
    #[test]
    fn refusals_are_found_by_the_kind_of_stage_that_made_them() {
        let throttled = test_request_record(RequestOutcome::Denied {
            status: 429,
            reason: "too many requests".to_owned(),
            decided_by: DecidingStage::Stage {
                stage_id: StageId::new(),
                kind: StageKindName::RateLimit,
            },
            rule: DecidingRule::Unnamed,
        });
        let records = vec![
            refused_off_hours(StageId::new()),
            refused_off_hours(StageId::new()),
            throttled,
        ];

        let page = search(
            records,
            FakeTenantAuthorities::holding_everything(),
            RequestRecordFilter {
                decided_by: DecidedByFilter::StageKind(StageKindName::Policy),
                ..RequestRecordFilter::default()
            },
        )
        .unwrap();

        assert_eq!(page.items.len(), 2);
        assert!(page.items.iter().all(|record| record.status() == 403));
    }

    /// Ann searches for refused requests whose reason mentions "route". She
    /// finds the one refused for want of a route, and no allowed request.
    #[test]
    fn refusals_are_found_by_their_reason() {
        let records = vec![
            refused_off_hours(StageId::new()),
            refused_no_route(),
            allowed(),
        ];

        let page = search(
            records,
            FakeTenantAuthorities::holding_everything(),
            RequestRecordFilter {
                decision: DecisionFilter::Refused,
                reason_contains: Some("ROUTE".to_owned()),
                ..RequestRecordFilter::default()
            },
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].status(), 404);
    }

    /// A search over records from two tenants returns only the caller's
    /// tenant's request.
    #[test]
    fn another_tenants_records_are_never_found() {
        let elsewhere = ProxyRequestRecord {
            tenant_id: TenantId::new(),
            ..allowed()
        };

        let page = search(
            vec![elsewhere, allowed()],
            FakeTenantAuthorities::holding_everything(),
            RequestRecordFilter::default(),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].tenant_id, test_ctx().tenant_id());
    }

    /// Routing view rights do not permit searching request audit records.
    #[test]
    fn a_caller_without_the_audit_right_is_refused() {
        let result = search(
            vec![allowed()],
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]),
            RequestRecordFilter::default(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Searching request records with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = search(
            vec![allowed()],
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            RequestRecordFilter::default(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
