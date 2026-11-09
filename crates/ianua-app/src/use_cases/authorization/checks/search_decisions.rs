//! Search decisions: the tenant's authorization decisions, newest first,
//! narrowed by subject, outcome, policy version or rule.
//!
//! An admin asking "why was Bob refused at noon?" finds the decision, the
//! rule that settled it and the version of the policy that held the rule.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{AuditLogAction, SystemPermission};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{DecisionFilter, DecisionRecord, DecisionRecordStore};
use crate::use_case::Query;

/// The ports [`SearchDecisionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SearchDecisionsPorts {
    /// Searches the decision records.
    pub decision_records: Arc<dyn DecisionRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which decisions to find, and which page.
pub struct SearchDecisionsRequest {
    /// Which decisions.
    pub filter: DecisionFilter,
    /// Which page of them, newest first.
    pub page: PageRequest,
}

/// Searches the authorization decisions of the caller's tenant.
pub struct SearchDecisionsUseCase {
    ports: SearchDecisionsPorts,
}

impl SearchDecisionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SearchDecisionsPorts) -> Self {
        Self { ports }
    }
}

impl Query for SearchDecisionsUseCase {
    type Caller = CallerContext;
    type Input = SearchDecisionsRequest;
    type Output = Result<Page<DecisionRecord>, AppError>;

    /// One page of the decisions `request.filter` keeps, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the audit log.
    /// - `AppError::Internal` when the records cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: SearchDecisionsRequest,
    ) -> Result<Page<DecisionRecord>, AppError> {
        let SearchDecisionsRequest { filter, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::AuditLog(AuditLogAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .decision_records
            .search(&ctx.tenant(), &filter, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::version::PolicyVersion;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ActorRef, DecisionRecordId, Label, PrincipalRef, Text, UserId};

    use super::*;
    use crate::ports::authorization::{DecisionBasis, MatchedRule, Verdict};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeDecisionRecordStore;
    use crate::test_support::{block_on, test_ctx};

    /// The gateway's policy version 1 refused Bob under "block-admin" and
    /// let Carol through by its default.
    fn two_decisions(bob: PrincipalRef) -> SearchDecisionsPorts {
        let store = FakeDecisionRecordStore::empty();
        let refused = denied_decision(bob);
        let let_through = DecisionRecord {
            id: DecisionRecordId::new(),
            subject: PrincipalRef::User(UserId::new()),
            basis: DecisionBasis::Policy {
                version: PolicyVersion::FIRST,
                matched: MatchedRule::Default,
                action: PolicyAction::Allow,
            },
            ..refused.clone()
        };
        let tenant = test_ctx().tenant();
        block_on(store.record(&tenant, &refused)).unwrap();
        block_on(store.record(&tenant, &let_through)).unwrap();
        SearchDecisionsPorts {
            decision_records: Arc::new(store),
            ..SearchDecisionsPorts::fakes()
        }
    }

    /// The gateway records Bob's denial under the named rule in policy version one.
    fn denied_decision(bob: PrincipalRef) -> DecisionRecord {
        DecisionRecord {
            id: DecisionRecordId::new(),
            asked_by: ActorRef::System,
            subject: bob,
            basis: DecisionBasis::Policy {
                version: PolicyVersion::FIRST,
                matched: MatchedRule::Rule(Label::new("rule_name", "block-admin").unwrap()),
                action: PolicyAction::Deny {
                    reason: Text::new("reason", "admin blocked").unwrap(),
                },
            },
            decided_at: clock::now(),
        }
    }

    fn search(
        ports: SearchDecisionsPorts,
        filter: DecisionFilter,
    ) -> Result<Page<DecisionRecord>, AppError> {
        block_on(SearchDecisionsUseCase::new(ports).execute(
            &test_ctx(),
            SearchDecisionsRequest {
                filter,
                page: PageRequest::default(),
            },
        ))
    }

    /// Ann looks for why Bob was refused. She finds the one refusal, under
    /// "block-admin" in version 1.
    #[test]
    fn a_refusal_is_found_with_its_rule_and_version() {
        let bob = PrincipalRef::User(UserId::new());
        let filter = DecisionFilter {
            subject: Some(bob),
            verdict: Some(Verdict::Denied),
            ..DecisionFilter::default()
        };

        let page = search(two_decisions(bob), filter).unwrap();

        assert_eq!(page.items.len(), 1);
        assert!(matches!(
            &page.items[0].basis,
            DecisionBasis::Policy {
                matched: MatchedRule::Rule(_),
                ..
            }
        ));
    }

    /// A caller without audit-log viewing rights cannot search decisions.
    #[test]
    fn a_caller_who_may_not_view_the_audit_log_is_refused() {
        let ports = SearchDecisionsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..two_decisions(PrincipalRef::User(UserId::new()))
        };

        let result = search(ports, DecisionFilter::default());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot search authorization decisions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = SearchDecisionsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..two_decisions(PrincipalRef::User(UserId::new()))
        };

        let result = search(ports, DecisionFilter::default());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
