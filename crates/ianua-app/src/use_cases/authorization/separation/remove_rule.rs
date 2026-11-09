//! Remove separation rule: lift a rule, so its two roles may be held
//! together again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SeparationRuleId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::SeparationRuleStore;
use crate::use_case::Command;

/// The ports [`RemoveRuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveRulePorts {
    /// Loads and removes the rule.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lifts a separation-of-duties rule of the caller's tenant.
pub struct RemoveRuleUseCase {
    ports: RemoveRulePorts,
}

impl RemoveRuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveRulePorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveRuleUseCase {
    type Caller = CallerContext;
    type Input = SeparationRuleId;
    type Output = Result<(), AppError>;

    /// Lifts rule `id` for the caller and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update roles, checked
    ///   before the rule is looked up so a made-up id is refused the same as
    ///   a real one.
    /// - `AppError::NotFound` when the tenant has no such rule.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: SeparationRuleId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Update))
            .map_err(AppError::from_domain)?;
        let store = self.ports.separation_rules.as_ref();
        let mut rule = store
            .find_by_id(&tenant, &id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authorization-separation-rule-not-found",
                "separation rule not found"
            ))?;
        rule.lift(&authority).map_err(AppError::from_domain)?;

        store.delete(&tenant, &id).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), rule.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeSeparationRuleStore, separation_between, stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A store holding the rule keeping "raiser" and "approver" apart.
    fn one_rule() -> (Arc<FakeSeparationRuleStore>, SeparationRuleId) {
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let approver = stored_role("approver", Vec::new(), Vec::new());
        let rule = separation_between("raise or approve payments", &raiser, &approver);
        let id = *rule.id();
        let store = FakeSeparationRuleStore::holding(test_ctx().tenant_id(), [rule]);
        (Arc::new(store), id)
    }

    fn remove(
        ports: RemoveRulePorts,
        sink: &Arc<FakeEventDispatcher>,
        id: SeparationRuleId,
    ) -> Result<(), AppError> {
        block_on(RemoveRuleUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            id,
        ))
    }

    fn ports_over(store: &Arc<FakeSeparationRuleStore>) -> RemoveRulePorts {
        RemoveRulePorts {
            separation_rules: store.clone(),
            ..RemoveRulePorts::fakes()
        }
    }

    /// Ann lifts the rule. It is gone and the lifting is recorded.
    #[test]
    fn a_rule_is_lifted_and_recorded() {
        let (store, id) = one_rule();
        let sink = Arc::new(FakeEventDispatcher::new());

        remove(ports_over(&store), &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.separation_rule_removed"]
        );
    }

    /// Ann lifts a rule the tenant does not have. It is not found.
    #[test]
    fn an_unknown_rule_is_not_found() {
        let (store, _) = one_rule();

        let result = remove(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            SeparationRuleId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Viewing roles does not permit lifting their separation rule.
    /// The rule stays stored and no removal is recorded.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let (store, id) = one_rule();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = remove(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot lift the stored separation rule.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = one_rule();
        let ports = RemoveRulePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = remove(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
