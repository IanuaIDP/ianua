//! Change break-glass policy: decide what a tenant's users may give
//! themselves in an emergency, with nobody else approving.
//!
//! A tenant starts letting nothing. Letting every user give themselves an
//! access hands it to each of them, and taking it away takes it from each
//! of them, so the person changing it must hold both what was let and what
//! will be.

use std::sync::Arc;

use ianua_domain::domains::authorization::break_glass::SelfService;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::BreakGlassStore;
use crate::services::lookup::break_glass_policy;
use crate::use_case::Command;

/// The ports [`ChangeBreakGlassPolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeBreakGlassPolicyPorts {
    /// The tenant's break-glass policy.
    pub break_glass_store: Arc<dyn BreakGlassStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes what the caller's tenant's users may give themselves.
pub struct ChangeBreakGlassPolicyUseCase {
    ports: ChangeBreakGlassPolicyPorts,
}

impl ChangeBreakGlassPolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeBreakGlassPolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeBreakGlassPolicyUseCase {
    type Caller = CallerContext;
    type Input = SelfService;
    type Output = Result<(), AppError>;

    /// Lets the tenant's users give themselves `self_service`, for the
    /// caller, and records what was let before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update users, or
    ///   holds less than the policy lets now or would let.
    /// - `AppError::Internal` when the policy cannot be read or written, or
    ///   the change cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        self_service: SelfService,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let store = self.ports.break_glass_store.as_ref();
        let mut policy = break_glass_policy(store, &tenant).await?;
        policy
            .change_self_service(self_service, &authority)
            .map_err(AppError::from_domain)?;

        store.save_policy(&tenant, &policy).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), policy.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::break_glass::{
        BreakGlassAccess, BreakGlassPolicy, BreakGlassPolicyRow,
    };
    use ianua_domain::domains::authorization::permission::{
        RoleAction, SystemPermission, UserAction,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeBreakGlassStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const UPDATE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Update);
    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    fn up_to(permission: SystemPermission) -> SelfService {
        SelfService::UpTo(BreakGlassAccess::new(vec![permission], Vec::new()).unwrap())
    }

    /// A store holding the tenant's policy letting `self_service`.
    fn store_letting(self_service: SelfService) -> Arc<FakeBreakGlassStore> {
        let store = Arc::new(FakeBreakGlassStore::empty());
        let policy = BreakGlassPolicy::reconstitute(BreakGlassPolicyRow {
            tenant_id: test_ctx().tenant_id(),
            self_service,
            updated_at: clock::now(),
        })
        .unwrap();
        block_on(store.save_policy(&test_ctx().tenant(), &policy)).unwrap();
        store
    }

    fn ports(
        store: &Arc<FakeBreakGlassStore>,
        authorities: FakeTenantAuthorities,
    ) -> ChangeBreakGlassPolicyPorts {
        ChangeBreakGlassPolicyPorts {
            break_glass_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        }
    }

    fn change(
        ports: ChangeBreakGlassPolicyPorts,
        self_service: SelfService,
    ) -> Result<(), AppError> {
        change_recorded(ports, self_service, &Arc::new(FakeEventDispatcher::new()))
    }

    fn change_recorded(
        ports: ChangeBreakGlassPolicyPorts,
        self_service: SelfService,
        events: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        block_on(ChangeBreakGlassPolicyUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(events.clone()),
            self_service,
        ))
    }

    fn letting(store: &FakeBreakGlassStore) -> Option<SelfService> {
        let policy = block_on(store.find_policy(&test_ctx().tenant())).unwrap();
        policy.map(|policy| policy.self_service().clone())
    }

    /// Ann lets the tenant's users give themselves the right to update
    /// roles in an emergency. The policy is saved letting that.
    #[test]
    fn the_tenant_lets_users_give_themselves_an_access() {
        let store = Arc::new(FakeBreakGlassStore::empty());

        change(
            ports(&store, FakeTenantAuthorities::holding_everything()),
            up_to(UPDATE_ROLES),
        )
        .unwrap();

        assert_eq!(letting(&store), Some(up_to(UPDATE_ROLES)));
    }

    /// Ann lets users give themselves "update roles" where before they
    /// could give themselves nothing. The audit trail records both.
    #[test]
    fn a_policy_change_is_recorded_with_what_was_let_before() {
        let store = Arc::new(FakeBreakGlassStore::empty());
        let events = Arc::new(FakeEventDispatcher::new());

        change_recorded(
            ports(&store, FakeTenantAuthorities::holding_everything()),
            up_to(UPDATE_ROLES),
            &events,
        )
        .unwrap();

        let payload = events.payload_of("authorization.break_glass_policy_changed");
        let Some(FieldValue::Change(change)) = payload.value("self_service") else {
            panic!("self_service is not a change");
        };
        assert_eq!(change.from(), Some("off"));
        assert_eq!(change.to(), Some(UPDATE_ROLES.to_string().as_str()));
    }

    /// Ann switches self-service off again. Every grant then needs someone
    /// else's approval.
    #[test]
    fn self_service_is_switched_off() {
        let store = store_letting(up_to(UPDATE_ROLES));

        change(
            ports(&store, FakeTenantAuthorities::holding_everything()),
            SelfService::Off,
        )
        .unwrap();

        assert_eq!(letting(&store), Some(SelfService::Off));
    }

    /// A caller who may update users but not roles cannot let users grant
    /// themselves role-update rights. No policy is saved.
    #[test]
    fn letting_more_than_the_caller_holds_is_refused() {
        let store = Arc::new(FakeBreakGlassStore::empty());
        let sam = FakeTenantAuthorities::holding(&[UPDATE_USERS]);

        let result = change(ports(&store, sam), up_to(UPDATE_ROLES));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(letting(&store), None);
    }

    /// A caller who lacks role-update rights cannot remove that access from
    /// the self-service policy. The policy keeps allowing it.
    #[test]
    fn taking_away_more_than_the_caller_holds_is_refused() {
        let store = store_letting(up_to(UPDATE_ROLES));
        let sam = FakeTenantAuthorities::holding(&[UPDATE_USERS]);

        let result = change(ports(&store, sam), SelfService::Off);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(letting(&store), Some(up_to(UPDATE_ROLES)));
    }

    /// A caller without user-update rights cannot enable self-service access.
    /// No policy is saved.
    #[test]
    fn a_caller_who_may_not_update_users_is_refused() {
        let store = Arc::new(FakeBreakGlassStore::empty());

        let result = change(
            ports(&store, FakeTenantAuthorities::holding(&[])),
            up_to(UPDATE_USERS),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(letting(&store), None);
    }

    /// A signed-out session cannot change the break-glass policy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeBreakGlassStore::empty());

        let result = change(
            ports(&store, FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            up_to(UPDATE_USERS),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
