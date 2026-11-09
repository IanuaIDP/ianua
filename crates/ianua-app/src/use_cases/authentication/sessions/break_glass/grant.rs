//! Granting emergency access: a tenant user gets named rights for a short
//! window, with a written reason, approved by the caller.
//!
//! The caller approves what they hold themselves and may hand out. A caller
//! granting it to themselves approves it under the tenant's break-glass
//! policy instead, which lets nothing until the tenant sets one.

use std::sync::Arc;

use ianua_domain::domains::authorization::break_glass::{
    BreakGlassAccess, BreakGlassGrant, NewBreakGlass, RequestedApproval,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{BreakGlassGrantId, Text, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::BreakGlassStore;
use crate::ports::identity::UserStore;
use crate::services::lookup::break_glass_policy;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::lookup::owned_grantee;

/// How long the deployment lets an emergency grant last, within the day
/// no grant may pass.
#[derive(Debug, Clone, Copy)]
pub struct BreakGlassLimits {
    /// The longest a grant may last, in seconds.
    pub max_duration_seconds: i64,
}

/// Emergency access for one user: what, why, and for how long.
pub struct BreakGlassGrantRequest {
    /// Who gets the access.
    pub user_id: UserId,
    /// What it lets them do.
    pub access: BreakGlassAccess,
    /// Why it is needed, kept in the audit trail.
    pub reason: Text,
    /// How long it lasts, in seconds.
    pub duration_seconds: i64,
}

/// The ports [`GrantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantPorts {
    /// Grants and the tenant's break-glass policy.
    pub grant_store: Arc<dyn BreakGlassStore>,
    /// The tenant's users, for the grantee.
    pub users: Arc<dyn UserStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Grants emergency access, approved by the caller.
pub struct GrantUseCase {
    limits: BreakGlassLimits,
    ports: GrantPorts,
}

impl GrantUseCase {
    /// A use case keeping to `limits`, working through `ports`.
    #[must_use]
    pub fn new(limits: BreakGlassLimits, ports: GrantPorts) -> Self {
        Self { limits, ports }
    }

    /// Refuses a second grant for someone who already holds an active one.
    async fn ensure_no_active_grant(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), AppError> {
        let grants = self.ports.grant_store.list(tenant).await.or_internal()?;
        let now = clock::now();
        if grants
            .iter()
            .any(|grant| grant.user_id() == user_id && grant.is_active(now))
        {
            return Err(AppError::Conflict(message!(
                "authentication-user-already-has-an-active-break",
                "user already has an active break-glass grant"
            )));
        }
        Ok(())
    }
}

impl Command for GrantUseCase {
    type Caller = CallerContext;
    type Input = BreakGlassGrantRequest;
    type Output = Result<BreakGlassGrantId, AppError>;

    /// Grants `request.user_id` the access asked for, approved by the
    /// caller, and records `authentication.break_glass_granted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for invalid/deployment-exceeding duration, insufficient grant rights, or self-approval outside policy.
    /// - `AppError::NotFound` for a missing user or another user's grant requested without grant rights, hiding account existence.
    /// - `AppError::Conflict` for an active grant; `Domain` for a window longer than a day.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: BreakGlassGrantRequest,
    ) -> Result<BreakGlassGrantId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_duration_allowed(request.duration_seconds, self.limits)?;
        let tenant = ctx.tenant();
        let users = self.ports.users.as_ref();
        let grantee = owned_grantee(users, &tenant, &request.user_id, &authority).await?;
        self.ensure_no_active_grant(&tenant, &request.user_id)
            .await?;
        let policy = break_glass_policy(self.ports.grant_store.as_ref(), &tenant).await?;
        let new = NewBreakGlass {
            tenant_id: ctx.tenant_id(),
            grantee: &grantee,
            access: request.access,
            reason: request.reason,
            approval: RequestedApproval::By(&authority),
            expires_at: clock::now() + time::Duration::seconds(request.duration_seconds),
        };
        let mut grant = BreakGlassGrant::create(new, &policy).map_err(AppError::from_domain)?;
        self.ports
            .grant_store
            .save(&tenant, &grant)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), grant.take_events())
            .await
            .or_internal()?;
        Ok(*grant.id())
    }
}

/// Refuses a duration that is not positive, or past the deployment's
/// limit.
///
/// # Errors
///
/// Returns `AppError::Forbidden` for either.
fn ensure_duration_allowed(
    duration_seconds: i64,
    limits: BreakGlassLimits,
) -> Result<(), AppError> {
    if duration_seconds > limits.max_duration_seconds {
        return Err(AppError::Forbidden(message!(
            "authentication-requested-duration-exceeds-maximum",
            "requested duration exceeds maximum"
        )));
    }
    if duration_seconds <= 0 {
        return Err(AppError::Forbidden(message!(
            "authentication-duration-must-be-positive",
            "duration must be positive"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeBreakGlassStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, reference_label, test_auditor, test_ctx, test_ctx_with,
    };

    const DAY: i64 = 86_400;

    struct Fixture {
        bob: UserId,
        ann: UserId,
        grants: Arc<FakeBreakGlassStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                bob: UserId::new(),
                ann: UserId::new(),
                grants: Arc::new(FakeBreakGlassStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn grant_as(
            &self,
            authorities: FakeTenantAuthorities,
            request: BreakGlassGrantRequest,
        ) -> Result<BreakGlassGrantId, AppError> {
            let users = FakeUserStore::with_user(self.ann, "ann@acme.test");
            let use_case = GrantUseCase::new(
                BreakGlassLimits {
                    max_duration_seconds: 4 * 3600,
                },
                GrantPorts {
                    grant_store: self.grants.clone(),
                    users: Arc::new(users),
                    tenant_authorities: Arc::new(authorities),
                },
            );
            let bob = test_ctx_with(
                test_ctx().organization_id(),
                test_ctx().tenant_id(),
                self.bob,
            );
            block_on(use_case.execute(&bob, &test_auditor(self.audit.clone()), request))
        }

        fn grant(&self, request: BreakGlassGrantRequest) -> Result<BreakGlassGrantId, AppError> {
            self.grant_as(FakeTenantAuthorities::holding_everything(), request)
        }

        fn for_ann(&self, duration_seconds: i64) -> BreakGlassGrantRequest {
            BreakGlassGrantRequest {
                user_id: self.ann,
                access: view_users(),
                reason: Text::new("reason", "Production incident INC-1234").unwrap(),
                duration_seconds,
            }
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn view_users() -> BreakGlassAccess {
        BreakGlassAccess::new(vec![SystemPermission::Users(UserAction::View)], Vec::new()).unwrap()
    }

    /// Bob, who may hand users rights, gives Ann an hour of emergency
    /// access. It is stored, approved by Bob, and recorded.
    #[test]
    fn a_grant_is_stored_approved_by_the_caller_and_audited() {
        let fixture = Fixture::new();

        let id = fixture.grant(fixture.for_ann(3600)).unwrap();

        let stored = block_on(fixture.grants.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert!(!stored.is_self_approved());
        assert_eq!(fixture.recorded(), ["authentication.break_glass_granted"]);
    }

    /// Bob's grant to Ann is recorded under her name, so the record reads
    /// without the user row.
    #[test]
    fn the_record_names_the_grantee() {
        let fixture = Fixture::new();

        fixture.grant(fixture.for_ann(3600)).unwrap();

        let payload = fixture
            .audit
            .payload_of("authentication.break_glass_granted");
        assert_eq!(reference_label(&payload, "user"), Some("Test User"));
    }

    /// An unknown grantee returns NotFound and leaves the grant store empty.
    #[test]
    fn granting_to_an_unknown_user_is_not_found() {
        let fixture = Fixture::new();
        let request = BreakGlassGrantRequest {
            user_id: UserId::new(),
            ..fixture.for_ann(3600)
        };

        let result = fixture.grant(request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.grants.count(), 0);
    }

    /// A duration beyond the deployment limit is forbidden without storing a grant.
    #[test]
    fn a_duration_past_the_limit_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.grant(fixture.for_ann(DAY));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.grants.count(), 0);
    }

    /// Bob asks for exactly the longest the deployment allows. It is
    /// granted.
    #[test]
    fn a_grant_for_exactly_the_limit_is_allowed() {
        let fixture = Fixture::new();

        let result = fixture.grant(fixture.for_ann(4 * 3600));

        assert!(result.is_ok());
    }

    /// Both zero and negative grant durations are forbidden.
    #[test]
    fn a_duration_that_is_not_positive_is_refused() {
        let fixture = Fixture::new();

        let none = fixture.grant(fixture.for_ann(0));
        let negative = fixture.grant(fixture.for_ann(-60));

        assert!(matches!(none, Err(AppError::Forbidden(_))));
        assert!(matches!(negative, Err(AppError::Forbidden(_))));
    }

    /// A second active grant conflicts and leaves only the original grant stored.
    #[test]
    fn a_second_active_grant_is_a_conflict() {
        let fixture = Fixture::new();
        fixture.grant(fixture.for_ann(3600)).unwrap();

        let again = fixture.grant(fixture.for_ann(3600));

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(fixture.grants.count(), 1);
    }

    /// A caller without grant authority receives NotFound for the grantee,
    /// with no grant stored and no event recorded.
    #[test]
    fn a_caller_without_the_right_to_hand_out_rights_finds_nobody() {
        let fixture = Fixture::new();

        let result = fixture.grant_as(FakeTenantAuthorities::holding(&[]), fixture.for_ann(3600));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.grants.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// Self-approval without a permitting policy is forbidden and stores no grant.
    #[test]
    fn a_self_approval_without_a_policy_is_refused() {
        let fixture = Fixture::new();
        let ann_herself = Fixture {
            bob: fixture.ann,
            ..fixture
        };

        let result = ann_herself.grant(ann_herself.for_ann(3600));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(ann_herself.grants.count(), 0);
    }

    /// A signed-out caller cannot grant emergency access and is unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.grant_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.for_ann(3600),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
