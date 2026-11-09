//! Ending emergency access early: the user, their approver, or someone who
//! may hand users rights takes a break-glass grant back.

use std::sync::Arc;

use ianua_domain::domains::authorization::break_glass::BreakGlassGrant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::BreakGlassGrantId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::authentication::BreakGlassStore;
use crate::ports::identity::UserStore;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::holder::account_label;
use crate::use_cases::authentication::sessions::lookup::owned_break_glass_grant;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads and saves emergency access being withdrawn.
    pub grant_store: Arc<dyn BreakGlassStore>,
    /// The tenant's users, for how the record names the grant's holder.
    pub users: Arc<dyn UserStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Takes an active break-glass grant back.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = BreakGlassGrantId;
    type Output = Result<(), AppError>;

    /// Ends the grant `grant_id` now and records
    /// `authentication.break_glass_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such grant, or the
    ///   caller is neither its user nor its approver and may not hand users
    ///   rights: a grant they may not end cannot be told from one that is
    ///   not there.
    /// - `AppError::Conflict` when the grant already ended or was revoked,
    ///   or another revocation of it landed first.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        grant_id: BreakGlassGrantId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.grant_store.as_ref();
        let mut grant = owned_break_glass_grant(store, &tenant, &grant_id, &authority).await?;
        ensure_active(&grant)?;
        let holder = self
            .ports
            .users
            .find_by_id(&tenant, grant.user_id())
            .await
            .or_internal()?;
        grant
            .revoke(&authority, account_label(holder.as_ref(), grant.user_id()))
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &grant).await.or_conflict(message!(
            "authentication-the-grant-was-revoked-meanwhile",
            "the grant was revoked meanwhile"
        ))?;
        auditor
            .dispatch_by(&ctx.actor(), grant.take_events())
            .await
            .or_internal()
    }
}

/// Refuses a grant that already ended or was revoked.
///
/// # Errors
///
/// Returns `AppError::Conflict` when the grant is not active.
fn ensure_active(grant: &BreakGlassGrant) -> Result<(), AppError> {
    if grant.is_active(clock::now()) {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "authentication-grant-is-already-revoked-or-expired",
        "grant is already revoked or expired"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::break_glass::{
        BreakGlassAccess, BreakGlassGrantRow, GrantApproval,
    };
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::{PersonKey, Revocation, Text, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeBreakGlassStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, reference_label, test_auditor, test_ctx,
    };

    struct Fixture {
        ann: UserId,
        grant_id: BreakGlassGrantId,
        grants: Arc<FakeBreakGlassStore>,
        users: Arc<FakeUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(row: BreakGlassGrantRow) -> Self {
            let ann = row.user_id;
            Self {
                ann,
                grant_id: row.id,
                grants: Arc::new(FakeBreakGlassStore::holding([
                    BreakGlassGrant::reconstitute(row).unwrap(),
                ])),
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn active() -> Self {
            Self::holding(grant_row(Duration::minutes(-5), Revocation::InForce))
        }

        fn revoke_as(
            &self,
            authorities: FakeTenantAuthorities,
            grant_id: BreakGlassGrantId,
        ) -> Result<(), AppError> {
            let use_case = RevokeUseCase::new(RevokePorts {
                grant_store: self.grants.clone(),
                users: self.users.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), grant_id))
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding_everything(), self.grant_id)
        }

        fn stored(&self) -> BreakGlassGrant {
            block_on(self.grants.find_by_id(&test_ctx().tenant(), &self.grant_id))
                .unwrap()
                .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann's self-approved hour of "view users", granted `started` from now
    /// and revoked or not as `revocation` says.
    fn grant_row(started: Duration, revocation: Revocation) -> BreakGlassGrantRow {
        let created_at = clock::now() + started;
        BreakGlassGrantRow {
            id: BreakGlassGrantId::new(),
            tenant_id: test_ctx().tenant_id(),
            user_id: UserId::new(),
            grantee_person: PersonKey::new("ann@acme.test").unwrap(),
            access: BreakGlassAccess::new(
                vec![SystemPermission::Users(UserAction::View)],
                Vec::new(),
            )
            .unwrap(),
            reason: Text::new("reason", "Production incident INC-1234").unwrap(),
            approved_by: GrantApproval::SelfApproved,
            expires_at: created_at + Duration::hours(1),
            revocation,
            created_at,
        }
    }

    /// Fay, who may hand users rights, ends Ann's emergency access early.
    /// It stops counting and the change is recorded under Ann's name.
    #[test]
    fn an_active_grant_is_revoked_and_audited() {
        let fixture = Fixture::active();

        fixture.revoke().unwrap();

        assert!(!fixture.stored().is_active(clock::now()));
        assert_eq!(fixture.recorded(), ["authentication.break_glass_revoked"]);
        let payload = fixture
            .audit
            .payload_of("authentication.break_glass_revoked");
        assert_eq!(reference_label(&payload, "user"), Some("Test User"));
    }

    /// Ann's account is gone. The record names her by her id.
    #[test]
    fn the_record_names_a_gone_holder_by_id() {
        let fixture = Fixture {
            users: Arc::new(FakeUserStore::empty()),
            ..Fixture::active()
        };

        fixture.revoke().unwrap();

        let payload = fixture
            .audit
            .payload_of("authentication.break_glass_revoked");
        let ann = fixture.ann.to_string();
        assert_eq!(reference_label(&payload, "user"), Some(ann.as_str()));
    }

    /// Revoking an unknown grant returns NotFound without recording an event.
    #[test]
    fn an_unknown_grant_is_not_found() {
        let fixture = Fixture::active();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::holding_everything(),
            BreakGlassGrantId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A grant already revoked is a conflict, and nothing more is recorded.
    #[test]
    fn a_revoked_grant_is_a_conflict() {
        let revoked = Revocation::Revoked {
            at: clock::now() - Duration::minutes(1),
        };
        let fixture = Fixture::holding(grant_row(Duration::minutes(-5), revoked));

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A grant whose window has passed is a conflict too.
    #[test]
    fn an_expired_grant_is_a_conflict() {
        let fixture = Fixture::holding(grant_row(Duration::hours(-2), Revocation::InForce));

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An unauthorized caller receives NotFound, leaves the grant active
    /// and records no revocation event.
    #[test]
    fn someone_else_without_the_right_finds_nothing() {
        let fixture = Fixture::active();

        let result = fixture.revoke_as(FakeTenantAuthorities::holding(&[]), fixture.grant_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.stored().is_active(clock::now()));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller cannot revoke emergency access and is unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::active();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.grant_id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
