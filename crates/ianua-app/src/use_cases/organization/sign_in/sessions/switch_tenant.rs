//! A member moving their session into a tenant of the organization
//! without signing in again.
//!
//! An organization session works in one tenant, or on the organization
//! alone for a member who reached no tenant when they signed in. Moving
//! swaps it for a new session in the tenant, checked against the member's
//! grants as signing in is: an owner reaches every tenant the organization
//! owns, a plain member only those they were let into, a billing contact
//! or a viewer none. So a member granted a tenant after signing in moves
//! into it without signing in again. The new session carries the
//! sign-in on and ends when the old one would have, so moving never
//! extends a sign-in. The old session ends in the same step.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::access::session::{
    OrgSession, SessionEntry, SessionSwitch,
};
use ianua_domain::domains::organization::access::session_check::OrgSessionCheck;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId, TenantId};

use crate::acting::OrgActors;
use crate::acting::organization::OrgActor;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgTenantGrantStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_org_session;

/// A session moved to another tenant. It holds the refresh token, so it
/// has no `Debug`.
pub struct MovedOrgSession {
    /// The new session.
    pub session_id: SessionId,
    /// The raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
    /// The tenant the new session works in.
    pub tenant_id: TenantId,
}

/// The ports [`SwitchOrgTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SwitchOrgTenantPorts {
    /// Members' sessions.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The tenants a member was let into.
    pub grants: Arc<dyn OrgTenantGrantStore>,
    /// Makes the new session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Moves the caller's session to another tenant of their organization.
pub struct SwitchOrgTenantUseCase {
    ports: SwitchOrgTenantPorts,
}

/// The member moving, their organization, and where to.
struct Move<'a> {
    member: &'a OrgUser,
    organization: &'a Organization,
    target: TenantId,
}

impl SwitchOrgTenantUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SwitchOrgTenantPorts) -> Self {
        Self { ports }
    }

    /// The new session `from` moves to, with its raw refresh token. `from`
    /// is retired in the same step.
    async fn moved(
        &self,
        from: &mut OrgSession,
        to: Move<'_>,
    ) -> Result<(OrgSession, Secret), AppError> {
        let grants = self
            .ports
            .grants
            .list_by_user_in_tenant(to.member.id(), &to.target)
            .await
            .or_internal()?;
        let (raw, hash) = self
            .ports
            .token_generator
            .generate()
            .or_internal()?
            .into_parts();
        let check = check_now(to.organization, to.member);
        let switch = SessionSwitch {
            id: SessionId::new(),
            tenant_id: to.target,
            refresh_token_hash: hash,
            entry: SessionEntry {
                member: to.member,
                organization: to.organization,
                grants: &grants,
            },
        };
        let moved = OrgSession::switch_to(from, &check, switch).map_err(AppError::from_domain)?;
        Ok((moved, raw))
    }

    /// Saves the retired session and the one it moved to.
    async fn keep(&self, from: &OrgSession, moved: &OrgSession) -> Result<(), AppError> {
        let store = self.ports.sessions.as_ref();
        store.save(from).await.or_internal()?;
        store.save(moved).await.or_internal()
    }
}

impl Command for SwitchOrgTenantUseCase {
    type Caller = OrgCaller;
    type Input = TenantId;
    type Output = Result<MovedOrgSession, AppError>;

    /// Moves the caller's session to `target`, ends the old one, and
    /// records `organization.org_session_moved`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts.
    /// - `AppError::Forbidden` when the organization turns the caller away,
    ///   the caller came with a key rather than a session, or the domain
    ///   refuses the move: the tenant is not the organization's, or a plain
    ///   member holds no grant for it.
    /// - `AppError::Domain` when the session already works in `target`.
    /// - `AppError::NotFound` when the caller's session is gone.
    /// - `AppError::Internal` when a store or the audit fails, or no token
    ///   can be made.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        target: TenantId,
    ) -> Result<MovedOrgSession, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let current = session_moving(&actor)?;
        let store = self.ports.sessions.as_ref();
        let mut from = existing_org_session(store, organization.id(), &current).await?;
        let to = Move {
            member: actor.member(),
            organization: &organization,
            target,
        };
        let (mut moved, refresh_token) = self.moved(&mut from, to).await?;
        self.keep(&from, &moved).await?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*moved.org_user_id()),
                moved.take_events(),
            )
            .await
            .or_internal()?;
        Ok(MovedOrgSession {
            session_id: *moved.id(),
            refresh_token,
            tenant_id: target,
        })
    }
}

/// The session the caller moves. A key works in no tenant, so it moves
/// nowhere.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the session no longer passes its
///   check.
/// - `AppError::Forbidden` when the caller came with a key.
fn session_moving(actor: &OrgActor) -> Result<SessionId, AppError> {
    actor
        .control()?
        .session()
        .map(|session| *session.id())
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "organization-a-key-does-not-move-between",
                "a key does not move between tenants"
            ))
        })
}

/// What `member`'s session is held to now, in `organization` as it stands.
fn check_now<'a>(organization: &Organization, member: &'a OrgUser) -> OrgSessionCheck<'a> {
    OrgSessionCheck {
        organization: organization.standing(),
        member,
        idle_timeout: organization.auth_config().idle_timeout_secs(),
        now: clock::now(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::session::SessionPlace;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::types::{ActedBy, OrganizationId, RoleId};

    use super::*;
    use crate::acting::organization::{OrgActing, OrgActingPorts};
    use crate::context::OrgCredential;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgTenantGrantStore, OrgShape, RecordingOrgSessionStore, org_session_of,
        org_session_on_organization, org_shaped, org_store_with, org_user_store_with,
        password_only, test_org_user,
    };
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    /// Acme owning production and staging, a member of it in one role,
    /// signed in to production.
    struct Fixture {
        uc: SwitchOrgTenantUseCase,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        caller: OrgCaller,
        production: TenantId,
        staging: TenantId,
    }

    impl Fixture {
        fn member_in(role: OrgRole, granted: &[TenantId]) -> Self {
            let (production, staging) = (TenantId::new(), TenantId::new());
            Self::with(role, [production, staging], granted)
        }

        fn with(role: OrgRole, tenants: [TenantId; 2], granted: &[TenantId]) -> Self {
            Self::opened_by(role, tenants, granted, |member| {
                org_session_of(member, tenants[0], password_only())
            })
        }

        /// A member in `role` of an organization owning `tenants`, granted
        /// `granted`, signed in to the organization alone.
        fn on_organization(role: OrgRole, tenants: [TenantId; 2], granted: &[TenantId]) -> Self {
            Self::opened_by(role, tenants, granted, org_session_on_organization)
        }

        fn opened_by(
            role: OrgRole,
            tenants: [TenantId; 2],
            granted: &[TenantId],
            open: impl FnOnce(&OrgUser) -> OrgSession,
        ) -> Self {
            let organization_id = OrganizationId::new();
            let member = test_org_user(organization_id, "sam@acme.com", role);
            let session = open(&member);
            let caller = OrgCaller::new(
                *member.id(),
                OrgCredential::Session(*session.id()),
                organization_id,
            );
            let grants: Vec<OrgTenantGrant> = granted
                .iter()
                .map(|tenant| grant(&member, *tenant))
                .collect();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([session]));
            let actors = member_actors(member, &tenants, &sessions);
            Self {
                uc: SwitchOrgTenantUseCase::new(SwitchOrgTenantPorts {
                    sessions: sessions.clone(),
                    grants: Arc::new(FakeOrgTenantGrantStore::holding(grants)),
                    org_actors: Arc::new(actors),
                    ..SwitchOrgTenantPorts::fakes()
                }),
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                caller,
                production: tenants[0],
                staging: tenants[1],
            }
        }

        fn switch_to(&self, target: TenantId) -> Result<MovedOrgSession, AppError> {
            let auditor = test_auditor(self.audit.clone());
            block_on(self.uc.execute(&self.caller, &auditor, target))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn live_in(&self, tenant: TenantId) -> usize {
            self.sessions
                .saved()
                .iter()
                .filter(|session| {
                    session.place() == SessionPlace::Tenant(tenant) && session.is_valid()
                })
                .count()
        }
    }

    /// Resolves the member through their stored session and organization's tenants.
    fn member_actors(
        member: OrgUser,
        tenants: &[TenantId],
        sessions: &Arc<RecordingOrgSessionStore>,
    ) -> OrgActing {
        OrgActing::new(OrgActingPorts {
            organizations: org_store_with([org_shaped(
                *member.organization_id(),
                OrgShape::owning(tenants),
            )]),
            org_users: Arc::new(org_user_store_with([member])),
            org_sessions: sessions.clone(),
            org_api_keys: Fake::fake(),
        })
    }

    fn grant(member: &OrgUser, tenant: TenantId) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: tenant,
            role_id: RoleId::new(),
            granted_by: ActedBy::Platform,
            granted_at: clock::now(),
        })
        .unwrap()
    }

    /// Olivia, an owner, moves from production to staging. A session opens
    /// in staging and the production one ends.
    #[test]
    fn an_owner_moves_to_another_tenant() {
        let fixture = Fixture::member_in(OrgRole::Owner, &[]);

        let moved = fixture.switch_to(fixture.staging).unwrap();

        assert_eq!(moved.tenant_id, fixture.staging);
        assert_eq!(fixture.live_in(fixture.staging), 1);
        assert_eq!(fixture.live_in(fixture.production), 0);
    }

    /// Olivia moves from production to staging. The move is recorded, so
    /// the audit trail shows when she began working in staging.
    #[test]
    fn a_move_is_recorded() {
        let fixture = Fixture::member_in(OrgRole::Owner, &[]);

        fixture.switch_to(fixture.staging).unwrap();

        assert_eq!(fixture.recorded(), ["organization.org_session_moved"]);
    }

    /// Moving to an ungranted tenant fails without recording a session move.
    #[test]
    fn a_refused_move_records_nothing() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture = Fixture::with(OrgRole::Member, [production, staging], &[production]);

        let result = fixture.switch_to(staging);

        assert!(result.is_err());
        assert!(fixture.recorded().is_empty());
    }

    /// Sam, a plain member granted staging, moves there from production.
    #[test]
    fn a_plain_member_moves_to_a_granted_tenant() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture = Fixture::with(
            OrgRole::Member,
            [production, staging],
            &[production, staging],
        );

        let moved = fixture.switch_to(staging).unwrap();

        assert_eq!(moved.tenant_id, staging);
    }

    /// A member cannot move from a granted tenant into an ungranted one;
    /// the source session stays valid and no target session opens.
    #[test]
    fn a_plain_member_is_refused_a_tenant_without_a_grant() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture = Fixture::with(OrgRole::Member, [production, staging], &[production]);

        let result = fixture.switch_to(staging);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.live_in(production), 1);
        assert_eq!(fixture.live_in(staging), 0);
    }

    /// Sam signed in before anyone granted him a tenant, so his session
    /// works on the organization alone. Ann grants him staging, and he
    /// moves into it without signing in again. The move is recorded.
    #[test]
    fn a_member_on_the_organization_alone_moves_into_a_tenant_granted_since() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture = Fixture::on_organization(OrgRole::Member, [production, staging], &[staging]);

        let moved = fixture.switch_to(staging).unwrap();

        assert_eq!(moved.tenant_id, staging);
        assert_eq!(fixture.live_in(staging), 1);
        assert_eq!(fixture.recorded(), ["organization.org_session_moved"]);
    }

    /// An organization-only session cannot move into an ungranted tenant;
    /// no session opens there and no move is recorded.
    #[test]
    fn a_member_on_the_organization_alone_moves_into_no_ungranted_tenant() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture = Fixture::on_organization(OrgRole::Member, [production, staging], &[staging]);

        let result = fixture.switch_to(production);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.live_in(production), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A billing contact cannot enter a tenant even with a grant, and no
    /// session opens there.
    #[test]
    fn a_billing_contact_moves_into_no_tenant() {
        let (production, staging) = (TenantId::new(), TenantId::new());
        let fixture =
            Fixture::on_organization(OrgRole::Billing, [production, staging], &[production]);

        let result = fixture.switch_to(production);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.live_in(production), 0);
    }

    /// An owner cannot move to a tenant outside the organization; the
    /// original session remains valid.
    #[test]
    fn a_tenant_of_another_organization_is_refused() {
        let fixture = Fixture::member_in(OrgRole::Owner, &[]);

        let result = fixture.switch_to(TenantId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.live_in(fixture.production), 1);
    }

    /// Olivia asks to move to production, where she already works. Nothing
    /// moves.
    #[test]
    fn moving_to_the_same_tenant_is_refused() {
        let fixture = Fixture::member_in(OrgRole::Owner, &[]);

        let result = fixture.switch_to(fixture.production);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.live_in(fixture.production), 1);
    }

    /// A signed-out session cannot move between tenants.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = SwitchOrgTenantUseCase::new(SwitchOrgTenantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..SwitchOrgTenantPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        let result = block_on(use_case.execute(&test_org_caller(), &auditor, TenantId::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An API key cannot authorize moving a session between tenants.
    #[test]
    fn a_key_does_not_move_between_tenants() {
        let use_case = SwitchOrgTenantUseCase::new(SwitchOrgTenantPorts {
            org_actors: Arc::new(FakeOrgActors::through_key(OrgRole::Owner, Vec::new())),
            ..SwitchOrgTenantPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        let result = block_on(use_case.execute(&test_org_caller(), &auditor, TenantId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
