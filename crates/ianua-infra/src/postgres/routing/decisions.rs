//! Whether a caller meets a route's policy, and whether the tenant's
//! records know a caller and let it act: the store of
//! `ports/routing/decisions.rs`.
//!
//! It holds no rule of its own. It reads the caller's account, agent or
//! consumer through their stores, and what a person holds through the
//! access records, and asks the domain: the record whether it may act now,
//! the policy whether what is held meets it. A person the tenant does not
//! know is undecided, and anything that fails or runs past its time is an
//! error, which every caller refuses.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentStore as _;
use ianua_app::ports::authorization::{AccessRecordStore as _, Holder};
use ianua_app::ports::consumers::ConsumerStore as _;
use ianua_app::ports::identity::UserStore as _;
use ianua_app::ports::routing::{PolicyDecision, PolicyDecisionPoint};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::access::question::Standing;
use ianua_domain::domains::routing::policy::{PolicyStanding, RouteCaller, RoutePolicy};
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ConsumerId, PrincipalRef, UserId};

use crate::postgres::agents::PgAgentStore;
use crate::postgres::authorization::PgAccessRecordStore;
use crate::postgres::consumers::PgConsumerStore;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::identity::PgUserStore;

/// How long one answer may take, every read together. The gateway holds a
/// connection open while it waits.
const DECISION_TIME: Duration = Duration::from_secs(2);

/// The gateway's policy decision point over the tenant's own records.
pub struct PgPolicyDecisionPoint {
    users: PgUserStore,
    agents: PgAgentStore,
    consumers: PgConsumerStore,
    records: PgAccessRecordStore,
}

impl TenantScoped for PgPolicyDecisionPoint {}

impl PgPolicyDecisionPoint {
    /// A decision point reading callers and what they hold from
    /// `databases`, checking stored names against `limits` as the user
    /// store does.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self {
            users: PgUserStore::new(Arc::clone(&databases), limits),
            agents: PgAgentStore::new(Arc::clone(&databases)),
            consumers: PgConsumerStore::new(Arc::clone(&databases)),
            records: PgAccessRecordStore::new(databases),
        }
    }

    /// The decision for `person` against `policy`, with no bound on time.
    async fn decided(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        policy: &RoutePolicy,
    ) -> Result<PolicyDecision, DomainError> {
        match self.user_standing(tenant_id, person).await? {
            Standing::Unknown => return Ok(PolicyDecision::Undecided),
            Standing::Barred => return Ok(PolicyDecision::Deny),
            Standing::Good => {}
        }
        let principal = PrincipalRef::User(*person);
        let records = self
            .records
            .load_held_by(tenant_id, Holder::of(principal))
            .await?;
        let holdings = records
            .access(**tenant_id)
            .permissions_held_by(principal, clock::now())?;
        match policy.standing_of(RouteCaller::Person(&holdings)) {
            PolicyStanding::Met => Ok(PolicyDecision::Permit),
            PolicyStanding::NothingListed
            | PolicyStanding::PermissionMissing
            | PolicyStanding::ScopeMissing => Ok(PolicyDecision::Deny),
        }
    }

    /// Whether the records know `principal` and let it act, with no bound
    /// on time.
    async fn stands(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Standing, DomainError> {
        match principal {
            PrincipalRef::User(user) => self.user_standing(tenant_id, user).await,
            PrincipalRef::Agent(agent) => self.agent_standing(tenant_id, agent).await,
            PrincipalRef::Consumer(consumer) => self.consumer_standing(tenant_id, consumer).await,
            PrincipalRef::OrgUser(_) => Ok(Standing::Unknown),
        }
    }

    /// Whether `user` has an account here that may sign in now.
    async fn user_standing(
        &self,
        tenant_id: &ScopedTenant,
        user: &UserId,
    ) -> Result<Standing, DomainError> {
        let Some(account) = self.users.find_by_id(tenant_id, user).await? else {
            return Ok(Standing::Unknown);
        };
        if !account.can_authenticate() {
            return Ok(Standing::Barred);
        }
        Ok(Standing::Good)
    }

    /// Whether `agent` is registered here and may act now.
    async fn agent_standing(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Standing, DomainError> {
        let Some(found) = self.agents.find_by_id(tenant_id, agent).await? else {
            return Ok(Standing::Unknown);
        };
        if !found.may_act_at(clock::now()) {
            return Ok(Standing::Barred);
        }
        Ok(Standing::Good)
    }

    /// Whether `consumer` is registered here and enabled.
    async fn consumer_standing(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &ConsumerId,
    ) -> Result<Standing, DomainError> {
        let Some(found) = self.consumers.find_by_id(tenant_id, consumer).await? else {
            return Ok(Standing::Unknown);
        };
        if !found.is_active() {
            return Ok(Standing::Barred);
        }
        Ok(Standing::Good)
    }
}

#[async_trait]
impl PolicyDecisionPoint for PgPolicyDecisionPoint {
    async fn decide(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        policy: &RoutePolicy,
    ) -> Result<PolicyDecision, DomainError> {
        tokio::time::timeout(DECISION_TIME, self.decided(tenant_id, person, policy))
            .await
            .map_err(DomainError::infra)?
    }

    async fn standing(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Standing, DomainError> {
        tokio::time::timeout(DECISION_TIME, self.stands(tenant_id, principal))
            .await
            .map_err(DomainError::infra)?
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::AgentStore;
    use ianua_app::ports::authorization::{RoleAssignmentStore, RoleStore};
    use ianua_app::ports::consumers::ConsumerStore;
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentIdentityRow};
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{Role, RoleRow};
    use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerRow, ConsumerStatus};
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{OrgUserId, TenantId};

    use super::*;
    use crate::postgres::authorization::{PgRoleAssignmentStore, PgRoleStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::agent_row;
    use crate::test_support::rows::authorization::{assignment, role_row};
    use crate::test_support::rows::consumers::consumer_row;
    use crate::test_support::rows::identity::{user_row, user_row_standing};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    struct Fixture {
        db: TestDb,
        decisions: PgPolicyDecisionPoint,
        tenant: ScopedTenant,
    }

    /// A fresh database, the decision point on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            decisions: PgPolicyDecisionPoint::new(
                Arc::clone(&db.databases),
                DomainLimits::default(),
            ),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    impl Fixture {
        /// Keeps `user` in the tenant, through the real user store.
        async fn person(&self, user: &User<ResolvedTenant>) -> UserId {
            PgUserStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .save(&self.tenant, user)
                .await
                .unwrap();
            *user.id()
        }

        /// Keeps the agent `row` describes, through the real agent store.
        async fn agent(&self, row: AgentIdentityRow) -> AgentId {
            let agent = AgentIdentity::reconstitute(row).unwrap();
            PgAgentStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &agent)
                .await
                .unwrap();
            *agent.id()
        }

        /// Keeps the consumer `row` describes, through the real consumer
        /// store.
        async fn consumer(&self, row: ConsumerRow) -> ConsumerId {
            let consumer = Consumer::reconstitute(row).unwrap();
            PgConsumerStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &consumer)
                .await
                .unwrap();
            *consumer.id()
        }

        /// Gives `person` a role granting `permissions`, through the real
        /// role and assignment stores.
        async fn grant(&self, person: UserId, permissions: Vec<SystemPermission>) {
            let role = Role::reconstitute(RoleRow {
                system_permissions: permissions,
                ..role_row("granting")
            })
            .unwrap();
            PgRoleStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &role)
                .await
                .unwrap();
            PgRoleAssignmentStore::new(Arc::clone(&self.db.databases))
                .save(
                    &self.tenant,
                    &assignment(PrincipalRef::User(person), *role.id()),
                )
                .await
                .unwrap();
        }

        async fn decide(&self, person: UserId, policy: &RoutePolicy) -> PolicyDecision {
            self.decisions
                .decide(&self.tenant, &person, policy)
                .await
                .unwrap()
        }

        async fn standing(&self, principal: PrincipalRef) -> Standing {
            self.decisions
                .standing(&self.tenant, &principal)
                .await
                .unwrap()
        }
    }

    fn active(email: &str) -> User<ResolvedTenant> {
        User::reconstitute(user_row(email)).unwrap()
    }

    /// A person holding one of the route's permissions through a role is
    /// let through.
    #[tokio::test]
    async fn a_person_holding_the_permission_is_permitted() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        f.grant(ann, vec![VIEW_USERS]).await;

        let decision = f
            .decide(ann, &RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]))
            .await;

        assert_eq!(decision, PolicyDecision::Permit);
    }

    /// A user with view permission receives a deny decision for a route
    /// requiring update permission.
    #[tokio::test]
    async fn a_person_without_the_permission_is_denied() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        f.grant(ann, vec![VIEW_USERS]).await;

        let decision = f
            .decide(
                ann,
                &RoutePolicy::RequireSystemPermission(vec![UPDATE_USERS]),
            )
            .await;

        assert_eq!(decision, PolicyDecision::Deny);
    }

    /// An unknown user yields an undecided result for an authenticated route.
    #[tokio::test]
    async fn an_unknown_person_is_undecided() {
        let f = fixture().await;

        let decision = f.decide(UserId::new(), &RoutePolicy::Authenticated).await;

        assert_eq!(decision, PolicyDecision::Undecided);
    }

    /// A locked user receives a deny decision even when their role grants
    /// the route's required permission.
    #[tokio::test]
    async fn an_account_that_may_not_sign_in_is_denied() {
        let f = fixture().await;
        let locked =
            User::reconstitute(user_row_standing("lee@example.com", UserStatus::Locked)).unwrap();
        let lee = f.person(&locked).await;
        f.grant(lee, vec![VIEW_USERS]).await;

        let decision = f
            .decide(lee, &RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]))
            .await;

        assert_eq!(decision, PolicyDecision::Deny);
    }

    /// A user holding every system permission is denied by both an empty
    /// scope policy and an empty system-permission policy.
    #[tokio::test]
    async fn a_scope_route_and_an_empty_list_deny_a_person() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        f.grant(ann, SystemPermission::all().to_vec()).await;

        let scoped = f.decide(ann, &RoutePolicy::RequireScope(Vec::new())).await;
        let empty = f
            .decide(ann, &RoutePolicy::RequireSystemPermission(Vec::new()))
            .await;

        assert_eq!(scoped, PolicyDecision::Deny);
        assert_eq!(empty, PolicyDecision::Deny);
    }

    /// Evaluating a user from another tenant returns an undecided result.
    #[tokio::test]
    async fn a_person_of_another_tenant_is_undecided() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        let elsewhere = ScopedTenant::for_background(TenantId::new());

        let decision = f
            .decisions
            .decide(&elsewhere, &ann, &RoutePolicy::Authenticated)
            .await
            .unwrap();

        assert_eq!(decision, PolicyDecision::Undecided);
    }

    /// An invalid stored user email makes policy evaluation return an
    /// infrastructure error.
    #[tokio::test]
    async fn a_corrupt_account_is_an_error() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        f.db.tamper("UPDATE users SET email = 'not an address'")
            .await;

        let result = f
            .decisions
            .decide(&f.tenant, &ann, &RoutePolicy::Authenticated)
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An active person, agent and consumer of the tenant each stand in
    /// good standing.
    #[tokio::test]
    async fn callers_the_tenant_keeps_stand_good() {
        let f = fixture().await;
        let ann = f.person(&active("ann@example.com")).await;
        let helper = f.agent(agent_row("helper")).await;
        let billing = f.consumer(consumer_row("billing")).await;

        assert_eq!(f.standing(PrincipalRef::User(ann)).await, Standing::Good);
        assert_eq!(
            f.standing(PrincipalRef::Agent(helper)).await,
            Standing::Good
        );
        assert_eq!(
            f.standing(PrincipalRef::Consumer(billing)).await,
            Standing::Good
        );
    }

    /// Standing checks report a locked user, suspended agent and disabled
    /// consumer as barred.
    #[tokio::test]
    async fn callers_that_may_not_act_are_barred() {
        let f = fixture().await;
        let locked =
            User::reconstitute(user_row_standing("lee@example.com", UserStatus::Locked)).unwrap();
        let lee = f.person(&locked).await;
        let paused = f
            .agent(AgentIdentityRow {
                status: AgentStatus::Suspended,
                ..agent_row("paused")
            })
            .await;
        let off = f
            .consumer(ConsumerRow {
                status: ConsumerStatus::Disabled,
                ..consumer_row("off")
            })
            .await;

        assert_eq!(f.standing(PrincipalRef::User(lee)).await, Standing::Barred);
        assert_eq!(
            f.standing(PrincipalRef::Agent(paused)).await,
            Standing::Barred
        );
        assert_eq!(
            f.standing(PrincipalRef::Consumer(off)).await,
            Standing::Barred
        );
    }

    /// Standing checks report absent agents and consumers, a consumer from
    /// another tenant, and organization members as unknown.
    #[tokio::test]
    async fn callers_the_tenant_does_not_keep_are_unknown() {
        let f = fixture().await;
        let billing = f.consumer(consumer_row("billing")).await;
        let elsewhere = ScopedTenant::for_background(TenantId::new());

        let foreign = f
            .decisions
            .standing(&elsewhere, &PrincipalRef::Consumer(billing))
            .await
            .unwrap();

        assert_eq!(
            f.standing(PrincipalRef::Agent(AgentId::new())).await,
            Standing::Unknown
        );
        assert_eq!(
            f.standing(PrincipalRef::Consumer(ConsumerId::new())).await,
            Standing::Unknown
        );
        assert_eq!(
            f.standing(PrincipalRef::OrgUser(OrgUserId::new())).await,
            Standing::Unknown
        );
        assert_eq!(foreign, Standing::Unknown);
    }
}
