//! What tests of deciding agents' paused actions share: the limits
//! approvers are held to, a presence check that knows one code, and callers
//! who are each a different person.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalOrigin, ApprovalRequest, RequestApprovalParams,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::test_support::fakes::FakeMfaVerifier;
use ianua_domain::types::{
    ActionClass, DeclaredAction, HttpMethod, Human, HumanAccount, Initiator, PersonKey, Seconds,
    SessionId,
};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::{AccountHolder, SignedInAccount};
use crate::context::{CallerContext, CallerIdentity, Credential};
use crate::error::AppError;
use crate::services::authentication::approver_presence::{ApproverPresence, ApproverPresencePorts};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::{FakeEncryptor, FakeMfaEnrollmentStore, lockout};
use crate::use_cases::agents::approvals::{
    ApprovalLimits, ApproveActionPorts, ApproveActionUseCase,
};

/// The code [`enrolled_presence`] accepts.
pub const PRESENT_CODE: &str = "246810";

/// The approval limits tests run under: requests opened by hand stay open
/// a day at most, and one person gives at most thirty approvals an hour.
#[must_use]
pub fn approval_limits() -> ApprovalLimits {
    ApprovalLimits {
        max_ttl: time::Duration::days(1),
        per_person_per_hour: 30,
    }
}

/// A presence check over `stores`, accepting [`PRESENT_CODE`] from anyone
/// enrolled there.
#[must_use]
pub fn enrolled_presence(stores: Arc<FakeMfaEnrollmentStore>) -> ApproverPresence {
    ApproverPresence::new(
        lockout(),
        ApproverPresencePorts {
            tenant_mfa: stores.clone(),
            org_mfa: stores,
            encryptor: Arc::new(FakeEncryptor),
            verifier: Arc::new(FakeMfaVerifier {
                valid_code: PRESENT_CODE.to_owned(),
            }),
            ..ApproverPresencePorts::fakes()
        },
    )
}

/// The path of the call [`opened_request`] asks about: a write, not high
/// risk, so one approver without a fresh second factor decides it.
pub const OPENED_TARGET: &str = "/notes";

/// A request `agent` itself opened under no delegation. What an agent
/// raises is taken to show restricted data.
///
/// # Panics
///
/// - Never: the action and lifetime are valid.
#[must_use]
pub fn opened_by_agent(agent: &AgentIdentity<ResolvedTenant>) -> ApprovalRequest<ResolvedTenant> {
    ApprovalRequest::request(RequestApprovalParams {
        agent_id: *agent.id(),
        delegation_id: ActingUnder::NoDelegation,
        origin: ApprovalOrigin::Opened(Initiator::Agent(*agent.id())),
        parties: ActionParties::from_stored(agent.owner().clone(), Vec::new()),
        action_class: DeclaredAction::Declared(ActionClass::Write),
        action: ApprovalAction::for_call(HttpMethod::Post, OPENED_TARGET)
            .expect("the action is valid"),
        ttl_seconds: Seconds::new(900),
    })
    .expect("a request an agent opens under no delegation is valid")
}

/// A request `opener` opened by hand for `agent` to `POST` [`OPENED_TARGET`],
/// under no delegation, open for fifteen minutes.
///
/// # Panics
///
/// - Never: the action and window are valid.
#[must_use]
pub fn opened_request(
    agent: &AgentIdentity<ResolvedTenant>,
    opener: Human,
) -> ApprovalRequest<ResolvedTenant> {
    ApprovalRequest::request(RequestApprovalParams {
        agent_id: *agent.id(),
        delegation_id: ActingUnder::NoDelegation,
        origin: ApprovalOrigin::Opened(Initiator::Human(opener)),
        parties: ActionParties::from_stored(agent.owner().clone(), Vec::new()),
        action_class: DeclaredAction::Declared(ActionClass::Write),
        action: ApprovalAction::for_call(HttpMethod::Post, OPENED_TARGET)
            .expect("the action is valid"),
        ttl_seconds: Seconds::new(900),
    })
    .expect("a request opened by hand under no delegation is valid")
}

/// What every caller holds in their tenant, each caller a person of their
/// own: two callers are two people, as two accounts of different people
/// are. A two-person rule can then be tested with two callers.
pub struct DistinctPeople {
    system: Vec<SystemPermission>,
}

impl DistinctPeople {
    /// Every caller holds `system`, and nothing else.
    #[must_use]
    pub fn holding(system: &[SystemPermission]) -> Self {
        Self {
            system: system.to_vec(),
        }
    }

    /// Every caller holds every system permission.
    #[must_use]
    pub fn holding_everything() -> Self {
        Self::holding(SystemPermission::all())
    }
}

#[async_trait]
impl TenantAuthorities for DistinctPeople {
    async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError> {
        Ok(TenantAuthority::assumed(
            person_of(caller),
            caller.tenant_id(),
            &self.system,
            &[],
        ))
    }

    async fn signed_in(&self, _: &CallerContext) -> Result<SignedInAccount, AppError> {
        Err(AppError::Unauthenticated)
    }

    async fn holder(&self, _: &CallerContext) -> Result<AccountHolder, AppError> {
        Err(AppError::Unauthenticated)
    }

    async fn signed_in_on(
        &self,
        _: &ScopedTenant,
        _: &SessionId,
    ) -> Result<SignedInAccount, AppError> {
        Err(AppError::Unauthenticated)
    }
}

/// The person [`DistinctPeople`] says `caller` is: one of their own, named
/// after the account they act through.
///
/// # Panics
///
/// - When `caller` is an operator, who acts in no tenant as a person.
#[must_use]
pub fn person_of(caller: &CallerContext) -> Human {
    let account = match (caller.identity(), caller.credential()) {
        (_, Credential::Impersonation { user, .. }) => HumanAccount::User(*user),
        (CallerIdentity::TenantUser(user), _) => HumanAccount::User(*user),
        (CallerIdentity::OrgUser(member), _) => HumanAccount::OrgUser(*member),
        (CallerIdentity::Operator(_), _) => panic!("an operator is no person in a tenant"),
    };
    let address = match account {
        HumanAccount::User(id) => format!("user-{id}@example.test"),
        HumanAccount::OrgUser(id) => format!("member-{id}@example.test"),
    };
    Human::new(
        account,
        PersonKey::new(address).expect("an address named after an id is valid"),
    )
}

impl Fake for Arc<ApproveActionUseCase> {
    fn fake() -> Self {
        Arc::new(ApproveActionUseCase::new(
            approval_limits(),
            ApproveActionPorts::fakes(),
        ))
    }
}

impl Fake for Arc<ApproverPresence> {
    fn fake() -> Self {
        Arc::new(ApproverPresence::new(
            lockout(),
            ApproverPresencePorts::fakes(),
        ))
    }
}
