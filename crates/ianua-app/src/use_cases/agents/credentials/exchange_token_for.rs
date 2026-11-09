//! Exchange token for agent: the client-credentials grant for autonomous
//! agents.
//!
//! An agent signs in as itself with an assertion its own key signed. The
//! capabilities it asks for are capped by the authority one person granted
//! it, and that capped set is minted as a delegation of its own, cut from
//! theirs, for a task token. Every failure denies.
//!
//! The cap is the point. Signing in proves which agent is calling, not what
//! it may do. Minting what the request names would let anyone holding an
//! agent's key issue it tenant-wide authority. An agent nobody granted
//! anything to mints nothing.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, OwnedTokenRequest, Revoker,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActingFor, ActorRef, AgentId, Audience, DelegationId, EventLabel, Lifetime, PrincipalRef,
};

use crate::acting::AgentActors;
use crate::acting::agent::SignedInAgent;
use crate::auditor::RequestAuditor;
use crate::context::AgentAssertion;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{DelegationStore, TaskTokenIssuer};
use crate::ports::identity::UserStore;
use crate::ports::notifications::AlertThrottle;
use crate::ports::organization::OrgUserStore;
use crate::services::agents::sign_in::{AgentDoor, signed_in_at};
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::credentials::token_ceiling::{
    Ceiling, CeilingSources, token_ceiling,
};
use crate::use_cases::agents::delegation::granting::grant::{TaskTokenMinting, issued_task_token};
use crate::use_cases::agents::delegation::granting::lineage::principal_chain;

/// What an agent presents to exchange for a task token.
pub struct ExchangeTokenForAgentRequest {
    /// The agent and the assertion its key signed.
    pub presented: AgentAssertion,
    /// The capabilities asked for. Capped to the authority the agent holds.
    pub granted: CapabilitySet,
    /// The limits asked for. Held inside every delegation the token is cut
    /// from.
    pub constraints: DelegationConstraints,
}

/// A minted delegation and the task token signed for it.
pub struct ExchangedToken {
    /// The delegation the agent minted for itself.
    pub delegation: Delegation<ResolvedTenant>,
    /// The signed task token.
    pub task_token: String,
    /// The agent, then the principals its authority descends from.
    pub chain: Vec<PrincipalRef>,
}

/// The ports [`ExchangeTokenForAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExchangeTokenPorts {
    /// How the agent signs in as itself.
    pub agent_actors: Arc<dyn AgentActors>,
    /// The delegations the token is cut from, and the one it is minted as.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Signs the task token.
    pub token_issuer: Arc<dyn TaskTokenIssuer>,
    /// Works out the tenant's own issuer the task token names.
    pub issuers: TenantIssuers,
    /// Tenant users, for whether a delegator may still sign in.
    pub user_store: Arc<dyn UserStore>,
    /// Organization members, for whether a delegator may still sign in.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Holds back records of a refused sign-in that looks like an attack
    /// to one a window per agent and kind of attack.
    pub alert_throttle: Arc<dyn AlertThrottle>,
}

/// Exchanges an agent's own assertion for a task token.
pub struct ExchangeTokenForAgentUseCase {
    ports: ExchangeTokenPorts,
    audience: Audience,
    max_ttl: Lifetime,
}

impl ExchangeTokenForAgentUseCase {
    /// A use case verifying assertions for `audience` and minting tokens
    /// that live at most `max_ttl`, working through `ports`.
    #[must_use]
    pub fn new(ports: ExchangeTokenPorts, audience: Audience, max_ttl: Lifetime) -> Self {
        Self {
            ports,
            audience,
            max_ttl,
        }
    }

    /// The delegation `signed` mints for itself within `ceiling`, with the
    /// delegations it was cut from.
    fn minted(
        &self,
        signed: &SignedInAgent,
        ceiling: Ceiling,
        requested: DelegationConstraints,
    ) -> Result<(Delegation<ResolvedTenant>, Vec<Delegation<ResolvedTenant>>), AppError> {
        let Ceiling {
            delegations: sources,
            granted,
        } = ceiling;
        let delegation = Delegation::grant_owned_within(
            OwnedTokenRequest {
                agent: &signed.acting,
                agent_label: EventLabel::of(signed.agent.name().as_str()),
                granted,
                requested,
                max_ttl: self.max_ttl,
            },
            &sources,
        )
        .map_err(AppError::from_domain)?;
        Ok((delegation, sources))
    }

    /// The token endpoint as a door the agent signs in at, in `tenant`.
    fn door<'a>(&'a self, tenant: &'a ScopedTenant) -> AgentDoor<'a> {
        AgentDoor {
            actors: self.ports.agent_actors.as_ref(),
            attacks: self.ports.alert_throttle.as_ref(),
            tenant,
            audience: &self.audience,
        }
    }

    fn ceiling_sources(&self) -> CeilingSources<'_> {
        CeilingSources {
            delegations: self.ports.delegation_store.as_ref(),
            users: self.ports.user_store.as_ref(),
            org_users: self.ports.org_user_store.as_ref(),
        }
    }
}

impl Command for ExchangeTokenForAgentUseCase {
    type Caller = ScopedTenant;
    type Input = ExchangeTokenForAgentRequest;
    type Output = Result<ExchangedToken, AppError>;

    /// Signs the agent in, mints the delegation it may have, saves it with
    /// where its authority came from, and signs its task token.
    ///
    /// A sign-in refused as a replayed or forged assertion, or one naming
    /// another agent, records `agents.token_attack_refused` about the agent
    /// it named, once a window per agent and kind of attack.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the agent does not sign in: it is
    ///   unknown or may not act now, the assertion names no key of its, the
    ///   key may not sign it in, the assertion does not verify, names
    ///   another agent, or was used before.
    /// - `AppError::Forbidden` when the agent holds none of what it asked
    ///   for, the limits asked for widen what it holds, or what it holds is
    ///   revoked while the token is minted.
    /// - `AppError::Internal` on persistence or signing failure, or when a
    ///   refusal that looks like an attack cannot be recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: ExchangeTokenForAgentRequest,
    ) -> Result<ExchangedToken, AppError> {
        let signed = signed_in_at(self.door(tenant), auditor, &req.presented).await?;
        let ceiling = token_ceiling(
            &self.ceiling_sources(),
            tenant,
            signed.agent.id(),
            &req.granted,
        )
        .await?;
        let (mut delegation, sources) = self.minted(&signed, ceiling, req.constraints)?;
        let store = self.ports.delegation_store.as_ref();
        save_with_provenance(store, tenant, &delegation, &sources).await?;
        let minting = TaskTokenMinting {
            tokens: self.ports.token_issuer.as_ref(),
            issuers: &self.ports.issuers,
        };
        let task_token = issued_task_token(minting, tenant, &delegation).await?;
        let minted = delegation.take_events(tenant);
        auditor
            .dispatch_by(&agent_itself(signed.agent.id()), minted)
            .await
            .or_internal()?;
        let chain = derived_chain(store, tenant, &sources).await?;
        Ok(ExchangedToken {
            delegation,
            task_token,
            chain,
        })
    }
}

/// Refuses a token whose sources stopped being live while it was minted,
/// revoking it so no live token is left behind them.
async fn ensure_sources_still_live(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    sources: &[DelegationId],
    minted: &Delegation<ResolvedTenant>,
) -> Result<(), AppError> {
    let now = clock::now();
    for source in sources {
        let still_live = store
            .find_by_id(tenant, source)
            .await
            .or_internal()?
            .is_some_and(|d| d.is_valid(now));
        if still_live {
            continue;
        }
        let mut revoked = minted.clone();
        revoked
            .revoke(Revoker::Platform)
            .map_err(AppError::from_domain)?;
        store.save(tenant, &revoked).await.or_internal()?;
        return Err(AppError::Forbidden(message!(
            "agents-the-authority-behind-this-token-was",
            "the authority behind this token was revoked while it was minted"
        )));
    }
    Ok(())
}

/// Saves `minted` and the delegations it was cut from, then checks they
/// are still live.
async fn save_with_provenance(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    minted: &Delegation<ResolvedTenant>,
    cut_from: &[Delegation<ResolvedTenant>],
) -> Result<(), AppError> {
    store.save(tenant, minted).await.or_internal()?;
    let sources: Vec<DelegationId> = cut_from.iter().map(|d| *d.id()).collect();
    store
        .record_provenance(tenant, minted.id(), &sources)
        .await
        .or_internal()?;
    ensure_sources_still_live(store, tenant, &sources, minted).await
}

/// The agent, then the principals behind the delegations it cut the token
/// from.
async fn derived_chain(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    cut_from: &[Delegation<ResolvedTenant>],
) -> Result<Vec<PrincipalRef>, AppError> {
    let Some(source) = cut_from.first() else {
        return Ok(Vec::new());
    };
    let mut chain = vec![PrincipalRef::Agent(*source.delegate())];
    chain.extend(principal_chain(store, tenant, source).await?);
    Ok(chain)
}

/// The agent acting on its own authority, as the audit trail names it.
fn agent_itself(agent: &AgentId) -> ActorRef {
    ActorRef::Agent {
        id: *agent,
        on_behalf_of: ActingFor::Itself,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::{
        DelegationRow, DelegationStatus, TokenKey,
    };
    use ianua_domain::domains::agents::identity::agent::{AgentIdentity, AgentIdentityRow};
    use ianua_domain::domains::agents::identity::credential::AgentCredential;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::agents::identity::token_attack::AssertionFault;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::{OrgUser, OrgUserRow};
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::{Joining, OrganizationId, Seconds, UserId};

    use super::*;
    use crate::acting::agent::{AgentActing, AgentActingPorts};
    use crate::ports::agents::{AgentCredentialStore, AgentStore};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeAssertionVerifier, FakeDelegationStore,
        agent_row, caller_person, delegation_row, key_row, signing_in,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::notification_delivery::FakeAlertThrottle;
    use crate::test_support::organization::{FakeOrgUserStore, org_user_store_with, test_org_user};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const AUDIENCE: &str = "https://ianua.test/oauth/token";

    struct Bench {
        agent: AgentId,
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        users: Arc<FakeUserStore>,
        org_users: Arc<FakeOrgUserStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn with_agent(row: AgentIdentityRow) -> Self {
            let agents = Arc::new(FakeAgentStore::empty());
            let agent = row.id;
            block_on(agents.save(
                &test_ctx().tenant(),
                &AgentIdentity::reconstitute(row).unwrap(),
            ))
            .unwrap();
            Self {
                agent,
                agents,
                delegations: Arc::new(FakeDelegationStore::empty()),
                users: Arc::new(FakeUserStore::empty()),
                org_users: Arc::new(FakeOrgUserStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with_agent(agent_row(AgentId::new(), caller_person()))
        }

        fn delegator(&self, address: &str) -> UserId {
            let user = UserId::new();
            self.users.add_active_user(user, address);
            user
        }

        fn granted(&self, row: DelegationRow) -> DelegationId {
            let delegation = Delegation::reconstitute(row).unwrap();
            block_on(self.delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            *delegation.id()
        }

        fn granted_by(&self, delegator: PrincipalRef, granted: CapabilitySet) -> DelegationId {
            self.granted(DelegationRow {
                granted,
                ..delegation_row(self.agent, delegator)
            })
        }

        fn ready(self) -> Self {
            let ann = self.delegator("ann@acme.test");
            self.granted_by(PrincipalRef::User(ann), caps(RoutingAction::View));
            self
        }

        fn ports(&self) -> ExchangeTokenPorts {
            let (sign_in, _) = signing_in(self.agents.clone(), self.agent);
            ExchangeTokenPorts {
                agent_actors: Arc::new(AgentActing::new(sign_in)),
                delegation_store: self.delegations.clone(),
                user_store: self.users.clone(),
                org_user_store: self.org_users.clone(),
                ..ExchangeTokenPorts::fakes()
            }
        }

        fn exchange_with(
            &self,
            ports: ExchangeTokenPorts,
            granted: CapabilitySet,
        ) -> Result<ExchangedToken, AppError> {
            self.exchange_asking(
                ports,
                granted,
                DelegationConstraints::new(Seconds::new(600), 0).unwrap(),
            )
        }

        fn exchange_asking(
            &self,
            ports: ExchangeTokenPorts,
            granted: CapabilitySet,
            constraints: DelegationConstraints,
        ) -> Result<ExchangedToken, AppError> {
            let use_case = ExchangeTokenForAgentUseCase::new(
                ports,
                Audience::new(AUDIENCE).unwrap(),
                Lifetime::seconds(3600).unwrap(),
            );
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                ExchangeTokenForAgentRequest {
                    presented: AgentAssertion {
                        agent_id: self.agent,
                        assertion: "signed.assertion".to_owned(),
                    },
                    granted,
                    constraints,
                },
            ))
        }

        fn exchange(&self, granted: CapabilitySet) -> Result<ExchangedToken, AppError> {
            self.exchange_with(self.ports(), granted)
        }

        fn live_delegations(&self) -> usize {
            self.delegations
                .all()
                .iter()
                .filter(|d| d.is_valid(clock::now()))
                .count()
        }
    }

    fn caps(action: RoutingAction) -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(action)], vec![])
    }

    fn view_and_manage() -> CapabilitySet {
        CapabilitySet::new(
            vec![
                SystemPermission::Routing(RoutingAction::View),
                SystemPermission::Routing(RoutingAction::Manage),
            ],
            vec![],
        )
    }

    fn deactivated(member: &OrgUser) -> OrgUser {
        OrgUser::reconstitute(OrgUserRow {
            id: *member.id(),
            organization_id: *member.organization_id(),
            email: member.email().clone(),
            display_name: member.display_name().clone(),
            password_hash: member.password_hash().clone(),
            status: OrgUserStatus::Deactivated,
            role: member.role(),
            email_standing: member.address().standing(),
            locale: member.locale().clone(),
            timezone: member.timezone().clone(),
            created_at: member.created_at(),
            updated_at: member.updated_at(),
            joining: Joining::from_stored(member.joined_at()),
            credentials_changed_at: member.credentials_changed_at(),
            vouching: ianua_domain::domains::identity::account::vouching::Vouching::Absent,
        })
        .unwrap()
    }

    /// Ann let her agent view routes. It signs in and asks for that. It
    /// gets a token, minted as a delegation of its own, and both the grant
    /// and the token are recorded.
    #[test]
    fn a_signed_in_agent_gets_a_task_token() {
        let bench = Bench::new().ready();

        let exchanged = bench.exchange(caps(RoutingAction::View)).unwrap();

        assert_eq!(exchanged.task_token, "test.task.token");
        assert!(exchanged.delegation.is_self_rooted());
        assert_eq!(bench.delegations.count(), 2);
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_granted", "agents.token_issued"]
        );
    }

    /// The token names the agent first and then Ann, whose grant capped it,
    /// so an audit reaches the person at the root.
    #[test]
    fn the_token_carries_the_agent_then_the_person_whose_grant_capped_it() {
        let bench = Bench::new();
        let ann = bench.delegator("ann@acme.test");
        bench.granted_by(PrincipalRef::User(ann), caps(RoutingAction::View));

        let exchanged = bench.exchange(caps(RoutingAction::View)).unwrap();

        assert_eq!(
            exchanged.chain,
            [PrincipalRef::Agent(bench.agent), PrincipalRef::User(ann)]
        );
    }

    /// Authority from a deactivated user cannot support a token exchange;
    /// the original grant remains the only stored delegation.
    #[test]
    fn a_grant_from_a_deactivated_user_lends_nothing() {
        let bench = Bench::new();
        let ann = UserId::new();
        bench
            .users
            .add(stored_user(ann, "ann@acme.test", UserStatus::Deactivated));
        bench.granted_by(PrincipalRef::User(ann), caps(RoutingAction::View));

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.delegations.count(), 1);
    }

    /// A grant whose user account is absent cannot authorize a task token.
    #[test]
    fn a_grant_from_a_person_who_no_longer_exists_lends_nothing() {
        let bench = Bench::new();
        bench.granted_by(PrincipalRef::User(UserId::new()), caps(RoutingAction::View));

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann, an owner of Acme, granted the agent authority. She may still
    /// sign in, so her grant lends.
    #[test]
    fn a_grant_from_an_active_org_member_lends() {
        let mut bench = Bench::new();
        let ann = test_org_user(OrganizationId::new(), "ann@acme.test", OrgRole::Owner);
        bench.granted_by(PrincipalRef::OrgUser(*ann.id()), caps(RoutingAction::View));
        bench.org_users = Arc::new(org_user_store_with([ann]));

        assert!(bench.exchange(caps(RoutingAction::View)).is_ok());
    }

    /// A deactivated organization member's grant cannot authorize a token
    /// exchange.
    #[test]
    fn a_grant_from_a_deactivated_org_member_lends_nothing() {
        let mut bench = Bench::new();
        let ann = deactivated(&test_org_user(
            OrganizationId::new(),
            "ann@acme.test",
            OrgRole::Owner,
        ));
        bench.granted_by(PrincipalRef::OrgUser(*ann.id()), caps(RoutingAction::View));
        bench.org_users = Arc::new(org_user_store_with([ann]));

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A suspended agent cannot exchange its assertion for a token, and
    /// no delegation is added to its existing grant.
    #[test]
    fn a_suspended_agent_is_refused() {
        let bench = Bench::with_agent(AgentIdentityRow {
            status: AgentStatus::Suspended,
            ..agent_row(AgentId::new(), caller_person())
        })
        .ready();

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.delegations.count(), 1);
    }

    /// With two active credentials, the token binds to k3, whose assertion
    /// signed the agent in, even though k2 was enrolled after it.
    #[test]
    fn a_bound_token_is_bound_to_the_key_that_signed_the_agent_in() {
        let bench = Bench::new().ready();
        let credentials = Arc::new(FakeAgentCredentialStore::empty());
        let key = |kid| AgentCredential::reconstitute(key_row(bench.agent, kid)).unwrap();
        let (k3, k2) = (key("k3"), key("k2"));
        for enrolled in [&k3, &k2] {
            block_on(credentials.save(&test_ctx().tenant(), enrolled)).unwrap();
        }
        let ports = ExchangeTokenPorts {
            agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
                credential_store: credentials,
                verifier: Arc::new(FakeAssertionVerifier::accepting("k3", bench.agent)),
                ..signing_in(bench.agents.clone(), bench.agent).0
            })),
            ..bench.ports()
        };
        let bound = DelegationConstraints::new(Seconds::new(600), 0)
            .unwrap()
            .sender_constrained();

        let exchanged = bench
            .exchange_asking(ports, caps(RoutingAction::View), bound)
            .unwrap();

        assert_eq!(
            exchanged.delegation.token_key(),
            TokenKey::SignedInWith(*k3.id())
        );
    }

    /// An invalid assertion is refused without adding a delegation to the
    /// agent's existing grant.
    #[test]
    fn a_rejected_assertion_mints_nothing() {
        let bench = Bench::new().ready();
        let ports = ExchangeTokenPorts {
            agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
                verifier: Arc::new(FakeAssertionVerifier::rejecting("agent-key")),
                ..signing_in(bench.agents.clone(), bench.agent).0
            })),
            ..bench.ports()
        };

        let result = bench.exchange_with(ports, caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.delegations.count(), 1);
    }

    /// The ports with Ann's agent's sign-in refusing every assertion for
    /// `fault`, and `throttle` holding back the records of attacks.
    fn refusing(
        bench: &Bench,
        fault: AssertionFault,
        throttle: &Arc<FakeAlertThrottle>,
    ) -> ExchangeTokenPorts {
        ExchangeTokenPorts {
            agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
                verifier: Arc::new(FakeAssertionVerifier::refusing("agent-key", fault)),
                ..signing_in(bench.agents.clone(), bench.agent).0
            })),
            alert_throttle: throttle.clone(),
            ..bench.ports()
        }
    }

    /// The records of attacks on agents the bench's sink was handed, with
    /// how many attempts each stands for.
    fn attack_records(bench: &Bench) -> Vec<String> {
        bench
            .sink
            .payloads
            .lock()
            .unwrap()
            .iter()
            .filter(|(kind, _)| kind == "agents.token_attack_refused")
            .map(|(_, payload)| match payload.value("attempts") {
                Some(FieldValue::Text(attempts)) => attempts.clone(),
                other => panic!("attempts is not a scalar: {other:?}"),
            })
            .collect()
    }

    /// Repeated forged assertions are all refused. Audit records summarize
    /// one attempt in the first window and two after the next window opens.
    #[test]
    fn forged_assertions_are_recorded_once_a_window_with_their_count() {
        let bench = Bench::new().ready();
        let throttle = Arc::new(FakeAlertThrottle::default());
        let forged = || {
            bench.exchange_with(
                refusing(&bench, AssertionFault::BadSignature, &throttle),
                caps(RoutingAction::View),
            )
        };

        let first = forged();
        let held_back = forged();
        throttle.pass_window();
        let later = forged();

        for result in [first, held_back, later] {
            assert!(matches!(result, Err(AppError::Forbidden(_))));
        }
        assert_eq!(attack_records(&bench), ["1", "2"]);
    }

    /// Ann's agent sends an assertion that ran out on the way. It is
    /// refused, and nobody is told of an attack that was none.
    #[test]
    fn an_agents_own_slip_records_no_attack() {
        let bench = Bench::new().ready();
        let throttle = Arc::new(FakeAlertThrottle::default());

        let result = bench.exchange_with(
            refusing(&bench, AssertionFault::Expired, &throttle),
            caps(RoutingAction::View),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(attack_records(&bench).is_empty());
    }

    /// Mallory names an agent Acme does not have. There is no agent to warn
    /// about, so nothing is recorded, and she is refused like any other.
    #[test]
    fn an_unknown_agent_records_no_attack() {
        let bench = Bench::new().ready();
        let ports = ExchangeTokenPorts {
            agent_actors: Arc::new(AgentActing::new(
                signing_in(Arc::new(FakeAgentStore::empty()), bench.agent).0,
            )),
            ..bench.ports()
        };

        let result = bench.exchange_with(ports, caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(attack_records(&bench).is_empty());
    }

    /// An agent granted only route viewing cannot mint route-management
    /// authority, and its existing grant remains the only delegation.
    #[test]
    fn a_request_beyond_the_agents_authority_mints_nothing() {
        let bench = Bench::new().ready();

        let result = bench.exchange(caps(RoutingAction::Manage));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.delegations.count(), 1);
    }

    /// The agent asks to view and manage routes, and was let view them. It
    /// gets a token that views routes and nothing more.
    #[test]
    fn a_partly_excessive_request_mints_only_the_overlap() {
        let bench = Bench::new().ready();

        let exchanged = bench.exchange(view_and_manage()).unwrap();

        let granted = exchanged.delegation.granted();
        assert!(granted.permits(&SystemPermission::Routing(RoutingAction::View)));
        assert!(!granted.permits(&SystemPermission::Routing(RoutingAction::Manage)));
    }

    /// An agent nobody granted anything to holds nothing, whatever it asks
    /// for.
    #[test]
    fn an_agent_with_no_delegations_mints_nothing() {
        let bench = Bench::new();

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.delegations.count(), 0);
    }

    /// Minting a route-view token does not authorize a later exchange for
    /// route-management rights.
    #[test]
    fn a_minted_token_does_not_widen_the_ceiling_for_the_next_one() {
        let bench = Bench::new().ready();
        bench.exchange(caps(RoutingAction::View)).unwrap();

        let escalated = bench.exchange(caps(RoutingAction::Manage));

        assert!(matches!(escalated, Err(AppError::Forbidden(_))));
    }

    /// A revoked grant cannot authorize another token exchange.
    #[test]
    fn a_revoked_grant_no_longer_counts_towards_the_ceiling() {
        let bench = Bench::new();
        let ann = bench.delegator("ann@acme.test");
        bench.granted(DelegationRow {
            granted: caps(RoutingAction::View),
            status: DelegationStatus::Revoked,
            ..delegation_row(bench.agent, PrincipalRef::User(ann))
        });

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Route-management authority granted to a different agent cannot
    /// authorize this agent's token exchange.
    #[test]
    fn a_delegation_granted_to_another_agent_is_not_this_agents_authority() {
        let bench = Bench::new();
        let ann = bench.delegator("ann@acme.test");
        bench.granted(DelegationRow {
            granted: caps(RoutingAction::Manage),
            ..delegation_row(AgentId::new(), PrincipalRef::User(ann))
        });

        let result = bench.exchange(caps(RoutingAction::Manage));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann let the agent view routes and Bob let it delete them. It asks
    /// for both. The token carries one of their grants, never the two
    /// added together.
    #[test]
    fn a_token_carries_one_delegators_authority() {
        let bench = Bench::new();
        let ann = bench.delegator("ann@acme.test");
        let bob = bench.delegator("bob@acme.test");
        bench.granted_by(PrincipalRef::User(ann), caps(RoutingAction::View));
        bench.granted_by(PrincipalRef::User(bob), caps(RoutingAction::Delete));

        let exchanged = bench
            .exchange(caps(RoutingAction::View).union(&caps(RoutingAction::Delete)))
            .unwrap();

        let granted = exchanged.delegation.granted();
        let views = granted.permits(&SystemPermission::Routing(RoutingAction::View));
        let deletes = granted.permits(&SystemPermission::Routing(RoutingAction::Delete));
        assert_ne!(views, deletes);
    }

    /// Revocation while token provenance is recorded refuses the exchange
    /// and leaves no live delegation.
    #[test]
    fn a_revoke_racing_the_exchange_leaves_no_live_token() {
        let bench = Bench::new();
        let ann = bench.delegator("ann@acme.test");
        let grant = bench.granted_by(PrincipalRef::User(ann), caps(RoutingAction::View));
        bench.delegations.revoke_while_recording_provenance(grant);

        let result = bench.exchange(caps(RoutingAction::View));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.live_delegations(), 0);
    }
}
