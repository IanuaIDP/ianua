//! The authority a tunnel is held to while it stays open: for an agent,
//! that it may still act and its delegation stands; for a person or a
//! consumer, that their credential still stands and the route still lets
//! them through.
//!
//! The answers are the application's, from [`CheckAgentAuthorityUseCase`]
//! and [`RecheckConnectionUseCase`]: the same rules the request was checked
//! against when the switch was asked for. This only asks them and reads
//! anything but a clear yes as a close: a no as lost, an error as a failed
//! check.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query;
use ianua_app::use_cases::agents::enforcement::{
    AgentAuthority, AgentAuthorityRequest, CheckAgentAuthorityUseCase,
};
use ianua_app::use_cases::proxy::{
    ConnectionStanding, RecheckConnectionRequest, RecheckConnectionUseCase,
};

use super::upgrade::{Standing, TunnelAuthority};

/// Asks whether the agent that opened a tunnel may still hold it open.
pub(crate) struct AgentTunnelAuthority {
    use_case: Arc<CheckAgentAuthorityUseCase>,
    tenant: ScopedTenant,
    agent: AgentAuthorityRequest,
}

impl AgentTunnelAuthority {
    /// Asks `use_case` about `agent` in `tenant`, the tenant the request
    /// that opened the tunnel was resolved to.
    #[must_use]
    pub(crate) fn new(
        use_case: Arc<CheckAgentAuthorityUseCase>,
        tenant: ScopedTenant,
        agent: AgentAuthorityRequest,
    ) -> Self {
        Self {
            use_case,
            tenant,
            agent,
        }
    }
}

#[async_trait]
impl TunnelAuthority for AgentTunnelAuthority {
    async fn standing(&self) -> Standing {
        match self.use_case.execute(&self.tenant, self.agent).await {
            Ok(AgentAuthority::Holds) => Standing::Holds,
            Ok(AgentAuthority::Lost(loss)) => {
                tracing::info!(
                    agent_id = %self.agent.agent_id,
                    ?loss,
                    "an agent's authority was lost while its tunnel was open"
                );
                Standing::Lost
            }
            Err(error) => {
                tracing::warn!(
                    agent_id = %self.agent.agent_id,
                    %error,
                    "an agent's authority could not be checked; its tunnel closes"
                );
                Standing::CheckFailed
            }
        }
    }
}

/// Asks whether the person or consumer who opened a tunnel may still hold
/// it open.
pub(crate) struct HolderTunnelAuthority {
    use_case: Arc<RecheckConnectionUseCase>,
    tenant: ScopedTenant,
    request: RecheckConnectionRequest,
}

impl HolderTunnelAuthority {
    /// Asks `use_case` about the holder and credential `request` names in
    /// `tenant`, the tenant the handshake was resolved to.
    #[must_use]
    pub(crate) fn new(
        use_case: Arc<RecheckConnectionUseCase>,
        tenant: ScopedTenant,
        request: RecheckConnectionRequest,
    ) -> Self {
        Self {
            use_case,
            tenant,
            request,
        }
    }
}

#[async_trait]
impl TunnelAuthority for HolderTunnelAuthority {
    async fn standing(&self) -> Standing {
        let holder = self.request.holder;
        match self
            .use_case
            .execute(&self.tenant, self.request.clone())
            .await
        {
            ConnectionStanding::Holds => Standing::Holds,
            ConnectionStanding::Lost => {
                tracing::info!(
                    ?holder,
                    "a caller's access ended while their tunnel was open"
                );
                Standing::Lost
            }
            ConnectionStanding::CheckFailed => {
                tracing::warn!(
                    ?holder,
                    "a caller's access could not be checked; their tunnel closes"
                );
                Standing::CheckFailed
            }
        }
    }
}

/// A tunnel whose caller cannot be asked about, which fails its first
/// check: it never stays open unchecked.
pub(crate) struct UncheckableTunnel;

#[async_trait]
impl TunnelAuthority for UncheckableTunnel {
    async fn standing(&self) -> Standing {
        Standing::CheckFailed
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use ianua_app::ports::authentication::{
        AppSessionClaim, IssuedUnder, PersonToken, TenantToken,
    };
    use ianua_app::ports::authorization::AccessRecords;
    use ianua_app::ports::routing::RouteStore as _;
    use ianua_app::test_support::agents::{FakeAgentStandings, FakeDelegationRevocations};
    use ianua_app::test_support::authentication::{FakeAppSessionCheck, FakePresentedTokens};
    use ianua_app::test_support::authorization::{
        FakeAccessRecordStore, stored_group, stored_membership, stored_role,
    };
    use ianua_app::test_support::identity::{FakeUserStore, stored_user};
    use ianua_app::test_support::oauth::test_issuer;
    use ianua_app::test_support::proxy::test_pipeline;
    use ianua_app::test_support::routing::{
        FakeRouteStore, RouteShape, pinned_upstream, route_of, service_named,
    };
    use ianua_app::test_support::test_ctx;
    use ianua_app::use_cases::agents::enforcement::AgentAuthorityPorts;
    use ianua_app::use_cases::oauth::sender::DpopHeader;
    use ianua_app::use_cases::proxy::credentials::{
        AuthenticatePorts, AuthenticateRequest, AuthenticateUseCase, PersonPorts, Presented,
        RequestTarget,
    };
    use ianua_app::use_cases::proxy::{
        ConnectionHolder, DecideAccessPorts, DecideAccessUseCase, RecheckConnectionChecks,
    };
    use ianua_domain::domains::agents::identity::standing::AgentStanding;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::proxy::access::question::{Asked, Circumstances, MethodClaim};
    use ianua_domain::domains::proxy::request::context::RouteRequirements;
    use ianua_domain::domains::routing::backend::upstream::TokenAudience;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{
        AgentId, Audience, CanonicalPath, DelegationId, Fact, HttpMethod, HttpUrl, PrincipalRef,
        RouteId, Scope, ServiceId, SessionId, UserId,
    };

    use super::*;

    fn runner() -> AgentAuthorityRequest {
        AgentAuthorityRequest {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
        }
    }

    fn authority(ports: AgentAuthorityPorts, agent: AgentAuthorityRequest) -> AgentTunnelAuthority {
        let use_case = Arc::new(CheckAgentAuthorityUseCase::new(ports));
        AgentTunnelAuthority::new(use_case, test_ctx().tenant(), agent)
    }

    /// The report runner is active under Ann's standing delegation. Its
    /// WebSocket stays open.
    #[tokio::test]
    async fn an_agent_in_standing_holds_its_tunnel() {
        let held = authority(AgentAuthorityPorts::fakes(), runner());

        assert_eq!(held.standing().await, Standing::Holds);
    }

    /// A revoked delegation makes the runner's tunnel authority report lost standing.
    #[tokio::test]
    async fn a_revoked_delegation_loses_the_tunnel() {
        let agent = runner();
        let revocations = Arc::new(FakeDelegationRevocations::default());
        revocations.revoke(&test_ctx().tenant(), agent.delegation_id);
        let ports = AgentAuthorityPorts {
            revocations,
            ..AgentAuthorityPorts::fakes()
        };

        let lost = authority(ports, agent);

        assert_eq!(lost.standing().await, Standing::Lost);
    }

    /// A suspended agent makes the tunnel authority report lost standing.
    #[tokio::test]
    async fn a_suspended_agent_loses_the_tunnel() {
        let agent = runner();
        let standings = Arc::new(FakeAgentStandings::default());
        standings.set(
            &test_ctx().tenant(),
            agent.agent_id,
            AgentStanding::Suspended,
        );
        let ports = AgentAuthorityPorts {
            standings,
            ..AgentAuthorityPorts::fakes()
        };

        let lost = authority(ports, agent);

        assert_eq!(lost.standing().await, Standing::Lost);
    }

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    /// Pat's open WebSocket, as the gateway keeps it: a token issued under
    /// her app session for the live app, on a route asking for a permission
    /// her Staff group gives her. Every port but those it reads is a fake.
    struct OpenSocket {
        pat: UserId,
        route: RouteId,
        users: Arc<FakeUserStore>,
        records: Arc<FakeAccessRecordStore>,
        sessions: Arc<FakeAppSessionCheck>,
        routes: Arc<FakeRouteStore>,
    }

    impl OpenSocket {
        /// Pat signed in, active and in the Staff group.
        async fn pats() -> Self {
            let pat = UserId::new();
            let route = route_of(
                RouteShape {
                    policy: RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]),
                    ..RouteShape::public("live", "/live")
                },
                &service_named("live", pinned_upstream("https://live:8080", "live")),
                &test_pipeline(),
            );
            let routes = Arc::new(FakeRouteStore::empty());
            routes.save(&test_ctx().tenant(), &route).await.unwrap();
            let open = Self {
                pat,
                route: *route.id(),
                users: Arc::new(FakeUserStore::with_user(pat, "pat@acme.test")),
                records: Arc::new(FakeAccessRecordStore::empty()),
                sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                routes,
            };
            open.put_pat_in_staff();
            open
        }

        /// Gives Pat, through the Staff group, what the route asks for.
        fn put_pat_in_staff(&self) {
            let viewer = stored_role("viewer", vec![VIEW_USERS], Vec::new());
            let staff = stored_group("Staff", GroupPlace::TopLevel, vec![*viewer.id()]);
            let member = stored_membership(PrincipalRef::User(self.pat), *staff.id());
            self.records.replace(
                test_ctx().tenant_id(),
                AccessRecords {
                    roles: vec![viewer],
                    groups: vec![staff],
                    memberships: vec![member],
                    ..AccessRecords::default()
                },
            );
        }

        /// Takes Pat out of the Staff group.
        fn take_pat_out_of_staff(&self) {
            self.records
                .replace(test_ctx().tenant_id(), AccessRecords::default());
        }

        /// The person's token as the fake token reader gives it, issued
        /// under a live session in the live app.
        fn token(&self) -> TenantToken {
            TenantToken::Person(PersonToken {
                user_id: self.pat,
                scopes: vec![Scope::new("read").unwrap()],
                assurance: Fact::Known(AssuranceLevel::Aal2),
                expires_at: clock::now() + time::Duration::hours(1),
                issued_under: IssuedUnder::AppSession(AppSessionClaim {
                    session_id: SessionId::new(),
                    user_id: self.pat,
                    service_id: ServiceId::new(),
                    idle_timeout: None,
                    signed_in_from: Fact::Unknown,
                }),
                claims: Vec::new(),
            })
        }

        /// The tunnel's authority, reading tokens through `tokens`.
        fn authority(&self, tokens: FakePresentedTokens) -> HolderTunnelAuthority {
            let authenticate = AuthenticateUseCase::new(AuthenticatePorts {
                tokens: Arc::new(tokens),
                access_records: self.records.clone(),
                people: PersonPorts {
                    user_store: self.users.clone(),
                    app_sessions: self.sessions.clone(),
                    ..PersonPorts::fakes()
                },
                ..AuthenticatePorts::fakes()
            });
            let access = DecideAccessUseCase::new(DecideAccessPorts {
                route_store: self.routes.clone(),
                access_records: self.records.clone(),
                ..DecideAccessPorts::fakes()
            });
            let use_case = RecheckConnectionUseCase::new(RecheckConnectionChecks {
                credentials: Arc::new(authenticate),
                access: Arc::new(access),
            });
            HolderTunnelAuthority::new(Arc::new(use_case), test_ctx().tenant(), self.request())
        }

        fn request(&self) -> RecheckConnectionRequest {
            let audience = Audience::new("live-app").unwrap();
            RecheckConnectionRequest {
                credential: AuthenticateRequest {
                    presented: Presented::Bearer(Secret::new("pat.session.token")),
                    certificate: Fact::Unknown,
                    dpop: DpopHeader::ProvenAtOpen,
                    target: RequestTarget {
                        method: HttpMethod::Get,
                        url: HttpUrl::new("https://live.acme.test/live").unwrap(),
                    },
                    route: RouteRequirements {
                        expected_issuer: Fact::Known(test_issuer()),
                        token_audience: TokenAudience::Pinned(audience),
                        policy: Fact::Known(RoutePolicy::Authenticated),
                        ..RouteRequirements::default()
                    },
                },
                holder: ConnectionHolder::Person(self.pat),
                route_id: self.route,
                asked: Asked {
                    method: Fact::Known(HttpMethod::Get),
                    path: Fact::Known(CanonicalPath::new("/live/feed").unwrap()),
                    method_claim: MethodClaim::AsSent,
                    host: Fact::Unknown,
                },
                circumstances: Circumstances::unknown(),
            }
        }

        /// The tunnel's standing with a token that reads as Pat's.
        async fn standing(&self) -> Standing {
            self.authority(FakePresentedTokens::reading_bearer(self.token()))
                .standing()
                .await
        }
    }

    /// Pat's WebSocket stays open while nothing about her access changed.
    #[tokio::test]
    async fn a_person_in_standing_holds_their_tunnel() {
        let open = OpenSocket::pats().await;

        assert_eq!(open.standing().await, Standing::Holds);
    }

    /// Tess suspends Pat, deactivating her account. The next check closes
    /// her WebSocket.
    #[tokio::test]
    async fn a_deactivated_person_loses_their_tunnel() {
        let mut open = OpenSocket::pats().await;

        open.users = Arc::new(FakeUserStore::empty());
        open.users.add(stored_user(
            open.pat,
            "pat@acme.test",
            UserStatus::Deactivated,
        ));

        assert_eq!(open.standing().await, Standing::Lost);
    }

    /// Tess takes Pat out of the Staff group the route's permission comes
    /// through. The next check closes her WebSocket.
    #[tokio::test]
    async fn a_person_removed_from_the_group_loses_their_tunnel() {
        let open = OpenSocket::pats().await;

        open.take_pat_out_of_staff();

        assert_eq!(open.standing().await, Standing::Lost);
    }

    /// Pat's session ended, as signing out or an administrator ending it
    /// does. The next check closes her WebSocket.
    #[tokio::test]
    async fn a_person_whose_session_ended_loses_their_tunnel() {
        let open = OpenSocket::pats().await;

        open.sessions.0.store(false, Ordering::SeqCst);

        assert_eq!(open.standing().await, Standing::Lost);
    }

    /// The token reader cannot be reached: the check fails and the tunnel
    /// closes rather than staying open undecided.
    #[tokio::test]
    async fn a_check_that_cannot_be_made_fails_the_tunnel() {
        let open = OpenSocket::pats().await;

        let authority = open.authority(FakePresentedTokens::unreachable());

        assert_eq!(authority.standing().await, Standing::CheckFailed);
    }

    /// A request whose credential cannot be read is checked as failed, not
    /// left open.
    #[tokio::test]
    async fn a_tunnel_nobody_can_ask_about_fails_its_check() {
        assert_eq!(UncheckableTunnel.standing().await, Standing::CheckFailed);
    }
}
