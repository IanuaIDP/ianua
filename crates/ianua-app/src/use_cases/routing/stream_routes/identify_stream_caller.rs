//! Identify stream caller: who the credential a stream connection presents
//! names, for the gateway to ask the route's admission about.
//!
//! A port carries no request, so the wire offers two credentials only: the
//! client certificate a handshake the gateway ended verified, and the token
//! a signed-in tunnel's `CONNECT` carries. A Protected data step's
//! `CONNECT` on the gateway's workflow listener carries a third, its run's
//! pass, taken only for the stream route it names while that route is open
//! to workflows. Both are checked the way every
//! credential at the gateway is, by [`AuthenticateUseCase`], and what it
//! proves is named as a [`StreamConnectionCaller`]. A connection that
//! presents neither is nobody, which the gateway says without asking.
//!
//! Deny by default: a credential refused for any reason, an agent's task
//! token, a route the tenant does not have, and a check that cannot be made
//! all leave the caller unnamed, and the gateway closes the connection.

use std::sync::Arc;

use ianua_domain::domains::proxy::request::context::{Caller, RouteRequirements};
use ianua_domain::domains::routing::backend::upstream::{RouteIdentity, TokenAudience};
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::WorkflowUse;
use ianua_domain::domains::routing::stream::{ListenPort, StreamRoute, StreamWorkflowUse};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificateFingerprint, DomainName, Expiry, Fact, HttpMethod, HttpUrl, StreamRouteId,
};

use crate::error::AppError;
use crate::ports::consumers::ConsumerStore;
use crate::ports::routing::StreamRouteStore;
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::sender::DpopHeader;
use crate::use_cases::proxy::credentials::{
    AuthenticateRequest, AuthenticateUseCase, Identification, Presented, Refusal, RequestTarget,
};
use crate::use_cases::routing::lookup::existing_stream_route;
use crate::use_cases::routing::stream_routes::StreamConnectionCaller;

/// What a stream connection presented, on the route whose port it arrived
/// on.
pub struct StreamCallerEvidence {
    /// The route whose port it arrived on.
    pub stream_route_id: StreamRouteId,
    /// The server name its TLS handshake asked for.
    pub server_name: DomainName,
    /// The credential it presented.
    pub credential: StreamCredential,
}

/// The one credential a stream connection presents.
pub enum StreamCredential {
    /// The client certificate the handshake verified against the tenant's
    /// authorities, by its leaf's fingerprint.
    Certificate(CertificateFingerprint),
    /// The token a signed-in tunnel's `CONNECT` carried.
    TunnelToken(Secret),
    /// The token an open tunnel was admitted with, checked again while it
    /// stays open. It is checked as fully as when the tunnel opened, but a
    /// consumer's quota, counted then, is not counted again.
    HeldTunnelToken(Secret),
    /// A workflow run's pass, carried by a Protected data step's `CONNECT`
    /// on the gateway's workflow listener: taken only for the stream route
    /// it was made for, while that route is open to workflows.
    RunPass(Secret),
}

/// Who a stream connection's credential names, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedStreamCaller {
    /// The caller, as the route's admission reads it.
    pub caller: StreamConnectionCaller,
    /// When the credential stops naming them. A tunnel closes then at the
    /// latest.
    pub expiry: Expiry,
}

/// Why a stream connection's caller was not named. Every kind closes the
/// connection; the kind is for the gateway's record, never the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCallerRefusal {
    /// The credential was refused, for this reason.
    Credential(Refusal),
    /// The token is an agent's. Agents act through HTTP routes, where the
    /// limits their task tokens carry can be held; a raw stream would carry
    /// them past every one.
    Agent,
    /// The tenant has no such route.
    RouteUnknown,
    /// Nothing could be checked: a store, the tenant's issuer or its keys
    /// could not be read.
    Unavailable,
}

/// The ports [`IdentifyStreamCallerUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IdentifyStreamCallerPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// The tenant's consumers, to tell a certificate no consumer holds from
    /// one whose consumer was turned away.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// The issuer the tenant's tokens carry.
    pub issuers: TenantIssuers,
    /// Checks a credential the way the gateway checks every one.
    pub credentials: Arc<AuthenticateUseCase>,
}

/// Names the caller of one stream connection.
pub struct IdentifyStreamCallerUseCase {
    ports: IdentifyStreamCallerPorts,
}

impl IdentifyStreamCallerUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: IdentifyStreamCallerPorts) -> Self {
        Self { ports }
    }

    /// The tenant's route `stream_route_id`.
    async fn route(
        &self,
        tenant: &ScopedTenant,
        stream_route_id: &StreamRouteId,
    ) -> Result<StreamRoute<ResolvedTenant>, StreamCallerRefusal> {
        let store = self.ports.stream_route_store.as_ref();
        match existing_stream_route(store, tenant, stream_route_id).await {
            Ok(route) => Ok(route),
            Err(AppError::NotFound(_)) => Err(StreamCallerRefusal::RouteUnknown),
            Err(error) => Err(unavailable(&error)),
        }
    }

    /// The consumer a verified client certificate belongs to, or an
    /// unnamed certificate when no consumer of the tenant holds it.
    async fn by_certificate(
        &self,
        tenant: &ScopedTenant,
        target: RequestTarget,
        fingerprint: CertificateFingerprint,
    ) -> Result<IdentifiedStreamCaller, StreamCallerRefusal> {
        let request = AuthenticateRequest {
            presented: Presented::Nothing,
            certificate: Fact::Known(fingerprint),
            dpop: DpopHeader::NotSent,
            target,
            route: RouteRequirements {
                identity: RouteIdentity::ClientCertificate,
                policy: Fact::Known(RoutePolicy::Authenticated),
                ..RouteRequirements::default()
            },
        };
        match self.ports.credentials.execute(tenant, request).await {
            Err(Refusal::UnknownSubject) => self.unnamed(tenant, &fingerprint).await,
            checked => named_by(checked),
        }
    }

    /// A certificate that signed no consumer in, named as unnamed only when
    /// no consumer of the tenant holds it at all.
    ///
    /// A consumer that was disabled, or whose certificate stopped working,
    /// still holds it, and is refused: otherwise turning a consumer away
    /// would let its certificate in as anyone's on a port open to every
    /// holder.
    async fn unnamed(
        &self,
        tenant: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<IdentifiedStreamCaller, StreamCallerRefusal> {
        let holder = self
            .ports
            .consumer_store
            .find_by_cert_fingerprint(tenant, fingerprint)
            .await
            .map_err(|error| unavailable(&error))?;
        if holder.is_some() {
            return Err(StreamCallerRefusal::Credential(Refusal::UnknownSubject));
        }
        Ok(IdentifiedStreamCaller {
            caller: StreamConnectionCaller::UnnamedCertificate,
            expiry: Expiry::Never,
        })
    }

    /// The check of a tunnel token, held to the tenant's issuer and the
    /// route's own tunnel audience.
    async fn tunnel_token_check(
        &self,
        tenant: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
        target: RequestTarget,
        token: Secret,
    ) -> Result<AuthenticateRequest, StreamCallerRefusal> {
        let issuer = self
            .ports
            .issuers
            .of(tenant)
            .await
            .map_err(|error| unavailable(&error))?;
        let audience = route
            .tunnel_audience()
            .map_err(|error| unavailable(&error))?;
        Ok(AuthenticateRequest {
            presented: Presented::Bearer(token),
            certificate: Fact::Unknown,
            dpop: DpopHeader::NotSent,
            target,
            route: RouteRequirements {
                expected_issuer: Fact::Known(issuer),
                token_audience: TokenAudience::Pinned(audience),
                identity: RouteIdentity::Token,
                policy: Fact::Known(RoutePolicy::Authenticated),
                ..RouteRequirements::default()
            },
        })
    }
}

impl IdentifyStreamCallerUseCase {
    /// The check of a run pass, held to the tenant's issuer, the stream
    /// route it must name, and whether that route is open to workflows.
    async fn run_pass_check(
        &self,
        tenant: &ScopedTenant,
        route: &StreamRoute<ResolvedTenant>,
        target: RequestTarget,
        pass: Secret,
    ) -> Result<AuthenticateRequest, StreamCallerRefusal> {
        let issuer = self
            .ports
            .issuers
            .of(tenant)
            .await
            .map_err(|error| unavailable(&error))?;
        let workflow_use = match route.workflow_use() {
            StreamWorkflowUse::Open => WorkflowUse::Open,
            StreamWorkflowUse::Closed => WorkflowUse::Closed,
        };
        Ok(AuthenticateRequest {
            presented: Presented::RunPass(pass),
            certificate: Fact::Unknown,
            dpop: DpopHeader::NotSent,
            target,
            route: RouteRequirements {
                expected_issuer: Fact::Known(issuer),
                identity: RouteIdentity::Token,
                policy: Fact::Known(RoutePolicy::Authenticated),
                stream_route_id: Fact::Known(*route.id()),
                workflow_use,
                ..RouteRequirements::default()
            },
        })
    }
}

impl Query for IdentifyStreamCallerUseCase {
    type Caller = ScopedTenant;
    type Input = StreamCallerEvidence;
    type Output = Result<IdentifiedStreamCaller, StreamCallerRefusal>;

    /// Who `evidence`'s credential names on `tenant`'s route.
    ///
    /// A certificate names the consumer it belongs to, or an unnamed
    /// certificate when no consumer of the tenant holds it. A tunnel token
    /// names the person or consumer it was issued to, once it names the
    /// tenant's issuer and the route's tunnel audience and what stands
    /// behind it still does. An open tunnel's token checked again is held
    /// to the same, without counting its consumer's quota a second time.
    ///
    /// # Errors
    ///
    /// - [`StreamCallerRefusal::RouteUnknown`] when the tenant has no such
    ///   route.
    /// - [`StreamCallerRefusal::Credential`] when the credential is refused,
    ///   a certificate whose consumer was turned away included.
    /// - [`StreamCallerRefusal::Agent`] for an agent's task token.
    /// - [`StreamCallerRefusal::Unavailable`] when a store, the issuer or
    ///   the keys cannot be read.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        evidence: StreamCallerEvidence,
    ) -> Result<IdentifiedStreamCaller, StreamCallerRefusal> {
        let route = self.route(tenant, &evidence.stream_route_id).await?;
        let target = target_of(&evidence.server_name, route.listen_port())?;
        match evidence.credential {
            StreamCredential::Certificate(fingerprint) => {
                self.by_certificate(tenant, target, fingerprint).await
            }
            StreamCredential::TunnelToken(token) => {
                let check = self
                    .tunnel_token_check(tenant, &route, target, token)
                    .await?;
                named_by(self.ports.credentials.execute(tenant, check).await)
            }
            StreamCredential::HeldTunnelToken(token) => {
                let check = self
                    .tunnel_token_check(tenant, &route, target, token)
                    .await?;
                named_by(self.ports.credentials.rechecked(tenant, check).await)
            }
            StreamCredential::RunPass(pass) => {
                let check = self.run_pass_check(tenant, &route, target, pass).await?;
                named_by(self.ports.credentials.execute(tenant, check).await)
            }
        }
    }
}

/// Where a stream connection was opened, as a request target.
///
/// A stream sends no request, so no proof of a key can name one: the
/// target is the name and port the connection was opened to, read as a
/// `GET`, and a token bound to a key is refused for want of its proof.
fn target_of(
    server_name: &DomainName,
    port: ListenPort,
) -> Result<RequestTarget, StreamCallerRefusal> {
    let url = HttpUrl::new(format!("https://{}:{}/", server_name.as_str(), port.get()))
        .map_err(|error| unavailable(&error))?;
    Ok(RequestTarget {
        method: HttpMethod::Get,
        url,
    })
}

/// The caller a checked credential names.
fn named_by(
    checked: Result<Identification, Refusal>,
) -> Result<IdentifiedStreamCaller, StreamCallerRefusal> {
    let proven = match checked.map_err(refusal_of)? {
        Identification::Proven(proven) => proven,
        Identification::Anonymous => {
            return Err(StreamCallerRefusal::Credential(Refusal::Missing));
        }
    };
    let caller = match proven.verified.caller {
        Caller::User { user_id, .. } => StreamConnectionCaller::Person(user_id),
        Caller::Consumer { consumer_id, .. } => StreamConnectionCaller::Consumer(consumer_id),
        Caller::Agent { .. } => return Err(StreamCallerRefusal::Agent),
    };
    Ok(IdentifiedStreamCaller {
        caller,
        expiry: proven.verified.expiry,
    })
}

/// The refusal a credential's refusal comes to.
fn refusal_of(refusal: Refusal) -> StreamCallerRefusal {
    match refusal {
        Refusal::Unavailable => StreamCallerRefusal::Unavailable,
        other => StreamCallerRefusal::Credential(other),
    }
}

/// The refusal of a check that could not be made, logged with its error
/// and nothing of the credential.
fn unavailable(error: &dyn std::fmt::Display) -> StreamCallerRefusal {
    tracing::warn!(%error, "a stream connection's caller could not be named");
    StreamCallerRefusal::Unavailable
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaPeriod, RequestAllowance};
    use ianua_domain::domains::proxy::request::context::{AgentLimits, KeyBinding, Metering};
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::stream::access::StreamAccess;
    use ianua_domain::domains::routing::stream::{LoginTls, LoginUser, WorkflowLogin};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{
        ActionCallId, AgentId, Audience, DelegationId, PrincipalRef, RouteId, SealedSecret,
        ServiceId, SessionId, UserId,
    };

    use super::*;
    use crate::ports::authentication::{
        AgentToken, AppSessionClaim, IssuedUnder, PassReach, PersonToken, RunPassToken,
        TenantToken, TokenFault,
    };
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authentication::{FakeAppSessionCheck, FakePresentedTokens};
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::consumers::{
        FakeConsumerQuotaCounter, FakeConsumerStore, billing_sync, billing_sync_with_quota,
        certificate_holder, consumers_of_test_tenant, sign_in_counted_by, sign_in_of, switched_off,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::routing::{
        FakeStreamRouteStore, certificate_port_on, routing_admin, tunnel_on,
    };
    use crate::test_support::{Fake, block_on, test_ctx};
    use crate::use_cases::proxy::credentials::{
        AgentPorts, AuthenticatePorts, ConsumerPorts, PersonPorts,
    };

    const EDGE: [u8; 32] = [7; 32];

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    /// What the tenant holds for one test: its routes, consumers, people
    /// and the reader of its tokens.
    struct World {
        routes: Arc<FakeStreamRouteStore>,
        consumers: Arc<FakeConsumerStore>,
        consumer_ports: ConsumerPorts,
        tokens: FakePresentedTokens,
        users: Arc<FakeUserStore>,
    }

    impl World {
        fn new() -> Self {
            Self {
                routes: Arc::new(FakeStreamRouteStore::empty()),
                consumers: Arc::new(FakeConsumerStore::empty()),
                consumer_ports: ConsumerPorts::fakes(),
                tokens: FakePresentedTokens::default(),
                users: Arc::new(FakeUserStore::empty()),
            }
        }

        /// The world where `consumer` is the tenant's and signs in with
        /// its own credential.
        fn with_consumer(mut self, consumer: Consumer<ResolvedTenant>) -> Self {
            self.consumers = consumers_of_test_tenant(consumer.clone());
            self.consumer_ports = ConsumerPorts {
                consumer_store: consumers_of_test_tenant(consumer.clone()),
                authorities: sign_in_of(consumer, &[]),
                ..ConsumerPorts::fakes()
            };
            self
        }

        /// Keeps `route` as the tenant's, and answers with its id.
        fn route(&self, route: &StreamRoute<ResolvedTenant>) -> StreamRouteId {
            block_on(self.routes.save(&tenant(), route)).unwrap();
            *route.id()
        }

        fn use_case(self) -> IdentifyStreamCallerUseCase {
            let records =
                FakeAccessRecordStore::holding(test_ctx().tenant_id(), AccessRecords::default());
            let credentials = AuthenticateUseCase::new(AuthenticatePorts {
                tokens: Arc::new(self.tokens),
                access_records: Arc::new(records),
                people: PersonPorts {
                    user_store: self.users,
                    app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                    ..PersonPorts::fakes()
                },
                agents: AgentPorts::fakes(),
                consumers: self.consumer_ports,
            });
            IdentifyStreamCallerUseCase::new(IdentifyStreamCallerPorts {
                stream_route_store: self.routes,
                consumer_store: self.consumers,
                issuers: TenantIssuers::fake(),
                credentials: Arc::new(credentials),
            })
        }
    }

    fn certificate_port() -> StreamRoute<ResolvedTenant> {
        certificate_port_on(15434, RouteHosts::Any, StreamAccess::AnyHolder)
    }

    fn people_tunnel() -> StreamRoute<ResolvedTenant> {
        tunnel_on(15433, StreamAccess::People(RoutePolicy::Authenticated))
    }

    fn identify(
        use_case: &IdentifyStreamCallerUseCase,
        stream_route_id: StreamRouteId,
        credential: StreamCredential,
    ) -> Result<IdentifiedStreamCaller, StreamCallerRefusal> {
        block_on(use_case.execute(
            &tenant(),
            StreamCallerEvidence {
                stream_route_id,
                server_name: DomainName::new("db.acme.test").unwrap(),
                credential,
            },
        ))
    }

    fn edge_certificate() -> StreamCredential {
        StreamCredential::Certificate(CertificateFingerprint::from_digest(EDGE))
    }

    fn token() -> StreamCredential {
        StreamCredential::TunnelToken(Secret::new("a.signed.token"))
    }

    /// A token the tenant signed for Ann under her app session.
    fn anns_token(ann: UserId) -> TenantToken {
        TenantToken::Person(PersonToken {
            user_id: ann,
            scopes: Vec::new(),
            assurance: Fact::Known(AssuranceLevel::Aal2),
            expires_at: clock::now() + time::Duration::hours(1),
            issued_under: IssuedUnder::AppSession(AppSessionClaim {
                session_id: SessionId::new(),
                user_id: ann,
                service_id: ServiceId::new(),
                idle_timeout: None,
                signed_in_from: Fact::Unknown,
            }),
            claims: Vec::new(),
        })
    }

    /// The edge device presents its certificate on the port. It is named
    /// as its consumer.
    #[test]
    fn a_certificate_names_its_consumer() {
        let fingerprint = CertificateFingerprint::from_digest(EDGE);
        let edge = certificate_holder(fingerprint);
        let edge_id = *edge.id();
        let world = World::new().with_consumer(edge);
        let route = world.route(&certificate_port());

        let named = identify(&world.use_case(), route, edge_certificate()).unwrap();

        assert_eq!(named.caller, StreamConnectionCaller::Consumer(edge_id));
    }

    /// A certificate from Acme's authority that no consumer holds is named
    /// as an unnamed certificate, for a port open to every holder.
    #[test]
    fn a_certificate_no_consumer_holds_is_unnamed() {
        let world = World::new();
        let route = world.route(&certificate_port());

        let named = identify(&world.use_case(), route, edge_certificate()).unwrap();

        assert_eq!(named.caller, StreamConnectionCaller::UnnamedCertificate);
    }

    /// A certificate held by a disabled consumer is refused as an unknown
    /// subject instead of identifying an unnamed certificate holder.
    #[test]
    fn a_certificate_of_a_disabled_consumer_is_refused() {
        let fingerprint = CertificateFingerprint::from_digest(EDGE);
        let world = World::new().with_consumer(switched_off(certificate_holder(fingerprint)));
        let route = world.route(&certificate_port());

        let refused = identify(&world.use_case(), route, edge_certificate());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::UnknownSubject))
        );
    }

    /// "billing-sync" opens the tunnel with its API key. It is named as
    /// the consumer.
    #[test]
    fn a_consumers_key_in_the_tunnel_names_it() {
        let billing = billing_sync();
        let billing_id = *billing.id();
        let world = World::new().with_consumer(billing);
        let route = world.route(&people_tunnel());
        let key = StreamCredential::TunnelToken(Secret::new("sk_live_abc.hash123"));

        let named = identify(&world.use_case(), route, key).unwrap();

        assert_eq!(named.caller, StreamConnectionCaller::Consumer(billing_id));
    }

    /// "billing-sync" pays for one request a day and opened its tunnel with
    /// it. The tunnel's checks while it stays open still name it, and are
    /// not counted; a new tunnel today is refused, its allowance spent.
    #[test]
    fn checks_on_an_open_tunnel_do_not_count_against_the_quota() {
        let billing = billing_sync_with_quota(ConsumerQuota::Limited(
            RequestAllowance::new(1, QuotaPeriod::Day).unwrap(),
        ));
        let billing_id = *billing.id();
        let counter = Arc::new(FakeConsumerQuotaCounter::having_counted(
            billing_id,
            QuotaPeriod::Day,
            1,
        ));
        let mut world = World::new().with_consumer(billing.clone());
        world.consumer_ports.authorities = sign_in_counted_by(billing, &[], counter.clone());
        let route = world.route(&people_tunnel());
        let use_case = world.use_case();
        let key = || Secret::new("sk_live_abc.hash123");

        let checked = identify(&use_case, route, StreamCredential::HeldTunnelToken(key()));
        let opened = identify(&use_case, route, StreamCredential::TunnelToken(key()));

        assert_eq!(
            checked.unwrap().caller,
            StreamConnectionCaller::Consumer(billing_id)
        );
        assert_eq!(
            opened,
            Err(StreamCallerRefusal::Credential(Refusal::QuotaSpent))
        );
        assert_eq!(counter.counted(billing_id, QuotaPeriod::Day), 2);
    }

    /// Rechecking a held tunnel key for a disabled consumer refuses it as
    /// an unknown subject.
    #[test]
    fn a_check_on_an_open_tunnel_refuses_a_disabled_consumer() {
        let world = World::new().with_consumer(switched_off(billing_sync()));
        let route = world.route(&people_tunnel());
        let key = StreamCredential::HeldTunnelToken(Secret::new("sk_live_abc.hash123"));

        let refused = identify(&world.use_case(), route, key);

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::UnknownSubject))
        );
    }

    /// Ann opens the tunnel with a token minted for it. She is named, until
    /// her token runs out.
    #[test]
    fn a_persons_token_for_the_tunnel_names_them() {
        let ann = UserId::new();
        let tunnel = people_tunnel();
        let mut world = World::new();
        world.users = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));
        world.tokens = FakePresentedTokens {
            minted_for: Some(tunnel.tunnel_audience().unwrap()),
            ..FakePresentedTokens::reading_bearer(anns_token(ann))
        };
        let route = world.route(&tunnel);

        let named = identify(&world.use_case(), route, token()).unwrap();

        assert_eq!(named.caller, StreamConnectionCaller::Person(ann));
        assert!(matches!(named.expiry, Expiry::At(_)));
    }

    /// A person's token minted for the reports app is refused on the tunnel
    /// because its audience does not match.
    #[test]
    fn a_token_minted_for_another_audience_is_refused() {
        let ann = UserId::new();
        let mut world = World::new();
        world.users = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));
        world.tokens = FakePresentedTokens {
            minted_for: Some(Audience::new("reports-app").unwrap()),
            ..FakePresentedTokens::reading_bearer(anns_token(ann))
        };
        let route = world.route(&people_tunnel());

        let refused = identify(&world.use_case(), route, token());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::WrongAudience))
        );
    }

    /// When the token reader reports an expired token, the tunnel caller
    /// receives an expired credential refusal.
    #[test]
    fn an_expired_token_is_refused() {
        let mut world = World::new();
        world.tokens = FakePresentedTokens::refusing(TokenFault::Expired);
        let route = world.route(&people_tunnel());

        let refused = identify(&world.use_case(), route, token());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::Expired))
        );
    }

    /// Presenting an agent's task token as a tunnel credential returns an
    /// agent refusal.
    #[test]
    fn an_agents_token_is_refused() {
        let agent = AgentToken {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            acting_for: PrincipalRef::User(UserId::new()),
            permissions: Vec::new(),
            limits: AgentLimits {
                intent_envelope: Restriction::Unrestricted,
                mcp: McpGrant::default(),
                resource_scope: Restriction::Unrestricted,
                max_data_class: Restriction::Unrestricted,
                key_binding: KeyBinding::Bearer,
                approval: ActionApproval::NotRequired,
                metering: Metering::Unmetered,
            },
            bound_key: None,
            expires_at: clock::now() + time::Duration::hours(1),
        };
        let mut world = World::new();
        world.tokens = FakePresentedTokens::reading_bearer(TenantToken::Agent(Box::new(agent)));
        let route = world.route(&people_tunnel());

        let refused = identify(&world.use_case(), route, token());

        assert_eq!(refused, Err(StreamCallerRefusal::Agent));
    }

    /// An unavailable token reader returns an unavailable result instead of
    /// identifying the tunnel caller.
    #[test]
    fn unreadable_keys_leave_the_caller_unnamed() {
        let mut world = World::new();
        world.tokens = FakePresentedTokens::unreachable();
        let route = world.route(&people_tunnel());

        let refused = identify(&world.use_case(), route, token());

        assert_eq!(refused, Err(StreamCallerRefusal::Unavailable));
    }

    /// The people tunnel to the orders database, open to workflows with a
    /// reader login.
    fn open_people_tunnel() -> StreamRoute<ResolvedTenant> {
        let mut route = people_tunnel();
        let login = WorkflowLogin::new(
            LoginUser::new("workflows_reader").unwrap(),
            SealedSecret::new("v1.AAECAwQF").unwrap(),
            LoginTls::Off,
        );
        route.open_to_workflows(&login, &routing_admin()).unwrap();
        route
    }

    /// The world where Ann is the tenant's and every run pass is one made
    /// for her run on `reaches`.
    fn passing_for(ann: UserId, reaches: PassReach) -> World {
        let mut world = World::new();
        world.users = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));
        world.tokens = FakePresentedTokens::reading_pass(RunPassToken {
            call_id: ActionCallId::new(),
            user_id: ann,
            reaches,
            expires_at: clock::now() + time::Duration::minutes(1),
        });
        world
    }

    fn run_pass() -> StreamCredential {
        StreamCredential::RunPass(Secret::new("a.run.pass"))
    }

    /// Ann's run reaches the orders database through the workflow listener
    /// with a pass made for that database. She is named as herself.
    #[test]
    fn a_run_pass_for_the_stream_route_names_its_person() {
        let ann = UserId::new();
        let route = open_people_tunnel();
        let world = passing_for(ann, PassReach::StreamRoute(*route.id()));
        let route = world.route(&route);

        let named = identify(&world.use_case(), route, run_pass()).unwrap();

        assert_eq!(named.caller, StreamConnectionCaller::Person(ann));
    }

    /// A run pass for another stream route is refused for the wrong audience
    /// on a route open to workflows.
    #[test]
    fn a_run_pass_for_another_stream_route_is_refused() {
        let ann = UserId::new();
        let world = passing_for(ann, PassReach::StreamRoute(StreamRouteId::new()));
        let route = world.route(&open_people_tunnel());

        let refused = identify(&world.use_case(), route, run_pass());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::WrongAudience))
        );
    }

    /// A run pass naming the stream route is refused for the wrong audience
    /// when that route is closed to workflows.
    #[test]
    fn a_run_pass_on_a_closed_stream_route_is_refused() {
        let ann = UserId::new();
        let route = people_tunnel();
        let world = passing_for(ann, PassReach::StreamRoute(*route.id()));
        let route = world.route(&route);

        let refused = identify(&world.use_case(), route, run_pass());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::WrongAudience))
        );
    }

    /// A run pass for a web route is refused for the wrong audience on a
    /// stream route open to workflows.
    #[test]
    fn a_run_pass_for_a_route_reaches_no_stream_route() {
        let ann = UserId::new();
        let world = passing_for(ann, PassReach::Route(RouteId::new()));
        let route = world.route(&open_people_tunnel());

        let refused = identify(&world.use_case(), route, run_pass());

        assert_eq!(
            refused,
            Err(StreamCallerRefusal::Credential(Refusal::WrongAudience))
        );
    }

    /// A token presented for an unknown stream route returns an unknown
    /// route refusal.
    #[test]
    fn an_unknown_route_names_nobody() {
        let world = World::new();

        let refused = identify(&world.use_case(), StreamRouteId::new(), token());

        assert_eq!(refused, Err(StreamCallerRefusal::RouteUnknown));
    }
}
