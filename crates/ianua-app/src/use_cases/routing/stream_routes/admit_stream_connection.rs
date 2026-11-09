//! Admit stream connection: decide whether the caller the gateway found on a
//! stream route's port may be spliced through.
//!
//! The gateway checks the wire first: the certificate, or the tunnel token
//! and who it belongs to. It then asks this use case, and splices only on
//! [`StreamAdmission::Admitted`]. Everything else, an error included, closes
//! the connection.

use std::sync::Arc;

use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::stream::access::{StreamCaller, StreamVerdict};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, StreamRouteId};

use crate::error::AppError;
use crate::ports::routing::{
    PolicyDecision, PolicyDecisionPoint, StreamConnectionCaller, StreamRouteStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::routing::lookup::existing_stream_route;

/// A connection the gateway accepted on a stream route's port.
pub struct StreamConnection {
    /// The route whose port it arrived on.
    pub stream_route_id: StreamRouteId,
    /// The server name its TLS handshake asked for. `None` on raw TCP, and
    /// for a client that sent none or one that is no domain name.
    pub server_name: Option<DomainName>,
    /// Who the gateway found on it, once the wire was checked.
    pub caller: StreamConnectionCaller,
}

impl StreamConnectionCaller {
    /// The caller as the domain's access rule reads it.
    fn as_stream_caller(&self) -> StreamCaller<'_> {
        match self {
            Self::Nobody => StreamCaller::Nobody,
            Self::UnnamedCertificate => StreamCaller::UnnamedCertificate,
            Self::Consumer(consumer) => StreamCaller::Consumer(consumer),
            Self::Person(_) => StreamCaller::Person,
        }
    }
}

/// Whether the connection may be spliced through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAdmission {
    /// Splice it.
    Admitted,
    /// Close it, for this reason. The reason goes to the request record,
    /// never to the caller.
    Refused(StreamRefusal),
}

/// Why a stream connection was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRefusal {
    /// The route is disabled.
    RouteClosed,
    /// The handshake named a server the route does not answer, or named
    /// none on a route restricted to some.
    ServerNameNotMatched,
    /// The route does not let this caller in.
    NotLetIn,
    /// The person does not meet the route's policy.
    PolicyDenied,
    /// No decision was made: the person is unknown to the policy, or the
    /// policy decision point could not be reached in time.
    NoDecision,
}

/// The ports [`AdmitStreamConnectionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AdmitStreamConnectionPorts {
    /// Keeps the tenant's stream routes.
    pub stream_route_store: Arc<dyn StreamRouteStore>,
    /// Decides whether a person meets a route's policy.
    pub policy_decisions: Arc<dyn PolicyDecisionPoint>,
}

/// Decides one stream connection.
pub struct AdmitStreamConnectionUseCase {
    ports: AdmitStreamConnectionPorts,
}

impl AdmitStreamConnectionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AdmitStreamConnectionPorts) -> Self {
        Self { ports }
    }

    /// Whether `caller`, a person the route holds to `policy`, may pass.
    /// Only a permit admits; a denial, no decision or a failure refuses.
    async fn person_meets(
        &self,
        tenant: &ScopedTenant,
        caller: &StreamConnectionCaller,
        policy: &RoutePolicy,
    ) -> StreamAdmission {
        let StreamConnectionCaller::Person(person) = caller else {
            return StreamAdmission::Refused(StreamRefusal::NotLetIn);
        };
        let decision = self
            .ports
            .policy_decisions
            .decide(tenant, person, policy)
            .await;
        admission_after(&decision)
    }
}

impl Query for AdmitStreamConnectionUseCase {
    type Caller = ScopedTenant;
    type Input = StreamConnection;
    type Output = Result<StreamAdmission, AppError>;

    /// Whether `connection` may be spliced through on the tenant's route.
    ///
    /// The route's server-name restriction comes first: a connection that
    /// names nothing reaches only a route restricted to nothing. Then the
    /// route's access decides: anyone its policy lets through, named
    /// consumers, or people the policy decision point permits. Anything it
    /// does not name is refused, and a person is admitted only on an
    /// explicit permit.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant has no such route.
    /// - `AppError::Internal` on storage failure. The gateway closes the
    ///   connection on any error.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        connection: StreamConnection,
    ) -> Result<StreamAdmission, AppError> {
        let store = self.ports.stream_route_store.as_ref();
        let route = existing_stream_route(store, tenant, &connection.stream_route_id).await?;
        if !route.is_active() {
            return Ok(StreamAdmission::Refused(StreamRefusal::RouteClosed));
        }
        if !route.accepts(connection.server_name.as_ref().map(DomainName::as_str)) {
            return Ok(StreamAdmission::Refused(
                StreamRefusal::ServerNameNotMatched,
            ));
        }
        let verdict = route
            .access()
            .admits(route.policy(), connection.caller.as_stream_caller());
        Ok(match verdict {
            StreamVerdict::Admit => StreamAdmission::Admitted,
            StreamVerdict::Refuse => StreamAdmission::Refused(StreamRefusal::NotLetIn),
            StreamVerdict::CheckPolicy(policy) => {
                self.person_meets(tenant, &connection.caller, policy).await
            }
        })
    }
}

/// The admission a policy decision, or the failure to get one, comes to.
fn admission_after(decision: &Result<PolicyDecision, DomainError>) -> StreamAdmission {
    match decision {
        Ok(PolicyDecision::Permit) => StreamAdmission::Admitted,
        Ok(PolicyDecision::Deny) => StreamAdmission::Refused(StreamRefusal::PolicyDenied),
        Ok(PolicyDecision::Undecided) | Err(_) => {
            StreamAdmission::Refused(StreamRefusal::NoDecision)
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::stream::StreamRoute;
    use ianua_domain::domains::routing::stream::access::{StreamAccess, StreamConsumers};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{ConsumerId, TenantId, UserId};

    use super::*;
    use crate::test_support::consumers::consumer_named;
    use crate::test_support::routing::{
        FakePolicyDecisionPoint, FakeStreamRouteStore, certificate_port_on, routing_admin,
        stream_route_on, tunnel_on,
    };
    use crate::test_support::{block_on, test_ctx};

    struct Fixture {
        decisions: Arc<FakePolicyDecisionPoint>,
        use_case: AdmitStreamConnectionUseCase,
        route_id: StreamRouteId,
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    /// Stores the route and records policy queries made while admitting connections.
    fn fixture(route: &StreamRoute<ResolvedTenant>, decisions: FakePolicyDecisionPoint) -> Fixture {
        let routes = Arc::new(FakeStreamRouteStore::empty());
        block_on(routes.save(&tenant(), route)).unwrap();
        let decisions = Arc::new(decisions);
        Fixture {
            use_case: AdmitStreamConnectionUseCase::new(AdmitStreamConnectionPorts {
                stream_route_store: routes,
                policy_decisions: decisions.clone(),
            }),
            decisions,
            route_id: *route.id(),
        }
    }

    fn people_tunnel(decisions: FakePolicyDecisionPoint) -> Fixture {
        fixture(
            &tunnel_on(15433, StreamAccess::People(RoutePolicy::Authenticated)),
            decisions,
        )
    }

    fn consumers_tunnel(consumer: ConsumerId) -> Fixture {
        let named = StreamConsumers::new(vec![consumer]).unwrap();
        fixture(
            &tunnel_on(15433, StreamAccess::Consumers(named)),
            FakePolicyDecisionPoint::deciding(PolicyDecision::Permit),
        )
    }

    fn admit(f: &Fixture, caller: StreamConnectionCaller) -> StreamAdmission {
        admit_naming(f, None, caller)
    }

    fn admit_naming(
        f: &Fixture,
        server_name: Option<&str>,
        caller: StreamConnectionCaller,
    ) -> StreamAdmission {
        block_on(f.use_case.execute(
            &tenant(),
            StreamConnection {
                stream_route_id: f.route_id,
                server_name: server_name.map(|name| DomainName::new(name).unwrap()),
                caller,
            },
        ))
        .unwrap()
    }

    /// The billing port answers only `db.acme.com`, for any certificate
    /// from Acme's authorities.
    fn billing_port() -> Fixture {
        let only = RouteHosts::only(vec![DomainName::new("db.acme.com").unwrap()]).unwrap();
        fixture(
            &certificate_port_on(15434, only, StreamAccess::AnyHolder),
            FakePolicyDecisionPoint::deciding(PolicyDecision::Permit),
        )
    }

    fn ann() -> StreamConnectionCaller {
        StreamConnectionCaller::Person(UserId::new())
    }

    /// Ann opens the database tunnel, and the policy permits her. She is
    /// let through.
    #[test]
    fn a_permitted_person_is_admitted() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Permit));

        assert_eq!(admit(&f, ann()), StreamAdmission::Admitted);
        assert_eq!(f.decisions.times_asked(), 1);
    }

    /// A person denied by the tunnel's policy receives a policy refusal.
    #[test]
    fn a_denied_person_is_refused() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Deny));

        assert_eq!(
            admit(&f, ann()),
            StreamAdmission::Refused(StreamRefusal::PolicyDenied)
        );
    }

    /// An undecided policy result refuses the person's connection with no
    /// decision available.
    #[test]
    fn an_unknown_subject_is_refused() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Undecided));

        assert_eq!(
            admit(&f, ann()),
            StreamAdmission::Refused(StreamRefusal::NoDecision)
        );
    }

    /// An unavailable policy decision point refuses the person's connection
    /// with no decision available.
    #[test]
    fn an_unreachable_policy_store_refuses() {
        let f = people_tunnel(FakePolicyDecisionPoint::unreachable());

        assert_eq!(
            admit(&f, ann()),
            StreamAdmission::Refused(StreamRefusal::NoDecision)
        );
    }

    /// An anonymous caller is refused by the people tunnel without asking
    /// the policy decision point.
    #[test]
    fn nobody_on_a_people_tunnel_is_refused_without_asking() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Permit));

        assert_eq!(
            admit(&f, StreamConnectionCaller::Nobody),
            StreamAdmission::Refused(StreamRefusal::NotLetIn)
        );
        assert_eq!(f.decisions.times_asked(), 0);
    }

    /// A consumer caller is refused by a tunnel that admits people.
    #[test]
    fn a_consumer_on_a_people_tunnel_is_refused() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Permit));

        assert_eq!(
            admit(&f, StreamConnectionCaller::Consumer(ConsumerId::new())),
            StreamAdmission::Refused(StreamRefusal::NotLetIn)
        );
    }

    /// The billing consumer opens the tunnel that names it. It is let
    /// through.
    #[test]
    fn a_named_consumer_is_admitted() {
        let billing = *consumer_named("billing", DataClassLevel::Internal).id();
        let f = consumers_tunnel(billing);

        assert_eq!(
            admit(&f, StreamConnectionCaller::Consumer(billing)),
            StreamAdmission::Admitted
        );
    }

    /// A consumer absent from the tunnel's allowed consumers is refused.
    #[test]
    fn a_consumer_not_named_is_refused() {
        let f = consumers_tunnel(ConsumerId::new());

        assert_eq!(
            admit(&f, StreamConnectionCaller::Consumer(ConsumerId::new())),
            StreamAdmission::Refused(StreamRefusal::NotLetIn)
        );
    }

    /// Anyone reaches a public port, as its policy says.
    #[test]
    fn anyone_is_admitted_on_a_public_port() {
        let f = fixture(
            &stream_route_on(15432),
            FakePolicyDecisionPoint::deciding(PolicyDecision::Deny),
        );

        assert_eq!(
            admit(&f, StreamConnectionCaller::Nobody),
            StreamAdmission::Admitted
        );
    }

    /// A disabled tunnel refuses a person with a closed-route result without
    /// asking the policy decision point.
    #[test]
    fn a_disabled_route_refuses_everyone() {
        let mut route = tunnel_on(15433, StreamAccess::People(RoutePolicy::Authenticated));
        route.disable(&routing_admin()).unwrap();
        let f = fixture(
            &route,
            FakePolicyDecisionPoint::deciding(PolicyDecision::Permit),
        );

        assert_eq!(
            admit(&f, ann()),
            StreamAdmission::Refused(StreamRefusal::RouteClosed)
        );
        assert_eq!(f.decisions.times_asked(), 0);
    }

    /// A connection naming an unknown route returns not found.
    #[test]
    fn an_unknown_route_is_not_found() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Permit));

        let result = block_on(f.use_case.execute(
            &tenant(),
            StreamConnection {
                stream_route_id: StreamRouteId::new(),
                server_name: None,
                caller: ann(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Looking up a tunnel through another tenant returns not found.
    #[test]
    fn another_tenants_route_is_not_found() {
        let f = people_tunnel(FakePolicyDecisionPoint::deciding(PolicyDecision::Permit));

        let result = block_on(f.use_case.execute(
            &ScopedTenant::for_test(TenantId::new()),
            StreamConnection {
                stream_route_id: f.route_id,
                server_name: None,
                caller: ann(),
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The billing port answers `db.acme.com`, and a certificate holder
    /// asking for it is let through.
    #[test]
    fn a_connection_for_a_name_the_route_answers_is_admitted() {
        let f = billing_port();
        let holder = StreamConnectionCaller::UnnamedCertificate;

        assert_eq!(
            admit_naming(&f, Some("db.acme.com"), holder),
            StreamAdmission::Admitted
        );
    }

    /// A certificate holder asking for another server name or no name is
    /// refused by the port restricted to `db.acme.com`.
    #[test]
    fn a_connection_for_another_name_or_none_is_refused() {
        let f = billing_port();
        let holder = StreamConnectionCaller::UnnamedCertificate;

        let other = admit_naming(&f, Some("other.acme.com"), holder.clone());
        let nameless = admit_naming(&f, None, holder);

        let refused = StreamAdmission::Refused(StreamRefusal::ServerNameNotMatched);
        assert_eq!(other, refused);
        assert_eq!(nameless, refused);
    }
}
