//! Who, by name, may use a stream route, and what the gateway does with a
//! caller it learned on the wire.
//!
//! A port open to any certificate from the tenant's CAs lets in every
//! machine that ever got one. Tying the route to people or to named
//! consumers lets the gateway ask the same question it asks on HTTP: is
//! this caller allowed here, under this policy, right now.

use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::stream::{StreamPolicy, StreamProtocol};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::ConsumerId;

/// Who may use a stream route, beyond what its policy checks on the wire.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StreamAccess {
    /// Whoever the policy lets through: anyone on a public port, and any
    /// holder of a certificate from the tenant's CAs on a mutual-TLS one.
    AnyHolder,
    /// People signed in to the tenant, through the signed-in tunnel, who
    /// meet this policy. The policy is never public.
    People(RoutePolicy),
    /// Only these consumers, known by their certificate or their tunnel
    /// token.
    Consumers(StreamConsumers),
}

/// The consumers a stream route lets through, each named once.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<ConsumerId>", into = "Vec<ConsumerId>")
)]
pub struct StreamConsumers(Vec<ConsumerId>);

impl StreamConsumers {
    /// The most consumers one route names.
    pub const MAX: usize = 100;

    /// A checked list of consumers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names none, more than 100, or
    ///   one twice.
    pub fn new(consumers: Vec<ConsumerId>) -> Result<Self, DomainError> {
        validate_count("consumers", consumers.len(), 1..=Self::MAX)?;
        if first_repeat(&consumers).is_some() {
            return Err(DomainError::invalid(message!(
                "routing-a-consumer-is-named-twice",
                "a consumer is named twice"
            )));
        }
        Ok(Self(consumers))
    }

    /// The consumers named.
    #[must_use]
    pub fn as_slice(&self) -> &[ConsumerId] {
        &self.0
    }

    /// Whether `consumer` is named.
    #[must_use]
    pub fn names(&self, consumer: &ConsumerId) -> bool {
        self.0.contains(consumer)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<Vec<ConsumerId>> for StreamConsumers {
    type Error = DomainError;

    fn try_from(consumers: Vec<ConsumerId>) -> Result<Self, Self::Error> {
        Self::new(consumers)
    }
}

#[cfg(feature = "serde")]
impl From<StreamConsumers> for Vec<ConsumerId> {
    fn from(consumers: StreamConsumers) -> Self {
        consumers.0
    }
}

/// Who the gateway found on a stream connection, once the wire was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCaller<'a> {
    /// No one: no certificate, no tunnel token.
    Nobody,
    /// A certificate from the tenant's CAs that belongs to no consumer.
    UnnamedCertificate,
    /// A consumer, by its certificate or its tunnel token.
    Consumer(&'a ConsumerId),
    /// A person signed in to the tenant, through the tunnel.
    Person,
}

/// What the gateway does with a stream caller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamVerdict<'a> {
    /// Splice the connection.
    Admit,
    /// Ask the policy port whether the person meets this policy, and splice
    /// only on a yes. Any error there is a refusal.
    CheckPolicy(&'a RoutePolicy),
    /// Close the connection.
    Refuse,
}

impl StreamAccess {
    /// What the gateway does with `caller` on a route that checks `policy`
    /// on the wire. Anything not named here is refused.
    #[must_use]
    pub fn admits<'a>(
        &'a self,
        policy: StreamPolicy,
        caller: StreamCaller<'_>,
    ) -> StreamVerdict<'a> {
        match (self, caller) {
            (Self::AnyHolder, _) if policy == StreamPolicy::Public => StreamVerdict::Admit,
            (Self::AnyHolder, StreamCaller::UnnamedCertificate | StreamCaller::Consumer(_)) => {
                StreamVerdict::Admit
            }
            (Self::People(rule), StreamCaller::Person) => StreamVerdict::CheckPolicy(rule),
            (Self::Consumers(named), StreamCaller::Consumer(id)) if named.names(id) => {
                StreamVerdict::Admit
            }
            (Self::AnyHolder | Self::People(_) | Self::Consumers(_), _) => StreamVerdict::Refuse,
        }
    }

    /// Refuses access the route's protocol and policy cannot deliver.
    ///
    /// - A public port knows no one, so it is open to any holder only.
    /// - A tunnel always names its caller, so it names whom it lets in.
    /// - A client certificate names a consumer, never a person. People come
    ///   in through the signed-in tunnel.
    /// - People are held to a policy that asks for sign-in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for each case above.
    pub(super) fn ensure_fits(
        &self,
        protocol: StreamProtocol,
        policy: StreamPolicy,
    ) -> Result<(), DomainError> {
        if policy == StreamPolicy::Tunnel && protocol != StreamProtocol::Tcp {
            return Err(DomainError::invalid(message!(
                "routing-a-signed-in-tunnel-carries-a",
                "a signed-in tunnel carries a TCP stream, so the route speaks tcp"
            )));
        }
        match (policy, self) {
            (StreamPolicy::Public, Self::People(_) | Self::Consumers(_)) => {
                Err(DomainError::invalid(message!(
                    "routing-a-public-port-knows-no-one",
                    "a public port knows no one, so it cannot be tied to anyone"
                )))
            }
            (StreamPolicy::Tunnel, Self::AnyHolder) => Err(DomainError::invalid(message!(
                "routing-a-tunnel-route-names-the-people",
                "a tunnel route names the people or consumers it lets in"
            ))),
            (StreamPolicy::MutualTls, Self::People(_)) => Err(DomainError::invalid(message!(
                "routing-a-client-certificate-names-a-consumer",
                "a client certificate names a consumer, never a person; people use the \
                 signed-in tunnel"
            ))),
            (_, Self::People(rule)) if rule.is_public() => Err(DomainError::invalid(message!(
                "routing-people-let-into-a-stream-route",
                "people let into a stream route are held to a policy that asks for sign-in"
            ))),
            (StreamPolicy::Public | StreamPolicy::Tunnel | StreamPolicy::MutualTls, _) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consumers(ids: &[ConsumerId]) -> StreamAccess {
        StreamAccess::Consumers(StreamConsumers::new(ids.to_vec()).unwrap())
    }

    /// The postgres port lets in only the "billing-sync" consumer. Its
    /// certificate is admitted.
    #[test]
    fn a_named_consumer_is_admitted() {
        let billing = ConsumerId::new();
        let access = consumers(&[billing]);

        assert_eq!(
            access.admits(StreamPolicy::MutualTls, StreamCaller::Consumer(&billing)),
            StreamVerdict::Admit
        );
    }

    /// Access restricted to named consumers refuses an unnamed certificate,
    /// another consumer, an unidentified caller and a person.
    #[test]
    fn anyone_not_named_is_refused() {
        let access = consumers(&[ConsumerId::new()]);

        for caller in [
            StreamCaller::UnnamedCertificate,
            StreamCaller::Consumer(&ConsumerId::new()),
            StreamCaller::Nobody,
            StreamCaller::Person,
        ] {
            assert_eq!(
                access.admits(StreamPolicy::MutualTls, caller),
                StreamVerdict::Refuse,
                "{caller:?}"
            );
        }
    }

    /// The SSH tunnel lets in people with the ops permission. Ann comes
    /// through the tunnel, and the gateway asks the policy before splicing.
    /// A consumer on the same route is refused.
    #[test]
    fn a_person_on_a_people_route_is_held_to_its_policy() {
        let access = StreamAccess::People(RoutePolicy::Authenticated);

        assert_eq!(
            access.admits(StreamPolicy::Tunnel, StreamCaller::Person),
            StreamVerdict::CheckPolicy(&RoutePolicy::Authenticated)
        );
        assert_eq!(
            access.admits(
                StreamPolicy::Tunnel,
                StreamCaller::Consumer(&ConsumerId::new())
            ),
            StreamVerdict::Refuse
        );
    }

    /// Any-holder access on a mutual-TLS route refuses an unidentified
    /// caller and admits an unnamed certificate holder.
    #[test]
    fn any_holder_on_a_mutual_tls_port_still_needs_a_certificate() {
        let access = StreamAccess::AnyHolder;

        assert_eq!(
            access.admits(StreamPolicy::MutualTls, StreamCaller::Nobody),
            StreamVerdict::Refuse
        );
        assert_eq!(
            access.admits(StreamPolicy::MutualTls, StreamCaller::UnnamedCertificate),
            StreamVerdict::Admit
        );
    }

    /// A public port, a tunnel open to any holder, people on a certificate
    /// port, people under a public policy, and a tunnel over UDP are all
    /// refused.
    #[test]
    fn access_the_wire_cannot_deliver_is_refused() {
        let named = consumers(&[ConsumerId::new()]);
        let people = StreamAccess::People(RoutePolicy::Authenticated);
        let anyone = StreamAccess::People(RoutePolicy::Public);

        assert_incompatible(&named, StreamProtocol::Tcp, StreamPolicy::Public);
        assert_incompatible(
            &StreamAccess::AnyHolder,
            StreamProtocol::Tcp,
            StreamPolicy::Tunnel,
        );
        assert_incompatible(
            &people,
            StreamProtocol::TlsTerminate,
            StreamPolicy::MutualTls,
        );
        assert_incompatible(&anyone, StreamProtocol::Tcp, StreamPolicy::Tunnel);
        assert_incompatible(&people, StreamProtocol::Udp, StreamPolicy::Tunnel);
        assert!(
            people
                .ensure_fits(StreamProtocol::Tcp, StreamPolicy::Tunnel)
                .is_ok()
        );
    }

    /// Access requiring an identity the wire cannot establish must be refused.
    fn assert_incompatible(access: &StreamAccess, protocol: StreamProtocol, policy: StreamPolicy) {
        assert!(access.ensure_fits(protocol, policy).is_err());
    }

    /// A consumer list that is empty or names one consumer twice is refused.
    #[test]
    fn consumers_are_named_once_each() {
        let billing = ConsumerId::new();

        assert!(StreamConsumers::new(Vec::new()).is_err());
        assert!(StreamConsumers::new(vec![billing, billing]).is_err());
    }
}
