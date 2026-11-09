//! The edge of a gateway document beside HTTP: stream routes, where
//! services may send traffic out, and the consumers let in.
//!
//! A consumer's API key is never written down, only the prefix that tells
//! it apart. Its hash would let anyone holding the file test guesses
//! offline, and a key is shown once, when it is made.

use std::collections::HashMap;

use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerStatus};
use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::domains::consumers::quota::ConsumerQuota;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::egress::{EgressDestination, EgressPolicy, ServiceIdentity};
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::stream::access::StreamAccess;
use ianua_domain::domains::routing::stream::{
    ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamRoute, StreamTimeouts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, HttpsUrl, Issuer, KeyPrefix,
    Label,
};

/// A port below HTTP, as declared.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamRouteDeclaration {
    /// Unique within the tenant; the key this document is applied by.
    pub name: Label,
    /// How the proxy speaks on the port. Fixed once the route exists.
    pub protocol: StreamProtocol,
    /// The port listened on. Fixed once the route exists.
    pub listen_port: ListenPort,
    /// Which handshakes it answers.
    pub sni: RouteHosts,
    /// What is checked on the wire.
    pub policy: StreamPolicy,
    /// Who by name may pass.
    pub access: StreamAccessDeclaration,
    /// Where accepted streams go.
    pub backends: Vec<StreamBackend>,
    /// How long a stream may take to start, and stay silent.
    pub timeouts: StreamTimeouts,
    /// Whether it is accepting connections.
    pub status: RouteStatus,
}

/// Who may use a stream route, as declared: naming consumers rather than
/// pointing at their ids.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamAccessDeclaration {
    /// Whoever the route's policy lets through.
    AnyHolder,
    /// People signed in to the tenant who meet this policy.
    People(RoutePolicy),
    /// Only these consumers, by name.
    Consumers(Vec<Label>),
}

/// Where one service may send traffic, as declared.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressPolicyDeclaration {
    /// The name people recognise the service by.
    pub name: Label,
    /// The service the policy is for; one policy per service, so this is
    /// the key the document is applied by.
    pub service: ServiceIdentity,
    /// Where it may go.
    pub destinations: Vec<EgressDestination>,
    /// The most sensitive data an agent's call through it may carry out.
    pub max_data_class: DataClassLevel,
}

/// A non-human caller, as declared.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsumerDeclaration {
    /// Unique within the tenant; the key this document is applied by.
    pub name: Label,
    /// How it signs in, without anything secret.
    pub credential: ConsumerCredentialDeclaration,
    /// When its credential stops working.
    pub credential_expiry: Expiry,
    /// How many requests it may send.
    pub quota: ConsumerQuota,
    /// The most sensitive data it may receive.
    pub clearance: DataClassLevel,
    /// Whether its requests go through.
    pub status: ConsumerStatus,
}

/// How a consumer signs in, as a document may carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumerCredentialDeclaration {
    /// An API key, known only by its visible prefix.
    ApiKey {
        /// The first characters of the key.
        prefix: KeyPrefix,
    },
    /// A client certificate, by its SHA-256 fingerprint.
    ClientCert {
        /// The certificate's fingerprint.
        fingerprint: CertificateFingerprint,
    },
    /// A JWT the consumer signs itself.
    JwtBearer {
        /// The expected `iss` claim.
        issuer: Issuer,
        /// The expected `sub` claim.
        subject: FederatedSubject,
        /// Where the consumer publishes its signing keys.
        jwks_uri: HttpsUrl,
    },
}

impl StreamRouteDeclaration {
    /// Describes a live stream route, naming its consumers from
    /// `consumers`.
    ///
    /// `None` when it names a consumer that is gone: it could not be made
    /// again from the document.
    #[must_use]
    pub(crate) fn of(
        route: &StreamRoute<ResolvedTenant>,
        consumers: &HashMap<ConsumerId, Label>,
    ) -> Option<Self> {
        Some(Self {
            name: route.name().clone(),
            protocol: route.protocol(),
            listen_port: route.listen_port(),
            sni: route.sni().clone(),
            policy: route.policy(),
            access: StreamAccessDeclaration::of(route.access(), consumers)?,
            backends: route.backends().to_vec(),
            timeouts: route.timeouts(),
            status: route.status(),
        })
    }
}

impl StreamAccessDeclaration {
    /// Describes `access`, naming its consumers from `consumers`. `None`
    /// when one is missing.
    fn of(access: &StreamAccess, consumers: &HashMap<ConsumerId, Label>) -> Option<Self> {
        match access {
            StreamAccess::AnyHolder => Some(Self::AnyHolder),
            StreamAccess::People(policy) => Some(Self::People(policy.clone())),
            StreamAccess::Consumers(named) => named
                .as_slice()
                .iter()
                .map(|consumer| consumers.get(consumer).cloned())
                .collect::<Option<Vec<Label>>>()
                .map(Self::Consumers),
        }
    }
}

impl EgressPolicyDeclaration {
    /// Describes a live egress policy.
    #[must_use]
    pub fn of(policy: &EgressPolicy<ResolvedTenant>) -> Self {
        Self {
            name: policy.name().clone(),
            service: policy.service().clone(),
            destinations: policy.destinations().to_vec(),
            max_data_class: policy.max_data_class(),
        }
    }
}

impl ConsumerDeclaration {
    /// Describes a live consumer by the credential it signs in with now.
    #[must_use]
    pub fn of(consumer: &Consumer<ResolvedTenant>) -> Self {
        let current = consumer.credentials().current();
        Self {
            name: consumer.name().clone(),
            credential: ConsumerCredentialDeclaration::of(current.kind()),
            credential_expiry: current.expiry(),
            quota: consumer.quota(),
            clearance: consumer.clearance(),
            status: consumer.status(),
        }
    }
}

impl ConsumerCredentialDeclaration {
    /// Describes `credential`, leaving out an API key's hash.
    #[must_use]
    pub fn of(credential: &ConsumerCredentialKind) -> Self {
        match credential {
            ConsumerCredentialKind::ApiKey { prefix, .. } => Self::ApiKey {
                prefix: prefix.clone(),
            },
            ConsumerCredentialKind::ClientCert { fingerprint } => Self::ClientCert {
                fingerprint: *fingerprint,
            },
            ConsumerCredentialKind::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Self::JwtBearer {
                issuer: issuer.clone(),
                subject: subject.clone(),
                jwks_uri: jwks_uri.clone(),
            },
        }
    }

    /// The credential a new consumer is made with, when the document can
    /// say all of it. An API key cannot be: its key is made and shown once,
    /// when the consumer is created by hand.
    #[must_use]
    pub(crate) fn to_kind(&self) -> Option<ConsumerCredentialKind> {
        match self {
            Self::ApiKey { .. } => None,
            Self::ClientCert { fingerprint } => Some(ConsumerCredentialKind::ClientCert {
                fingerprint: *fingerprint,
            }),
            Self::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Some(ConsumerCredentialKind::JwtBearer {
                issuer: issuer.clone(),
                subject: subject.clone(),
                jwks_uri: jwks_uri.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::stream::access::StreamConsumers;
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::routing::{routing_label, tunnel_on};

    /// The billing consumer signs in with an API key. Its declaration keeps
    /// the key's prefix and never its hash.
    #[test]
    fn an_api_key_is_declared_by_its_prefix_alone() {
        let declared = ConsumerDeclaration::of(&billing_sync());

        assert!(matches!(
            declared.credential,
            ConsumerCredentialDeclaration::ApiKey { .. }
        ));
        assert!(declared.credential.to_kind().is_none());
    }

    /// Formatting an API-key declaration for debugging does not expose the
    /// consumer's stored key hash.
    #[test]
    fn no_key_hash_appears_in_a_declaration() {
        let hash = TokenHash::from_stored("hash-of-the-key".to_owned());
        let declared = ConsumerCredentialDeclaration::of(&ConsumerCredentialKind::ApiKey {
            prefix: KeyPrefix::new("sk_live_abc").unwrap(),
            key_hash: hash,
        });

        assert!(!format!("{declared:?}").contains("hash-of-the-key"));
    }

    /// The billing tunnel names the billing consumer. Its declaration names
    /// it, and a tunnel naming a consumer that is gone has none.
    #[test]
    fn a_tunnel_names_its_consumers() {
        let billing = billing_sync();
        let named = StreamConsumers::new(vec![*billing.id()]).unwrap();
        let tunnel = tunnel_on(15433, StreamAccess::Consumers(named));
        let names = HashMap::from([(*billing.id(), routing_label("billing-sync"))]);

        let declared = StreamRouteDeclaration::of(&tunnel, &names).unwrap();

        assert_eq!(
            declared.access,
            StreamAccessDeclaration::Consumers(vec![routing_label("billing-sync")])
        );
        assert!(StreamRouteDeclaration::of(&tunnel, &HashMap::new()).is_none());
    }
}
