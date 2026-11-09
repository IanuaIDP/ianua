//! Recheck a connection: whether the person or consumer who opened a
//! long-lived connection through the gateway may still hold it open.
//!
//! A WebSocket a person opens outlives the request that checked them by
//! hours. Suspending Pat, ending her session, taking her out of a route's
//! group or withdrawing its permission must close what she holds open, not
//! only refuse her next request, and disabling a partner's consumer must
//! do the same to its connection. The gateway keeps the credential and what
//! the handshake asked, and asks this on an interval for as long as the
//! connection lasts.
//!
//! The answer is the one a fresh request would get: the same credential
//! check and the same access decision, on the route as stored now. Only a
//! clear yes keeps the connection open: a refusal of any kind, an answer
//! naming someone else, and a store that could not be read close it, the
//! last told apart so its record says the check failed rather than that
//! Pat lost access. A consumer's quota, counted at the handshake, is not
//! counted again.

use std::sync::Arc;

use ianua_domain::domains::proxy::access::decision::Outcome;
use ianua_domain::domains::proxy::access::question::{Asked, Circumstances};
use ianua_domain::domains::proxy::request::context::Caller;
use ianua_domain::types::{ConsumerId, DenialStatus, RouteId, UserId};

use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::proxy::credentials::{
    AuthenticateRequest, AuthenticateUseCase, Identification, Proven, Refusal,
};
use crate::use_cases::proxy::decide_access::{DecideAccessRequest, DecideAccessUseCase};

/// Who opened a connection, as the credential named them at the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHolder {
    /// A person, through a tenant account.
    Person(UserId),
    /// A consumer outside the platform.
    Consumer(ConsumerId),
}

impl ConnectionHolder {
    /// Whether `caller` is this holder.
    fn is(self, caller: &Caller) -> bool {
        match (self, caller) {
            (Self::Person(person), Caller::User { user_id, .. }) => *user_id == person,
            (Self::Consumer(consumer), Caller::Consumer { consumer_id, .. }) => {
                *consumer_id == consumer
            }
            _ => false,
        }
    }
}

/// What an open connection is checked against: the credential it opened
/// with, who that credential named, and what the handshake asked.
#[derive(Clone)]
pub struct RecheckConnectionRequest {
    /// The credential the handshake presented, as the gateway keeps it in
    /// memory for these checks.
    pub credential: AuthenticateRequest,
    /// Who the credential named at the handshake. Anyone else named now
    /// closes the connection.
    pub holder: ConnectionHolder,
    /// The route the handshake matched.
    pub route_id: RouteId,
    /// What the handshake asked for.
    pub asked: Asked,
    /// What was known around the handshake. Its key binding is replaced
    /// with what this check proves.
    pub circumstances: Circumstances,
}

/// Whether a connection's holder may still hold it open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStanding {
    /// They may; it stays open.
    Holds,
    /// They may not: a check refused them.
    Lost,
    /// A store could not be read, so the check could not be made. The
    /// connection closes all the same.
    CheckFailed,
}

/// The two checks [`RecheckConnectionUseCase`] runs.
pub struct RecheckConnectionChecks {
    /// Proves the credential and reads what its holder holds now.
    pub credentials: Arc<AuthenticateUseCase>,
    /// Decides on the route and the tenant's policy as they stand now.
    pub access: Arc<DecideAccessUseCase>,
}

/// Answers whether a person or consumer may still hold a connection open.
pub struct RecheckConnectionUseCase {
    ports: RecheckConnectionChecks,
}

impl RecheckConnectionUseCase {
    /// A use case checking through `ports`.
    #[must_use]
    pub fn new(ports: RecheckConnectionChecks) -> Self {
        Self { ports }
    }

    /// Who the credential proves, or how the check came out when it proves
    /// nobody who may hold this connection.
    async fn proven(
        &self,
        tenant: &ScopedTenant,
        credential: AuthenticateRequest,
        holder: ConnectionHolder,
    ) -> Result<Box<Proven>, ConnectionStanding> {
        let identified = self.ports.credentials.rechecked(tenant, credential).await;
        let proven = match identified {
            Ok(Identification::Proven(proven)) => proven,
            Err(Refusal::Unavailable) => return Err(ConnectionStanding::CheckFailed),
            Ok(Identification::Anonymous) | Err(_) => return Err(ConnectionStanding::Lost),
        };
        if holder.is(&proven.verified.caller) {
            return Ok(proven);
        }
        Err(ConnectionStanding::Lost)
    }
}

impl Query for RecheckConnectionUseCase {
    type Caller = ScopedTenant;
    type Input = RecheckConnectionRequest;
    type Output = ConnectionStanding;

    /// Whether `request`'s holder may still hold their connection in
    /// `tenant`. Anything but [`ConnectionStanding::Holds`] closes it.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: RecheckConnectionRequest,
    ) -> ConnectionStanding {
        let RecheckConnectionRequest {
            credential,
            holder,
            route_id,
            asked,
            circumstances,
        } = request;
        let proven = match self.proven(tenant, credential, holder).await {
            Ok(proven) => proven,
            Err(standing) => return standing,
        };
        let circumstances = Circumstances {
            binding: proven.binding,
            ..circumstances
        };
        let question = DecideAccessRequest {
            route_id,
            identification: Identification::Proven(proven),
            asked,
            circumstances,
        };
        standing_of(self.ports.access.execute(tenant, question).await.outcome())
    }
}

/// How the access decision's `outcome` leaves the connection. A refusal
/// for a store that could not be read is a failed check; every other
/// refusal, a challenge included, means the holder lost access.
fn standing_of(outcome: Outcome) -> ConnectionStanding {
    match outcome {
        Outcome::Permit => ConnectionStanding::Holds,
        Outcome::Deny(code) if code.status() == DenialStatus::SERVICE_UNAVAILABLE => {
            ConnectionStanding::CheckFailed
        }
        Outcome::Deny(_) | Outcome::Challenge(_) => ConnectionStanding::Lost,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::access::decision::DenyCode;
    use ianua_domain::domains::proxy::request::context::ConsumerCredential;

    use super::*;

    /// Only a permit keeps the connection open.
    #[test]
    fn only_a_permit_holds() {
        assert_eq!(standing_of(Outcome::Permit), ConnectionStanding::Holds);
        assert_eq!(
            standing_of(Outcome::Deny(DenyCode::PermissionMissing)),
            ConnectionStanding::Lost
        );
    }

    /// A store that could not be read is a failed check, never a pass.
    #[test]
    fn a_store_that_could_not_be_read_is_a_failed_check() {
        for code in [
            DenyCode::RouteUnreadable,
            DenyCode::RecordsUnreadable,
            DenyCode::TenantPolicyUnreadable,
        ] {
            assert_eq!(
                standing_of(Outcome::Deny(code)),
                ConnectionStanding::CheckFailed
            );
        }
    }

    fn partner(consumer_id: ConsumerId) -> Caller {
        Caller::Consumer {
            consumer_id,
            credential: ConsumerCredential::ApiKey,
        }
    }

    /// A partner's connection stays with that partner: its own key proves
    /// it, and another consumer's answer closes the connection.
    #[test]
    fn a_consumer_holds_only_its_own_connection() {
        let billing = ConsumerId::new();
        let holder = ConnectionHolder::Consumer(billing);

        assert!(holder.is(&partner(billing)));
        assert!(!holder.is(&partner(ConsumerId::new())));
    }

    /// A consumer's connection is not held by a person, whichever id it
    /// names.
    #[test]
    fn a_person_never_holds_a_consumers_connection() {
        let holder = ConnectionHolder::Person(UserId::new());

        assert!(!holder.is(&partner(ConsumerId::new())));
    }
}
