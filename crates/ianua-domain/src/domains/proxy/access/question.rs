//! What the gateway's access decision is asked: the route, who is calling
//! with what the tenant's records say of them, the request, the facts
//! around it, and the tenant's live policy.
//!
//! Everything the decision rests on that had to be read says whether it was
//! read. A store that could not be reached is a value here, not a missing
//! one, so the decision refuses on it instead of deciding without it.

use std::net::IpAddr;

use crate::domains::authentication::risk_engine::step_up::{Familiarity, Sensitivity};
use crate::domains::authorization::held::Held;
use crate::domains::authorization::policy::condition::RiskThreshold;
use crate::domains::authorization::policy::set::PolicySet;
use crate::domains::authorization::policy::time_window::ZonedTime;
use crate::domains::proxy::request::context::{Caller, CallerClaims};
use crate::domains::proxy::stages::posture::PostureVerdict;
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::Route;
use crate::domains::routing::route_status::RouteStatus;
use crate::isolation::scope::TenantScope;
use crate::types::{CanonicalPath, CountryCode, DeclaredAction, Fact, HostName, HttpMethod};

/// What a read the decision needs came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<T> {
    /// It was read and found.
    Found(T),
    /// It was read, and there is none.
    Missing,
    /// It could not be read, or not in time.
    Unreadable,
}

impl<T> Lookup<T> {
    /// What was read, lent out.
    #[must_use]
    pub fn as_ref(&self) -> Lookup<&T> {
        match self {
            Self::Found(found) => Lookup::Found(found),
            Self::Missing => Lookup::Missing,
            Self::Unreadable => Lookup::Unreadable,
        }
    }

    /// What was read, made into something else.
    #[must_use]
    pub fn map<U>(self, into: impl FnOnce(T) -> U) -> Lookup<U> {
        match self {
            Self::Found(found) => Lookup::Found(into(found)),
            Self::Missing => Lookup::Missing,
            Self::Unreadable => Lookup::Unreadable,
        }
    }
}

/// What the matched route asks of a request, as it is stored now.
#[derive(Debug, Clone, Copy)]
pub struct RouteTerms<'a> {
    /// Who may pass.
    pub policy: &'a RoutePolicy,
    /// The kind of action the route declares it takes.
    pub action: DeclaredAction,
    /// Whether the route is in use.
    pub status: RouteStatus,
}

impl<'a> RouteTerms<'a> {
    /// What `route` asks of a request.
    #[must_use]
    pub fn of<T: TenantScope>(route: &'a Route<T>) -> Self {
        Self {
            policy: route.policy(),
            action: route.action_class(),
            status: route.status(),
        }
    }
}

/// Whether the tenant's records know a caller and let it act now: what the
/// policy decision point answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The records name no such caller in the tenant, or it is not a kind
    /// of caller a tenant's gateway serves.
    Unknown,
    /// The records name it, but it may not act now: a locked or closed
    /// account, a suspended or revoked agent, a disabled consumer.
    Barred,
    /// It may act.
    Good,
}

/// What the tenant's records say of a signed-in caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Records {
    /// The records name no such caller.
    Unknown,
    /// The caller may not act now.
    Barred,
    /// The caller may act, holding this.
    Holds(Held),
    /// The records could not be read.
    Unreadable,
    /// What was read is too old to decide this request on: it was read for
    /// another request, or held past the time a request may take.
    Stale,
}

/// Whose authority an agent acts on, beyond its own token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnBehalf {
    /// Nobody else's: the caller is a person or a consumer, or an agent
    /// acting for itself, held to its own grants.
    Own,
    /// The agent acts for someone else: what the records say of that
    /// delegator now. An agent never does more than they still hold.
    Of(Records),
}

/// Who is asking.
#[derive(Debug, Clone, Copy)]
pub enum Asker<'a> {
    /// Nobody proved who they are.
    Anonymous,
    /// The credential the Identity stage verified, and what the tenant's
    /// records say of the caller it names.
    Identified {
        /// Who the credential names.
        caller: &'a Caller,
        /// What the credential carries: its scopes, an agent token's
        /// permissions, the sign-in's assurance level, the claims it
        /// asserts.
        credential: &'a CallerClaims,
        /// What the tenant's records say of the caller.
        records: &'a Records,
        /// For an agent acting for someone else, what the records say of
        /// them.
        on_behalf: &'a OnBehalf,
    },
}

/// Whether a request asks to be read as another method than the one it was
/// sent with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodClaim {
    /// The method on the request line is the method meant.
    AsSent,
    /// An override header, a `_method` parameter or a form body asks the
    /// upstream to read it as another method.
    Overridden,
}

/// What the request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The HTTP method, when it is one the platform knows.
    pub method: Fact<HttpMethod>,
    /// The path in its canonical spelling, when it has one.
    pub path: Fact<CanonicalPath>,
    /// Whether the request asks to be read as another method.
    pub method_claim: MethodClaim,
    /// The host the request is for.
    pub host: Fact<HostName>,
}

/// Whether the request proved possession of the key its credential is
/// bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopBinding {
    /// The gateway verified a `DPoP` proof for this request against the key
    /// the credential is bound to.
    Bound,
    /// No proof was verified: none was sent, or the credential is bound to
    /// no key.
    Unbound,
}

/// What a device posture check on the request found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureFinding {
    /// The route's pipeline asks for no posture check.
    NotAsked,
    /// The check ran and gave this verdict.
    Checked(PostureVerdict),
}

/// What is known around the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Circumstances {
    /// The client's country, when the address could be placed.
    pub country: Fact<CountryCode>,
    /// The client's address, as the edge saw it.
    pub source_ip: Fact<IpAddr>,
    /// Whether the device has been seen and trusted before.
    pub device: Fact<Familiarity>,
    /// The risk of the request.
    pub risk: Fact<RiskThreshold>,
    /// Whether the request is a sensitive operation.
    pub sensitivity: Fact<Sensitivity>,
    /// Whether the request proved possession of its credential's key.
    pub binding: DpopBinding,
    /// What a device posture check found.
    pub posture: PostureFinding,
}

impl Circumstances {
    /// Nothing known around a request: what a dry run or a start page asks
    /// with, so a rule that needs the country, the device or the risk
    /// refuses, as it would without them.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            country: Fact::Unknown,
            source_ip: Fact::Unknown,
            device: Fact::Unknown,
            risk: Fact::Unknown,
            sensitivity: Fact::Unknown,
            binding: DpopBinding::Unbound,
            posture: PostureFinding::NotAsked,
        }
    }
}

/// Everything one access decision rests on.
#[derive(Debug, Clone, Copy)]
pub struct AccessQuestion<'a> {
    /// The route the request matched, as stored now.
    pub route: Lookup<RouteTerms<'a>>,
    /// Who is asking.
    pub asker: Asker<'a>,
    /// What the request asks for.
    pub asked: &'a Asked,
    /// What is known around it.
    pub circumstances: &'a Circumstances,
    /// The time of day the request arrived, in each zone the tenant's
    /// policy names. A zone left out is a time nobody knows.
    pub local_times: &'a [ZonedTime],
    /// The tenant's live access policy. Missing when the tenant has none
    /// live.
    pub tenant_policy: Lookup<&'a PolicySet>,
}
