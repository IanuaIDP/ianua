//! Who a request comes from, as the Identity stage proved it: nobody, or a
//! caller with what they hold, when that was read, and whether the request
//! proved the key their credential is bound to.

use time::OffsetDateTime;

use crate::domains::authorization::held::Held;
use crate::domains::proxy::access::question::DpopBinding;
use crate::domains::proxy::request::context::{CallerClaims, Verified};

/// Who a request comes from.
#[derive(Debug, Clone, Default)]
pub enum Identification {
    /// Nobody: the route is public and the request proved no one, or
    /// carried a token the route's service pins no audience for.
    #[default]
    Anonymous,
    /// The caller its credential proved.
    Proven(Box<Proven>),
}

impl Identification {
    /// Whether the request proved possession of the key its credential is
    /// bound to. Nobody proves no key.
    #[must_use]
    pub fn binding(&self) -> DpopBinding {
        match self {
            Self::Anonymous => DpopBinding::Unbound,
            Self::Proven(proven) => proven.binding,
        }
    }
}

/// A caller a credential proved, with what they hold now.
///
/// The access decision takes `held` from here rather than reading the
/// records again, and refuses it once `established_at` is too far back.
#[derive(Debug, Clone)]
pub struct Proven {
    /// Who the credential names, and until when it holds.
    pub verified: Verified,
    /// What the credential carries and the caller holds, written out: their
    /// scopes, permissions, roles, assurance and asserted claims.
    pub claims: CallerClaims,
    /// What the tenant's records give the caller, as read for this request.
    pub held: Held,
    /// When the caller's standing was checked and `held` read.
    pub established_at: OffsetDateTime,
    /// Whether the credential is bound to a key and the request proved it
    /// holds that key with a `DPoP` proof the check verified. A proof sent
    /// beside a credential bound to no key binds nothing.
    pub binding: DpopBinding,
}
