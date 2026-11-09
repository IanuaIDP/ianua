//! Who is asking, once the tenant's records say they may act, and the
//! checks that turn on who they are: a key their credential is bound to,
//! the route's policy, and an agent's task limits.

use std::borrow::Cow;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::held::Held;
use crate::domains::authorization::permission::CustomPermission;
use crate::domains::proxy::access::assurance::SignInStrength;
use crate::domains::proxy::access::decision::DenyCode;
use crate::domains::proxy::access::question::{
    Asked, Asker, DpopBinding, MethodClaim, OnBehalf, Records,
};
use crate::domains::proxy::request::context::{AgentLimits, Caller, CallerClaims, KeyBinding};
use crate::domains::routing::policy::{PolicyStanding, RouteCaller, RoutePolicy};
use crate::shared::model::restriction::Restriction;
use crate::types::{
    AgentId, DeclaredAction, Fact, GroupId, PermissionName, PrincipalRef, RoleId, Scope,
};

/// A caller the decision goes on with: nobody, or one the tenant's records
/// let act, with what it holds.
#[derive(Debug, Clone, Copy)]
pub(super) enum Requester<'a> {
    /// Nobody proved who they are.
    Anonymous,
    /// A person.
    User {
        /// What the records give them.
        held: &'a Held,
        /// How strongly they signed in.
        assurance: Fact<AssuranceLevel>,
    },
    /// An agent under one delegation.
    Agent {
        /// What its task token confines it to.
        limits: &'a AgentLimits,
        /// The permissions its task token names.
        token: &'a [PermissionName],
        /// What the records give the agent itself: its roles and groups.
        held: &'a Held,
        /// What the one whose authority it acts on holds now: the person it
        /// acts for, or the agent itself.
        authority: &'a Held,
    },
    /// A consumer outside the platform.
    Consumer {
        /// What its roles give it.
        held: &'a Held,
        /// The scopes its credential carries.
        scopes: &'a [Scope],
    },
}

impl<'a> Requester<'a> {
    /// The caller `asker` names, once the records say it may act.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::CallerUnknown`] when the records name no such caller.
    /// - [`DenyCode::CallerBarred`] when it may not act now.
    /// - [`DenyCode::RecordsUnreadable`] when the records could not be read.
    /// - [`DenyCode::RecordsStale`] when they were read too long ago.
    /// - The cases [`authority_of`] lists, for an agent acting for someone
    ///   else.
    pub(super) fn of(asker: Asker<'a>) -> Result<Self, DenyCode> {
        let Asker::Identified {
            caller,
            credential,
            records,
            on_behalf,
        } = asker
        else {
            return Ok(Self::Anonymous);
        };
        let held = held_in(records)?;
        Self::of_caller(caller, credential, held, on_behalf)
    }

    /// The requester `caller` is, holding `held`, its credential carrying
    /// `credential`.
    fn of_caller(
        caller: &'a Caller,
        credential: &'a CallerClaims,
        held: &'a Held,
        on_behalf: &'a OnBehalf,
    ) -> Result<Self, DenyCode> {
        Ok(match caller {
            Caller::User { .. } => Self::User {
                held,
                assurance: credential.current_aal,
            },
            Caller::Agent {
                agent_id,
                acting_for,
                limits,
                ..
            } => Self::Agent {
                limits,
                token: &credential.permissions,
                held,
                authority: authority_of(agent_id, acting_for, held, on_behalf)?,
            },
            Caller::Consumer { .. } => Self::Consumer {
                held,
                scopes: &credential.scopes,
            },
        })
    }

    /// Refuses a credential bound to a key when the request proved no
    /// possession of it.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::KeyNotProven`] for an agent whose task token is bound to
    ///   a key, on a request without a verified proof.
    pub(super) fn ensure_key_proven(&self, binding: DpopBinding) -> Result<(), DenyCode> {
        let Self::Agent { limits, .. } = self else {
            return Ok(());
        };
        match (&limits.key_binding, binding) {
            (KeyBinding::Bearer, _) | (KeyBinding::Key(_), DpopBinding::Bound) => Ok(()),
            (KeyBinding::Key(_), DpopBinding::Unbound) => Err(DenyCode::KeyNotProven),
        }
    }

    /// Refuses an agent's request that asks to be read as another method:
    /// a `GET` the upstream runs as a `DELETE` would carry a delete through
    /// a read-only intent.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::MethodOverridden`] for an agent's request that asks to
    ///   be read as another method.
    pub(super) fn ensure_sent_as(&self, claim: MethodClaim) -> Result<(), DenyCode> {
        match (self, claim) {
            (Self::Agent { .. }, MethodClaim::Overridden) => Err(DenyCode::MethodOverridden),
            _ => Ok(()),
        }
    }

    /// Refuses a caller the route's policy does not let through.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::NothingDelegated`] for an agent whose task token names
    ///   nothing, whatever the route asks for.
    /// - [`DenyCode::SignInRequired`] for nobody on a route that is not
    ///   public.
    /// - [`DenyCode::NothingListed`], [`DenyCode::PermissionMissing`] or
    ///   [`DenyCode::ScopeMissing`] for a caller the policy refuses.
    pub(super) fn ensure_meets(&self, policy: &RoutePolicy) -> Result<(), DenyCode> {
        self.ensure_given_something()?;
        let Some(caller) = self.route_caller() else {
            return ensure_public(policy);
        };
        match policy.standing_of(caller) {
            PolicyStanding::Met => Ok(()),
            PolicyStanding::NothingListed => Err(DenyCode::NothingListed),
            PolicyStanding::PermissionMissing => Err(DenyCode::PermissionMissing),
            PolicyStanding::ScopeMissing => Err(DenyCode::ScopeMissing),
        }
    }

    /// Refuses an agent whose task token names no permission and nothing on
    /// an MCP server.
    ///
    /// Such a token carries no authority, only its audiences: the apps its
    /// delegation lists. A route that asks only for a signed-in caller
    /// would let it through on the audience alone. Ann's reviewer agent is
    /// meant to hold nothing; a delegation granting nothing but naming the
    /// billing app would otherwise reach every page of it.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::NothingDelegated`] for such an agent.
    fn ensure_given_something(&self) -> Result<(), DenyCode> {
        let Self::Agent { token, limits, .. } = self else {
            return Ok(());
        };
        if token.is_empty() && limits.mcp.is_empty() {
            return Err(DenyCode::NothingDelegated);
        }
        Ok(())
    }

    /// Refuses an agent's request outside what its task token confines it
    /// to: the action its intent allows, and the paths its resource scope
    /// reaches. A request whose method or path is not known meets neither.
    ///
    /// # Errors
    ///
    /// - [`DenyCode::OutsideIntent`] for an action the intent does not
    ///   allow.
    /// - [`DenyCode::OutsideResourceScope`] for a path the scope does not
    ///   reach.
    pub(super) fn ensure_within_limits(
        &self,
        asked: &Asked,
        action: DeclaredAction,
    ) -> Result<(), DenyCode> {
        let Self::Agent { limits, .. } = self else {
            return Ok(());
        };
        ensure_within_intent(limits, asked, action)?;
        ensure_within_scope(limits, asked)
    }

    /// How strongly the caller signed in, and whether they can sign in
    /// again. Only a person's sign-in has a level; nobody's and a machine's
    /// are unknown. A person can sign in again, and so can someone not yet
    /// signed in; an agent or a consumer cannot.
    pub(super) fn sign_in_strength(&self) -> SignInStrength {
        match *self {
            Self::User { assurance, .. } => SignInStrength::person(assurance),
            Self::Anonymous => SignInStrength::nobody(),
            Self::Agent { .. } | Self::Consumer { .. } => SignInStrength::machine(),
        }
    }

    /// The roles the caller holds. Nobody holds none.
    pub(super) fn roles(&self) -> &'a [RoleId] {
        self.held().map(Held::roles).unwrap_or_default()
    }

    /// The groups the caller is in. Nobody is in none.
    pub(super) fn groups(&self) -> &'a [GroupId] {
        self.held().map(Held::groups).unwrap_or_default()
    }

    /// The app permissions the caller holds: an agent those its token names
    /// that its authority still holds, anyone else those the records give.
    pub(super) fn custom_permissions(&self) -> Cow<'a, [CustomPermission]> {
        match *self {
            Self::Anonymous => Cow::Borrowed(&[]),
            Self::User { held, .. } | Self::Consumer { held, .. } => {
                Cow::Borrowed(held.holdings().custom())
            }
            Self::Agent {
                token, authority, ..
            } => Cow::Owned(
                token
                    .iter()
                    .filter_map(|name| CustomPermission::parse(name.as_str()))
                    .filter(|permission| authority.holdings().holds_custom(permission))
                    .collect(),
            ),
        }
    }

    /// What the records give the caller, when someone signed in.
    fn held(&self) -> Option<&'a Held> {
        match *self {
            Self::Anonymous => None,
            Self::User { held, .. } | Self::Agent { held, .. } | Self::Consumer { held, .. } => {
                Some(held)
            }
        }
    }

    /// The caller as a route's policy reads it, when someone signed in.
    fn route_caller(&self) -> Option<RouteCaller<'a>> {
        match *self {
            Self::Anonymous => None,
            Self::User { held, .. } => Some(RouteCaller::Person(held.holdings())),
            Self::Agent {
                token, authority, ..
            } => Some(RouteCaller::Agent {
                token,
                authority: authority.holdings(),
            }),
            Self::Consumer { held, scopes } => Some(RouteCaller::Consumer {
                holdings: held.holdings(),
                scopes,
            }),
        }
    }
}

/// What the records give a caller they let act.
fn held_in(records: &Records) -> Result<&Held, DenyCode> {
    match records {
        Records::Holds(held) => Ok(held),
        Records::Unknown => Err(DenyCode::CallerUnknown),
        Records::Barred => Err(DenyCode::CallerBarred),
        Records::Unreadable => Err(DenyCode::RecordsUnreadable),
        Records::Stale => Err(DenyCode::RecordsStale),
    }
}

/// What the one an agent acts for holds now: the agent's own records when
/// it acts for itself, the delegator's otherwise.
///
/// # Errors
///
/// - [`DenyCode::DelegatorUnknown`] when the agent acts for someone the
///   records do not know, or the question says nothing of them.
/// - [`DenyCode::DelegatorBarred`] when they may not act now.
/// - [`DenyCode::RecordsUnreadable`] or [`DenyCode::RecordsStale`] when
///   their records could not be read, or were read too long ago.
fn authority_of<'a>(
    agent: &AgentId,
    acting_for: &PrincipalRef,
    own: &'a Held,
    on_behalf: &'a OnBehalf,
) -> Result<&'a Held, DenyCode> {
    if *acting_for == PrincipalRef::Agent(*agent) {
        return Ok(own);
    }
    let OnBehalf::Of(delegator) = on_behalf else {
        return Err(DenyCode::DelegatorUnknown);
    };
    match delegator {
        Records::Holds(held) => Ok(held),
        Records::Unknown => Err(DenyCode::DelegatorUnknown),
        Records::Barred => Err(DenyCode::DelegatorBarred),
        Records::Unreadable => Err(DenyCode::RecordsUnreadable),
        Records::Stale => Err(DenyCode::RecordsStale),
    }
}

/// Lets nobody through a route that is not public.
fn ensure_public(policy: &RoutePolicy) -> Result<(), DenyCode> {
    if policy.is_public() {
        return Ok(());
    }
    Err(DenyCode::SignInRequired)
}

/// Refuses an action an agent's intent does not allow.
fn ensure_within_intent(
    limits: &AgentLimits,
    asked: &Asked,
    action: DeclaredAction,
) -> Result<(), DenyCode> {
    let Restriction::To(envelope) = &limits.intent_envelope else {
        return Ok(());
    };
    let (Fact::Known(method), Fact::Known(path)) = (asked.method, &asked.path) else {
        return Err(DenyCode::OutsideIntent);
    };
    if envelope.permits_route_action(method, path.as_str(), action) {
        return Ok(());
    }
    Err(DenyCode::OutsideIntent)
}

/// Refuses a path an agent's resource scope does not reach.
fn ensure_within_scope(limits: &AgentLimits, asked: &Asked) -> Result<(), DenyCode> {
    let Restriction::To(scope) = &limits.resource_scope else {
        return Ok(());
    };
    let Fact::Known(path) = &asked.path else {
        return Err(DenyCode::OutsideResourceScope);
    };
    if scope.permits(path) {
        return Ok(());
    }
    Err(DenyCode::OutsideResourceScope)
}
