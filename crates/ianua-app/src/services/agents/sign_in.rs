//! An agent signing in as itself at any door it uses: the token exchange,
//! passing a delegation on, asking a person for one, the review desk.
//!
//! Every door refuses the same way, and records the same way a refusal
//! that cannot be the agent's own slip: a replayed or forged assertion, or
//! one naming another agent. Were one door left silent, Mallory would
//! probe the agent's key there, unseen. The record is held back to one a
//! window per agent and kind of attack, saying how many attempts it stands
//! for, so repeating a forgery all day neither floods the trail nor hides
//! an attack on another agent.

use ianua_domain::domains::agents::events::identity::AgentTokenAttackRefused;
use ianua_domain::domains::notifications::alert::ALERT_WINDOW;
use ianua_domain::types::event_type::AgentsEvent;
use ianua_domain::types::{ActorRef, Audience, EventType};

use crate::acting::AgentActors;
use crate::acting::agent::{RefusedSignIn, SignInAttempt, SignedInAgent};
use crate::auditor::RequestAuditor;
use crate::context::AgentAssertion;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{AlertAbout, AlertKey, AlertPlane, AlertThrottle, AlertTurn};
use crate::tenancy::ScopedTenant;

/// One door an agent signs in at: who signs it in, where an attack is held
/// back, the tenant, and the audience its assertion must be made for.
#[derive(Clone, Copy)]
pub(crate) struct AgentDoor<'a> {
    /// Signs the agent in as itself.
    pub(crate) actors: &'a dyn AgentActors,
    /// Holds back records of attacks to one a window per agent and kind.
    pub(crate) attacks: &'a dyn AlertThrottle,
    /// The tenant the request was addressed to.
    pub(crate) tenant: &'a ScopedTenant,
    /// The audience the assertion must name.
    pub(crate) audience: &'a Audience,
}

/// The agent `presented` names, signed in at `door`, a refusal that looks
/// like an attack recorded through `auditor` first.
///
/// # Errors
///
/// - `AppError::Forbidden` when the agent does not sign in, saying no more
///   than which step refused.
/// - `AppError::Internal` on storage failure, or when an attack cannot be
///   recorded: it fails the request rather than going unseen.
pub(crate) async fn signed_in_at(
    door: AgentDoor<'_>,
    auditor: &RequestAuditor,
    presented: &AgentAssertion,
) -> Result<SignedInAgent, AppError> {
    let attempt = door
        .actors
        .attempted(door.tenant, presented, door.audience)
        .await?;
    match attempt {
        SignInAttempt::SignedIn(signed) => Ok(*signed),
        SignInAttempt::Refused(refused) => {
            record_attack(door, auditor, &refused).await?;
            Err(refused.forbidden())
        }
    }
}

/// Records `refused` when it looks like an attack on an agent of the
/// door's tenant, once a window per agent and kind of attack. A refusal
/// that is the agent's own slip, or names no agent the tenant has, records
/// nothing.
///
/// # Errors
///
/// - `AppError::Internal` when the record cannot be written.
async fn record_attack(
    door: AgentDoor<'_>,
    auditor: &RequestAuditor,
    refused: &RefusedSignIn,
) -> Result<(), AppError> {
    let Some((agent, attack)) = refused.attack() else {
        return Ok(());
    };
    let key = AlertKey {
        plane: AlertPlane::Tenant(**door.tenant),
        event_type: EventType::from(AgentsEvent::TokenAttackRefused),
        about: AlertAbout::AgentAttack {
            agent_id: *agent.id(),
            attack,
        },
    };
    let AlertTurn::Raise { since_last } = door.attacks.admit(&key, ALERT_WINDOW).await else {
        return Ok(());
    };
    let attempts = since_last.unwrap_or(1);
    let recorded = AgentTokenAttackRefused::observed(**door.tenant, agent, attack, attempts);
    auditor
        .dispatch_by(&ActorRef::Anonymous, vec![recorded])
        .await
        .or_internal()
}
