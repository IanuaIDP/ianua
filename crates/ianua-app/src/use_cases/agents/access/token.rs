//! The token a dry run reads for each live delegation: what the gateway
//! would see when the agent presents the token minted from it.

use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::proxy::access::question::{Asker, OnBehalf, Records};
use ianua_domain::domains::proxy::request::context::{
    AgentLimits, Caller, CallerClaims, KeyBinding, Metering,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{AgentId, PermissionName};

/// One live delegation, as the gateway would read the token minted from it.
pub(in crate::use_cases::agents::access) struct Token {
    caller: Caller,
    credential: CallerClaims,
    on_behalf: OnBehalf,
}

impl Token {
    /// The token's agent as the decision reads it, with `own` its records.
    pub(in crate::use_cases::agents::access) fn asker<'a>(&'a self, own: &'a Records) -> Asker<'a> {
        Asker::Identified {
            caller: &self.caller,
            credential: &self.credential,
            records: own,
            on_behalf: &self.on_behalf,
        }
    }
}

/// The token the gateway would see for `delegation` to `agent_id`.
pub(in crate::use_cases::agents::access) fn token_of(
    agent_id: AgentId,
    delegation: &Delegation<ResolvedTenant>,
    on_behalf: OnBehalf,
) -> Token {
    let permissions = delegation
        .granted()
        .http()
        .iter()
        .filter_map(|right| PermissionName::new(right.to_string()).ok())
        .collect();
    Token {
        caller: Caller::Agent {
            agent_id,
            delegation_id: *delegation.id(),
            acting_for: *delegation.delegator(),
            limits: Box::new(limits_of(delegation)),
        },
        credential: CallerClaims {
            permissions,
            ..CallerClaims::default()
        },
        on_behalf,
    }
}

/// What a token minted from `delegation` confines its agent to. The key
/// binding is left out: a dry run assumes the agent proves its key.
fn limits_of(delegation: &Delegation<ResolvedTenant>) -> AgentLimits {
    let constraints = delegation.constraints();
    let intent_envelope = match constraints.intent() {
        Restriction::Unrestricted => Restriction::Unrestricted,
        Restriction::To(binding) => Restriction::To(binding.envelope().clone()),
    };
    AgentLimits {
        intent_envelope,
        mcp: delegation.granted().mcp().clone(),
        resource_scope: constraints.resource_scope().clone(),
        max_data_class: constraints.max_data_class(),
        key_binding: KeyBinding::Bearer,
        approval: constraints.approval(),
        metering: Metering::Unmetered,
    }
}
