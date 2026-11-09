//! The tenant's own access policy, read last: whether it refuses the
//! request, lets it through, or asks for a stronger sign-in or a `DPoP`
//! proof first.

use crate::domains::authorization::permission::CustomPermission;
use crate::domains::authorization::policy::claims::Claim;
use crate::domains::authorization::policy::simulator::{
    AuditMark, PolicyDecision, RequestFacts, StepUp, evaluate,
};
use crate::domains::proxy::access::assurance::ensure_assurance;
use crate::domains::proxy::access::decision::{
    AccessDecision, Challenge, DenyCode, Outcome, SettledBy, TenantRuling,
};
use crate::domains::proxy::access::question::{AccessQuestion, Asker, DpopBinding, Lookup};
use crate::domains::proxy::access::requester::Requester;
use crate::types::{Fact, HttpMethod};

/// The decision once the tenant's policy has had its say.
///
/// A tenant with no live policy leaves the route's decision standing. A
/// policy that could not be read refuses: what it would have said is not
/// known, so nothing is let through on a guess.
pub(super) fn ruled(question: &AccessQuestion<'_>, requester: &Requester<'_>) -> AccessDecision {
    let policy = match question.tenant_policy {
        Lookup::Found(policy) => policy,
        Lookup::Missing => return AccessDecision::new(Outcome::Permit, TenantRuling::NoPolicy),
        Lookup::Unreadable => {
            return AccessDecision::new(
                Outcome::Deny(DenyCode::TenantPolicyUnreadable),
                TenantRuling::Unreadable,
            );
        }
    };
    let custom = requester.custom_permissions();
    let result = evaluate(policy, &request_facts(question, requester, &custom));
    let ruling = TenantRuling::Decided {
        version: result.policy_version(),
        settled_by: result
            .matched_rule()
            .cloned()
            .map_or(SettledBy::Default, SettledBy::Rule),
        audit: AuditMark::from(result.audited()),
    };
    let outcome =
        match ensure_decision(result.decision(), requester, question.circumstances.binding) {
            Ok(()) => Outcome::Permit,
            Err(outcome) => outcome,
        };
    AccessDecision::new(outcome, ruling)
}

/// The request as the tenant's policy reads it.
///
/// What the caller holds comes from the records; an agent's app
/// permissions from its token, as far as its authority still holds them.
/// The claims are those the credential asserts. A credential of a kind that
/// carries none leaves them unknown, so a refusing rule on one matches and
/// an allowing rule does not; nobody signed in asserts none.
fn request_facts<'q>(
    question: &AccessQuestion<'q>,
    requester: &Requester<'q>,
    custom: &'q [CustomPermission],
) -> RequestFacts<'q> {
    let asked = question.asked;
    let around = question.circumstances;
    RequestFacts {
        path: asked.path.as_ref(),
        method: asked.method.as_ref().map(HttpMethod::as_str),
        roles: requester.roles(),
        country: around.country.as_ref(),
        device: around.device,
        risk: around.risk,
        sensitive_operation: around.sensitivity,
        groups: Fact::Known(requester.groups()),
        permissions: Fact::Known(custom),
        claims: asserted_by(question.asker),
        source_ip: around.source_ip,
        local_times: question.local_times,
        host: asked.host.as_ref(),
    }
}

/// The claims `asker`'s credential asserts: none for nobody, unknown for a
/// credential that carries none.
fn asserted_by<'q>(asker: Asker<'q>) -> Fact<&'q [Claim]> {
    let Asker::Identified { credential, .. } = asker else {
        return Fact::Known(&[]);
    };
    credential.asserted.as_ref().map(Vec::as_slice)
}

/// Lets through what the policy allows, once the caller shows what the
/// matched rules asked for.
///
/// # Errors
///
/// - [`Outcome::Deny`] with [`DenyCode::TenantRule`] for a request the
///   policy refuses.
/// - The refusals and challenges `ensure_assurance` and [`ensure_proof`]
///   give.
fn ensure_decision(
    decision: &PolicyDecision,
    requester: &Requester<'_>,
    binding: DpopBinding,
) -> Result<(), Outcome> {
    let PolicyDecision::Allow { step_up } = decision else {
        return Err(Outcome::Deny(DenyCode::TenantRule));
    };
    ensure_assurance(step_up.required_aal(), requester.sign_in_strength())?;
    ensure_proof(step_up, binding)
}

/// Asks for a `DPoP` proof when a rule asked for one and the request proved
/// no key.
///
/// # Errors
///
/// - [`Outcome::Challenge`] with [`Challenge::DpopProof`] for a request
///   without a verified proof.
fn ensure_proof(step_up: &StepUp, binding: DpopBinding) -> Result<(), Outcome> {
    if !step_up.requires_dpop() || binding == DpopBinding::Bound {
        return Ok(());
    }
    Err(Outcome::Challenge(Challenge::DpopProof))
}
