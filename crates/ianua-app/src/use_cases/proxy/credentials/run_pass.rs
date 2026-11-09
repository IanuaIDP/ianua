//! A workflow run's pass: one call of a Protected apps or Protected data
//! step, acting as the person its run acts for, on the one route or stream
//! route the pass names.
//!
//! The pass is taken only where its tenant opened to workflows, and only
//! on what it was made for. The person must still be able to
//! sign in, and is held to what they hold now, like a token of theirs. The
//! person is not there, so the pass proves nothing of how strongly they
//! signed in: a route asking for more refuses it.

use ianua_domain::domains::proxy::access::question::DpopBinding;
use ianua_domain::domains::proxy::request::context::{Caller, RouteRequirements, UserSignIn};
use ianua_domain::domains::routing::route::WorkflowUse;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, PrincipalRef};

use crate::ports::authentication::PassReach;
use crate::use_cases::proxy::credentials::checking::Checking;
use crate::use_cases::proxy::credentials::held::{claims_of, held_by};
use crate::use_cases::proxy::credentials::outcome::{Identification, Refusal, proven, read};
use crate::use_cases::proxy::credentials::person::{PersonPorts, ensure_may_sign_in};

/// The person a run pass acts as, on the route it was made for.
///
/// # Errors
///
/// - [`Refusal::WrongAudience`] when the route is not open to workflows,
///   or the pass was made for another route.
/// - The reader's refusals, as [`Refusal`] maps them, and
///   [`Refusal::WrongIssuer`] while the route holds tokens to no issuer.
/// - [`Refusal::UnknownSubject`] or [`Refusal::Inactive`] when the person
///   is not there or may no longer sign in.
/// - [`Refusal::Unavailable`] when a check fails.
pub(crate) async fn by_run_pass(
    ports: &PersonPorts,
    checking: &Checking<'_>,
    token: &Secret,
) -> Result<Identification, Refusal> {
    ensure_open_to_workflows(checking.route)?;
    let reading = checking
        .tokens
        .read_run_pass(checking.tenant, token, checking.issuer()?)
        .await
        .map_err(Refusal::unavailable)?;
    let pass = read(reading)?;
    ensure_made_for(checking.route, pass.reaches)?;
    ensure_may_sign_in(ports, checking.tenant, &pass.user_id).await?;
    let held = held_by(
        checking.records,
        checking.tenant,
        PrincipalRef::User(pass.user_id),
    )
    .await?;
    let claims = claims_of(&held);
    let caller = Caller::User {
        user_id: pass.user_id,
        sign_in: UserSignIn::WorkflowRun(pass.call_id),
    };
    Ok(proven(
        caller,
        Expiry::At(pass.expires_at),
        held,
        claims,
        DpopBinding::Unbound,
    ))
}

/// Refuses a pass on a route its tenant has not opened to workflows.
///
/// # Errors
///
/// - [`Refusal::WrongAudience`] while the route is closed to them.
fn ensure_open_to_workflows(route: &RouteRequirements) -> Result<(), Refusal> {
    match route.workflow_use {
        WorkflowUse::Open => Ok(()),
        WorkflowUse::Closed => Err(Refusal::WrongAudience),
    }
}

/// Refuses a pass made for anything but what was reached: the route a
/// request matched, or the stream route a connection reached. A pass for a
/// route opens no stream route and one for a stream route opens no route,
/// since the other is never known.
///
/// # Errors
///
/// - [`Refusal::WrongAudience`] when they differ or the one reached is
///   unknown.
fn ensure_made_for(route: &RouteRequirements, made_for: PassReach) -> Result<(), Refusal> {
    let reached = match made_for {
        PassReach::Route(made_for) => route.route_id.known() == Some(&made_for),
        PassReach::StreamRoute(made_for) => route.stream_route_id.known() == Some(&made_for),
    };
    match reached {
        true => Ok(()),
        false => Err(Refusal::WrongAudience),
    }
}
