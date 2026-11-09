//! The operator plane: signing in for a key, other operators' accounts,
//! impersonation grants, and the jobs the platform gave up on. Every call
//! but the sign-in carries the operator's own key as its bearer.

use super::Request;
use crate::net::Call;
use crate::wire::Page;
use crate::wire::operators::{
    DeadJob, GrantImpersonation, GrantMade, NewOperator, OperatorAccount, OperatorKeyMade,
    OperatorMade, OperatorSignIn,
};

/// The header naming the grant a request to a tenant acts through as the
/// grant's user.
pub const IMPERSONATION_HEADER: &str = "ianua-operator-impersonation";

/// `POST /api/v1/operators/sign-in`: an operator's password for a
/// short-lived key of their own.
#[must_use]
pub fn sign_in(sign_in: &OperatorSignIn) -> Request<OperatorKeyMade> {
    Request::of(Call::post("/api/v1/operators/sign-in").json(sign_in))
}

/// `GET /api/v1/operators`: the operators, a page at a time.
#[must_use]
pub fn list() -> Request<Page<OperatorAccount>> {
    Request::of(Call::get("/api/v1/operators"))
}

/// `POST /api/v1/operators`: an operator makes another operator's
/// account, active at once.
#[must_use]
pub fn create(operator: &NewOperator) -> Request<OperatorMade> {
    Request::of(Call::post("/api/v1/operators").json(operator))
}

/// `GET /api/v1/operators/dead-jobs`: the jobs that used up their tries,
/// newest first, without their payloads.
#[must_use]
pub fn dead_jobs() -> Request<Page<DeadJob>> {
    Request::of(Call::get("/api/v1/operators/dead-jobs"))
}

/// `POST /api/v1/operators/dead-jobs/{id}/retry`: gives a dead job one
/// more attempt, due at once.
#[must_use]
pub fn retry_dead_job(job_id: &str) -> Request<()> {
    Request::of(Call::post(format!(
        "/api/v1/operators/dead-jobs/{job_id}/retry"
    )))
}

/// `GET /api/v1/operators/{id}`: an operator's account.
#[must_use]
pub fn get(operator_id: &str) -> Request<OperatorAccount> {
    Request::of(Call::get(format!("/api/v1/operators/{operator_id}")))
}

/// `POST /api/v1/operators/{id}/disable`: disables another operator.
#[must_use]
pub fn disable(operator_id: &str) -> Request<()> {
    Request::of(Call::post(format!(
        "/api/v1/operators/{operator_id}/disable"
    )))
}

/// `POST /api/v1/operators/{id}/grants`: the calling operator, `id` their
/// own, asks to act as a tenant user.
#[must_use]
pub fn grant(operator_id: &str, grant: &GrantImpersonation) -> Request<GrantMade> {
    Request::of(Call::post(format!("/api/v1/operators/{operator_id}/grants")).json(grant))
}

/// `DELETE /api/v1/operators/grants/{id}`: the operator ends their grant.
#[must_use]
pub fn revoke_grant(grant_id: &str) -> Request<()> {
    Request::of(Call::delete(format!("/api/v1/operators/grants/{grant_id}")))
}
