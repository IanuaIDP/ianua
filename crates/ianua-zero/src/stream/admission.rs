//! Asking the application who is on a connection, and whether it may be
//! spliced.
//!
//! The gateway hands over what the wire showed, the credential and the
//! name the handshake asked for, on the route the connection arrived on.
//! [`IdentifyStreamCallerUseCase`] names the caller and
//! [`AdmitStreamConnectionUseCase`] answers. Only an explicit admission
//! opens the gate. A refusal, a route the tenant does not have, an error
//! and an answer that comes too late all close it.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::error::AppError;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query;
use ianua_app::use_cases::proxy::credentials::Refusal;
use ianua_app::use_cases::routing::stream_routes::{
    AdmitStreamConnectionUseCase, IdentifiedStreamCaller, IdentifyStreamCallerUseCase,
    StreamAdmission, StreamCallerEvidence, StreamCallerRefusal, StreamConnection, StreamRefusal,
};
use ianua_domain::types::TenantId;

/// The longest the gateway waits for an answer before closing the
/// connection.
///
/// The use cases read the route and may check a token or ask the policy
/// decision point, which holds itself to two seconds. A store that hangs
/// must not hold an accepted socket and its permit.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);

/// Whether a connection may go through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// Splice it.
    Open,
    /// Close it, for this reason.
    Closed(Shut),
}

/// Why a connection was closed before a byte of it was forwarded.
///
/// Each is a distinct cause for the record, never told to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shut {
    /// The application refused it.
    Refused(StreamRefusal),
    /// Its credential named no one.
    NotNamed(StreamCallerRefusal),
    /// The tenant has no such route any more.
    RouteUnknown,
    /// The application could not decide.
    Undecided,
    /// The application did not answer in time.
    Late,
    /// The TLS handshake was refused, for this reason.
    Handshake(&'static str),
    /// The tunnel was not opened with a `CONNECT` the gateway could read.
    NoTunnelRequest,
    /// The tunnel's `CONNECT` carried no token.
    NoToken,
}

impl Shut {
    /// A short, stable reason for the record.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Refused(StreamRefusal::RouteClosed) => "route_closed",
            Self::Refused(StreamRefusal::ServerNameNotMatched) => "server_name_not_matched",
            Self::Refused(StreamRefusal::NotLetIn) => "not_let_in",
            Self::Refused(StreamRefusal::PolicyDenied) => "policy_denied",
            Self::Refused(StreamRefusal::NoDecision) => "no_decision",
            Self::NotNamed(StreamCallerRefusal::Credential(refusal)) => refusal_reason(refusal),
            Self::NotNamed(StreamCallerRefusal::Agent) => "agent_not_served",
            Self::NotNamed(StreamCallerRefusal::RouteUnknown) | Self::RouteUnknown => {
                "route_unknown"
            }
            Self::NotNamed(StreamCallerRefusal::Unavailable) | Self::Undecided => "undecided",
            Self::Late => "admission_timed_out",
            Self::Handshake(reason) => reason,
            Self::NoTunnelRequest => "no_tunnel_request",
            Self::NoToken => "credential_missing",
        }
    }
}

/// The reason a refused credential is recorded under.
fn refusal_reason(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Missing => "credential_missing",
        Refusal::Invalid => "credential_invalid",
        Refusal::Expired => "credential_expired",
        Refusal::WrongIssuer => "credential_wrong_issuer",
        Refusal::WrongAudience => "credential_wrong_audience",
        Refusal::WrongHost => "credential_wrong_host",
        Refusal::UnknownSubject => "unknown_subject",
        Refusal::Inactive => "subject_inactive",
        Refusal::Revoked => "credential_revoked",
        Refusal::CrossSite => "cross_site",
        Refusal::DpopMismatch(_) => "dpop_mismatch",
        Refusal::QuotaSpent => "quota_spent",
        Refusal::Unavailable => "undecided",
    }
}

/// The application's answers, held to a deadline.
pub(super) struct Admission {
    admit: Arc<AdmitStreamConnectionUseCase>,
    identify: Arc<IdentifyStreamCallerUseCase>,
}

impl Admission {
    /// Admission through `admit`, callers named through `identify`.
    pub(super) fn new(
        admit: Arc<AdmitStreamConnectionUseCase>,
        identify: Arc<IdentifyStreamCallerUseCase>,
    ) -> Self {
        Self { admit, identify }
    }

    /// Whether `connection`, on a port of `tenant`, may be spliced through.
    ///
    /// The tenant is the one the directory published for the port the
    /// connection arrived on, never anything the client sent.
    pub(super) async fn admits(&self, tenant: TenantId, connection: StreamConnection) -> Gate {
        let scoped = ScopedTenant::from_listening_port(tenant);
        let answer = tokio::time::timeout(ANSWER_TIMEOUT, self.admit.execute(&scoped, connection))
            .await
            .ok();
        gate_after(answer)
    }

    /// Who `evidence`'s credential names on a port of `tenant`.
    ///
    /// # Errors
    ///
    /// - [`Shut::NotNamed`] when the application named no one.
    /// - [`Shut::Late`] when it did not answer in time.
    pub(super) async fn identifies(
        &self,
        tenant: TenantId,
        evidence: StreamCallerEvidence,
    ) -> Result<IdentifiedStreamCaller, Shut> {
        let scoped = ScopedTenant::from_listening_port(tenant);
        tokio::time::timeout(ANSWER_TIMEOUT, self.identify.execute(&scoped, evidence))
            .await
            .map_err(|_| Shut::Late)?
            .map_err(Shut::NotNamed)
    }
}

/// The gate an answer comes to; `None` is an answer that never came.
fn gate_after(answer: Option<Result<StreamAdmission, AppError>>) -> Gate {
    let Some(answered) = answer else {
        return Gate::Closed(Shut::Late);
    };
    match answered {
        Ok(StreamAdmission::Admitted) => Gate::Open,
        Ok(StreamAdmission::Refused(refusal)) => Gate::Closed(Shut::Refused(refusal)),
        Err(AppError::NotFound(_)) => Gate::Closed(Shut::RouteUnknown),
        Err(error) => {
            tracing::warn!(%error, "a stream connection could not be decided");
            Gate::Closed(Shut::Undecided)
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::errors::DomainError;

    use super::*;

    #[test]
    fn only_an_admission_opens_the_gate() {
        assert_eq!(gate_after(Some(Ok(StreamAdmission::Admitted))), Gate::Open);
    }

    #[test]
    fn a_refusal_closes_the_gate_with_its_reason() {
        let refused = StreamAdmission::Refused(StreamRefusal::PolicyDenied);

        assert_eq!(
            gate_after(Some(Ok(refused))),
            Gate::Closed(Shut::Refused(StreamRefusal::PolicyDenied))
        );
    }

    #[test]
    fn a_failing_store_closes_the_gate() {
        let failed = AppError::Domain(DomainError::infra_msg("the store is unreachable"));

        assert_eq!(gate_after(Some(Err(failed))), Gate::Closed(Shut::Undecided));
    }

    #[test]
    fn a_route_the_tenant_no_longer_has_closes_the_gate() {
        let missing = AppError::NotFound("stream route".to_owned().into());

        assert_eq!(
            gate_after(Some(Err(missing))),
            Gate::Closed(Shut::RouteUnknown)
        );
    }

    #[test]
    fn an_answer_that_never_came_closes_the_gate() {
        assert_eq!(gate_after(None), Gate::Closed(Shut::Late));
    }

    /// A refused credential is recorded by what was wrong with it, never by
    /// anything it carried.
    #[test]
    fn a_refused_credential_is_recorded_by_its_kind() {
        let expired = Shut::NotNamed(StreamCallerRefusal::Credential(Refusal::Expired));

        assert_eq!(expired.as_str(), "credential_expired");
        assert_eq!(
            Shut::NotNamed(StreamCallerRefusal::Agent).as_str(),
            "agent_not_served"
        );
    }
}
