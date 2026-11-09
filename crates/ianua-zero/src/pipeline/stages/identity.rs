//! The identity group: who a request comes from, how strongly they signed
//! in, the device they sent it from, and the token minted for the upstream.
//!
//! Each stage hands what it read to the application and enforces the
//! answer. Who the caller is comes from `AuthenticateUseCase`, whether
//! their device passes from `CheckDevicePostureUseCase`, the upstream's
//! narrowed token from `ExchangeTokenUseCase`, and whether their sign-in is
//! strong enough from the domain's assurance levels. Nothing
//! here reads a token or decides on its own. Every refusal, every error and
//! every answer that does not fit is a deny.
//!
//! A deny carries a reason code for the audit record, never the credential:
//! the client is told as little as the status says.

mod assurance;
mod credential;

pub(crate) use credential::{held_credential, verified_certificate};
mod exchange;
mod posture;

use std::sync::Arc;
use std::time::Duration;

pub(crate) use credential::IdentityOutcome;
use ianua_app::use_cases::agents::enforcement::RecordStolenBindingUseCase;
use ianua_app::use_cases::authentication::sessions::WatchUseUseCase;
use ianua_app::use_cases::proxy::credentials::AuthenticateUseCase;
use ianua_app::use_cases::proxy::{CheckDevicePostureUseCase, ExchangeTokenUseCase};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::types::DenialStatus;

/// What [`IdentityStages`] is built from.
pub(crate) struct IdentityStagesParts {
    /// Who a request comes from.
    pub authenticate: Arc<AuthenticateUseCase>,
    /// Whether the device a request came from passes.
    pub posture: Arc<CheckDevicePostureUseCase>,
    /// The narrowed token an upstream is handed.
    pub exchange: Arc<ExchangeTokenUseCase>,
    /// Records an agent's key-bound token presented without its key's
    /// proof.
    pub stolen_tokens: Arc<RecordStolenBindingUseCase>,
    /// Holds each session's uses against where it was last used.
    pub watch_session: Arc<WatchUseUseCase>,
    /// The longest that record, or the look at a session, may take. A
    /// request whose look runs out is refused, not waved through.
    pub record_timeout: Duration,
}

/// The stages that establish who a request comes from: `Identity`,
/// `StepUp`, `DevicePosture` and `TokenExchange`.
///
/// The address a `DPoP` proof must name is spelled with the scheme of the
/// listener the request came on, which the handler puts in the request's
/// facts, never read off the connection, which a TLS-ending ingress makes
/// look like plain HTTP.
pub(crate) struct IdentityStages {
    authenticate: Arc<AuthenticateUseCase>,
    posture: Arc<CheckDevicePostureUseCase>,
    exchange: Arc<ExchangeTokenUseCase>,
    stolen_tokens: Arc<RecordStolenBindingUseCase>,
    watch_session: Arc<WatchUseUseCase>,
    record_timeout: Duration,
}

impl IdentityStages {
    /// The group `parts` describes.
    #[must_use]
    pub(crate) fn new(parts: IdentityStagesParts) -> Self {
        Self {
            authenticate: parts.authenticate,
            posture: parts.posture,
            exchange: parts.exchange,
            stolen_tokens: parts.stolen_tokens,
            watch_session: parts.watch_session,
            record_timeout: parts.record_timeout,
        }
    }
}

/// A refusal answered with `status`, recorded as `code`.
fn deny(status: DenialStatus, code: &str) -> StageDecision {
    StageDecision::Deny {
        status,
        reason: code.to_owned(),
    }
}

/// A pass, recorded as `code`.
fn pass(code: &str) -> StageDecision {
    StageDecision::Pass {
        reason: code.to_owned(),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use ianua_app::use_cases::agents::enforcement::RecordStolenBindingPorts;
    use ianua_app::use_cases::authentication::sessions::WatchUsePorts;
    use ianua_app::use_cases::proxy::credentials::AuthenticatePorts;
    use ianua_app::use_cases::proxy::{CheckDevicePosturePorts, ExchangeTokenPorts};

    use super::*;

    /// The parts of a group asking `authenticate`, with fakes for the rest.
    pub(crate) fn parts_with(authenticate: AuthenticatePorts) -> IdentityStagesParts {
        IdentityStagesParts {
            authenticate: Arc::new(AuthenticateUseCase::new(authenticate)),
            posture: Arc::new(CheckDevicePostureUseCase::new(
                CheckDevicePosturePorts::fakes(),
            )),
            exchange: Arc::new(ExchangeTokenUseCase::new(ExchangeTokenPorts::fakes())),
            stolen_tokens: Arc::new(RecordStolenBindingUseCase::new(
                RecordStolenBindingPorts::fakes(),
            )),
            watch_session: Arc::new(WatchUseUseCase::new(WatchUsePorts::fakes())),
            record_timeout: Duration::from_secs(1),
        }
    }

    /// The parts of a group of fakes alone.
    pub(crate) fn parts() -> IdentityStagesParts {
        parts_with(AuthenticatePorts::fakes())
    }
}
