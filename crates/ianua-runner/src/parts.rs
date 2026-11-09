//! The runner built from its configuration: the key it signs with, the
//! tokens it holds, the proofs it makes, the use cases over them, and the
//! client its requests leave through. Nothing is built anywhere else.

use std::sync::Arc;

use ianua_app::ports::agents::RunnerKeys;
use ianua_app::use_cases::agents::runner::{
    CredentialPorts, CredentialUseCase, ForgetPorts, ForgetUseCase,
};
use ianua_domain::shared::errors::DomainError;
use ianua_infra::http::{HttpRunnerKeys, HttpRunnerTokens};
use ianua_infra::proofs::{JwsRunnerProofs, MountedRunnerKeys};

use crate::config::{Config, Identity};
use crate::error::RunnerError;
use crate::handler::{Destinations, RequestLimits, Runner, RunnerUseCases};
use crate::outbound::{InternalAuthority, Outbounds, Trust, outbound};

/// The runner `config` describes.
///
/// # Errors
///
/// [`RunnerError::Build`] naming the part that could not be built: a
/// mounted key that does not read, or a client that cannot be made.
pub(crate) fn runner(config: &Config) -> Result<Runner, RunnerError> {
    let use_cases = use_cases(config)?;
    let destinations = Destinations {
        gateway_url: config.gateway_url.clone(),
        gateway: config.gateway.clone(),
        agents_url: config.agent.agents_url.clone(),
    };
    let limits = RequestLimits {
        timeout: config.limits.request,
        in_flight: config.limits.in_flight,
    };
    Ok(Runner::new(
        use_cases,
        outbounds(config)?,
        destinations,
        limits,
    ))
}

/// Connects credential lookup and token removal to the same token cache.
fn use_cases(config: &Config) -> Result<RunnerUseCases, RunnerError> {
    let keys = keys(config)?;
    let tokens = Arc::new(
        HttpRunnerTokens::new(config.agent.clone(), config.ask.clone(), config.limits.call)
            .map_err(RunnerError::of("the token exchange"))?,
    );
    Ok(RunnerUseCases {
        credential: CredentialUseCase::new(
            CredentialPorts {
                keys,
                tokens: tokens.clone(),
                proofs: Arc::new(JwsRunnerProofs),
            },
            config.gateway.clone(),
        ),
        forget: ForgetUseCase::new(ForgetPorts { tokens }),
    })
}

/// The clients to the gateway, trusting its authority when one is named,
/// and to the platform's API, trusting the public roots.
fn outbounds(config: &Config) -> Result<Outbounds, RunnerError> {
    let gateway_trust = match &config.gateway_authority {
        Some(authority) => Trust::Only(InternalAuthority {
            certificate: std::fs::read_to_string(&authority.file)
                .map_err(DomainError::infra)
                .map_err(RunnerError::of("the gateway's authority"))?,
            name: authority.name.as_ref().map(|name| name.as_str().to_owned()),
        }),
        None => Trust::Public,
    };
    let idle = config.limits.request;
    Ok(Outbounds {
        gateway: outbound(idle, &gateway_trust).map_err(RunnerError::of("the gateway's client"))?,
        platform: outbound(idle, &Trust::Public).map_err(RunnerError::of("the API's client"))?,
    })
}

/// The key the runner signs with: attested, or mounted.
fn keys(config: &Config) -> Result<Arc<dyn RunnerKeys>, RunnerError> {
    match &config.identity {
        Identity::Spiffe(svid) => Ok(Arc::new(
            HttpRunnerKeys::new(config.agent.clone(), svid.clone(), config.limits.call)
                .map_err(RunnerError::of("the attestation"))?,
        )),
        Identity::Mounted {
            kid,
            algorithm,
            key,
        } => Ok(Arc::new(
            MountedRunnerKeys::new(kid.clone(), *algorithm, key.clone())
                .map_err(RunnerError::of("the mounted key"))?,
        )),
    }
}
