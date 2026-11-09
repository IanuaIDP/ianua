//! The gateway's listeners inside the deployment's own network: the
//! workflow listener the worker's Protected apps steps call, and the
//! runner listener agents' runners send through.
//!
//! Each serves TLS with a certificate of the internal authority
//! `ianua internal-pki` issues, so a pass or token sent to it cannot be
//! read on the network. The workflow listener serves mutual TLS: only
//! clients whose certificate chains to that authority get to send
//! anything. The runner listener asks no client certificate, since a
//! runner holds none of the authority's and every request it sends
//! carries a proof made with its agent's own key. Plain HTTP is taken
//! only outside production, and only with no certificate set at all.

use std::net::SocketAddr;
use std::path::PathBuf;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::network::PemFiles;

/// One listener inside the deployment's network, and how it protects its
/// connections.
#[derive(Debug, Clone)]
pub(crate) struct InternalListen {
    /// Where it listens.
    pub address: SocketAddr,
    /// How it protects its connections.
    pub transport: InternalTransport,
}

/// How an internal listener protects its connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InternalTransport {
    /// Mutual TLS: it serves `certificate`, and takes only clients whose
    /// certificate chains to `authority`.
    Mutual {
        /// The internal authority's certificate, the only one a client's
        /// certificate may chain to.
        authority: PathBuf,
        /// The certificate it serves, and its key.
        certificate: PemFiles,
    },
    /// TLS asking no client certificate: it serves `certificate`.
    Tls {
        /// The certificate it serves, and its key.
        certificate: PemFiles,
    },
    /// Plain HTTP, outside production, with no certificate set.
    PlainInDevelopment,
}

/// Whose certificates an internal listener's clients present.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Clients {
    /// A certificate chaining to the authority the setting names.
    Certified {
        /// The setting naming the authority's certificate, such as
        /// `GATEWAY_WORKFLOW_CA_FILE`.
        authority: &'static str,
    },
    /// None: each request carries its own proof.
    Uncertified,
}

/// The settings one internal listener is read from.
pub(crate) struct InternalSettings {
    /// Its address, such as `GATEWAY_WORKFLOW_LISTEN`.
    pub(crate) listen: &'static str,
    /// Whose certificates its clients present.
    pub(crate) clients: Clients,
    /// The certificate it serves.
    pub(crate) certificate: &'static str,
    /// The environment variable naming the private-key file paired with the listener certificate.
    pub(crate) key: &'static str,
}

/// The internal listener `settings` names, in `environment`, or `None`
/// when it is not set.
///
/// # Errors
///
/// - [`ConfigError::Contradicts`] when a certificate is set without the
///   listener, or the listener is set without certificates in production.
/// - [`ConfigError::Missing`] when only part of the certificates is set.
pub(crate) fn internal_listen(
    vars: &Env,
    environment: Environment,
    settings: &InternalSettings,
) -> Read<Option<InternalListen>> {
    let address = vars.parsed(settings.listen, |text| text.parse::<SocketAddr>())?;
    let authority = match settings.clients {
        Clients::Certified { authority } => vars.path(authority)?,
        Clients::Uncertified => None,
    };
    let certificate = vars.pem_files(settings.certificate, settings.key)?;
    let Some(address) = address else {
        return without_listener(settings, authority.is_some() || certificate.is_some());
    };
    let transport = match (settings.clients, authority, certificate) {
        (Clients::Certified { .. }, Some(authority), Some(certificate)) => {
            InternalTransport::Mutual {
                authority,
                certificate,
            }
        }
        (Clients::Uncertified, None, Some(certificate)) => InternalTransport::Tls { certificate },
        (_, None, None) => plain(settings, environment)?,
        _ => return Err(ConfigError::missing(&needed(settings))),
    };
    Ok(Some(InternalListen { address, transport }))
}

/// The settings TLS on the listener needs together, for a refusal.
fn needed(settings: &InternalSettings) -> String {
    match settings.clients {
        Clients::Certified { authority } => format!(
            "{authority}, {} and {}, which mutual TLS on {} needs together,",
            settings.certificate, settings.key, settings.listen
        ),
        Clients::Uncertified => format!(
            "{} and {}, which TLS on {} needs together,",
            settings.certificate, settings.key, settings.listen
        ),
    }
}

/// Plain HTTP, refused in production.
fn plain(settings: &InternalSettings, environment: Environment) -> Read<InternalTransport> {
    if environment.is_production() {
        return Err(ConfigError::contradicts(
            settings.listen,
            format!(
                "is set without {} in production, where every internal listener serves TLS",
                settings.certificate
            ),
        ));
    }
    Ok(InternalTransport::PlainInDevelopment)
}

/// No listener, refused when a certificate meant for one is set: a
/// listener meant to be protected and silently not opened leaves its
/// callers failing with nothing said why.
fn without_listener(
    settings: &InternalSettings,
    certificate_set: bool,
) -> Read<Option<InternalListen>> {
    if certificate_set {
        return Err(ConfigError::contradicts(
            settings.certificate,
            format!(
                "or the listener's authority is set without {}",
                settings.listen
            ),
        ));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use ianua_boot::environment::Environment::{Development, Production};

    use super::*;

    const WORKFLOW: InternalSettings = InternalSettings {
        listen: "GATEWAY_WORKFLOW_LISTEN",
        clients: Clients::Certified {
            authority: "GATEWAY_WORKFLOW_CA_FILE",
        },
        certificate: "GATEWAY_WORKFLOW_TLS_CERT_FILE",
        key: "GATEWAY_WORKFLOW_TLS_KEY_FILE",
    };

    const RUNNER: InternalSettings = InternalSettings {
        listen: "GATEWAY_RUNNER_LISTEN",
        clients: Clients::Uncertified,
        certificate: "GATEWAY_RUNNER_TLS_CERT_FILE",
        key: "GATEWAY_RUNNER_TLS_KEY_FILE",
    };

    fn read(pairs: &[(&str, &str)], environment: Environment) -> Read<Option<InternalListen>> {
        internal_listen(&Env::of(pairs.iter().copied()), environment, &WORKFLOW)
    }

    fn runner(pairs: &[(&str, &str)], environment: Environment) -> Read<Option<InternalListen>> {
        internal_listen(&Env::of(pairs.iter().copied()), environment, &RUNNER)
    }

    /// The workflow listener with its authority, certificate and key serves
    /// mutual TLS.
    #[test]
    fn a_listener_with_its_certificates_serves_mutual_tls() {
        let listen = read(
            &[
                ("GATEWAY_WORKFLOW_LISTEN", "10.0.0.4:8082"),
                ("GATEWAY_WORKFLOW_CA_FILE", "/etc/ianua/link/ca.crt"),
                ("GATEWAY_WORKFLOW_TLS_CERT_FILE", "/etc/ianua/link/tls.crt"),
                ("GATEWAY_WORKFLOW_TLS_KEY_FILE", "/etc/ianua/link/tls.key"),
            ],
            Production,
        )
        .unwrap()
        .unwrap();

        assert!(matches!(listen.transport, InternalTransport::Mutual { .. }));
    }

    /// The runner listener with its certificate and key serves TLS asking
    /// no client certificate, in production too.
    #[test]
    fn the_runner_listener_with_its_certificate_serves_tls() {
        let listen = runner(
            &[
                ("GATEWAY_RUNNER_LISTEN", "10.0.0.4:8082"),
                (
                    "GATEWAY_RUNNER_TLS_CERT_FILE",
                    "/etc/ianua/internal/tls.crt",
                ),
                ("GATEWAY_RUNNER_TLS_KEY_FILE", "/etc/ianua/internal/tls.key"),
            ],
            Production,
        )
        .unwrap()
        .unwrap();

        assert!(matches!(listen.transport, InternalTransport::Tls { .. }));
    }

    /// Workflow and runner listeners without certificates are rejected in
    /// production; the workflow listener accepts plain HTTP in development.
    #[test]
    fn a_listener_without_certificates_is_refused_in_production() {
        let workflow = [("GATEWAY_WORKFLOW_LISTEN", "10.0.0.4:8082")];
        let runners = [("GATEWAY_RUNNER_LISTEN", "10.0.0.4:8083")];

        let production = read(&workflow, Production);
        let runner_in_production = runner(&runners, Production);
        let development = read(&workflow, Development).unwrap().unwrap();

        assert!(
            matches!(production, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_WORKFLOW_LISTEN")
        );
        assert!(
            matches!(runner_in_production, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_RUNNER_LISTEN")
        );
        assert_eq!(development.transport, InternalTransport::PlainInDevelopment);
    }

    /// Workflow TLS without its client authority reports missing configuration,
    /// while an authority without a listener reports contradictory settings.
    #[test]
    fn half_set_certificates_are_refused() {
        let no_authority = read(
            &[
                ("GATEWAY_WORKFLOW_LISTEN", "10.0.0.4:8082"),
                ("GATEWAY_WORKFLOW_TLS_CERT_FILE", "/etc/ianua/link/tls.crt"),
                ("GATEWAY_WORKFLOW_TLS_KEY_FILE", "/etc/ianua/link/tls.key"),
            ],
            Development,
        );
        let no_listener = read(
            &[("GATEWAY_WORKFLOW_CA_FILE", "/etc/ianua/link/ca.crt")],
            Development,
        );

        assert!(matches!(no_authority, Err(ConfigError::Missing { .. })));
        assert!(matches!(no_listener, Err(ConfigError::Contradicts { .. })));
    }
}
