//! The LDAP directory: started beside the API when `LDAP_BIND_ADDR` is set,
//! asking the same use cases the API is built from, and stopped with
//! everything else.

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_api::state::Deps;
use ianua_boot::shutdown::Shutdown;
use ianua_ldap::tls::reload_on_hangup;
use ianua_ldap::{
    GroupWrites, LdapConfig, LdapLimits, LdapPorts, LdapServer, LdapTls, Targets, UserWrites,
};

use crate::config::Config;
use crate::config::serving::DirectoryConfig;
use crate::config::serving::ldap::DirectoryTransport;
use crate::error::{PlatformError, ServerError};
use crate::platform::Platform;

/// Starts the LDAP directory when the configuration names where it
/// listens, its use cases built from `deps` as the API's are, and returns
/// where it listens once it does. A stop lets each connection finish the
/// operation in hand; a `SIGHUP` reloads its TLS certificate. Does nothing
/// and answers `None` when `LDAP_BIND_ADDR` is unset.
///
/// # Errors
///
/// [`ServerError::Platform`] when the address cannot be taken or the TLS
/// files do not read.
pub async fn run(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
    deps: &Deps,
) -> Result<Option<SocketAddr>, ServerError> {
    let Some(settings) = settings(&config.directory) else {
        return Ok(None);
    };
    warn_of_plain_connections(&config.directory);
    let server = LdapServer::open(settings, ports(platform, deps))
        .await
        .map_err(PlatformError::of("the LDAP directory"))?;
    let address = server
        .local_addr()
        .map_err(PlatformError::of("the LDAP directory"))?;
    tracing::info!(%address, tls = server.acceptor().is_some(), "the LDAP directory listens");
    if let Some(acceptor) = server.acceptor() {
        shutdown.spawn_until_stopped(reload_on_hangup(acceptor, shutdown.stopping()));
    }
    shutdown.spawn("the LDAP directory", server.serve(shutdown.stopping()));
    Ok(Some(address))
}

/// Logs, at start, a directory taking plain connections and why it may.
fn warn_of_plain_connections(directory: &DirectoryConfig) {
    let Some(listener) = &directory.listener else {
        return;
    };
    match listener.transport {
        DirectoryTransport::Tls(_) => {}
        DirectoryTransport::EndedUpstream => tracing::warn!(
            "the LDAP directory takes plain connections: LDAP_TLS_TERMINATED_UPSTREAM says TLS \
             is ended in front of it; no client certificate reaches it, so no person can bind"
        ),
        DirectoryTransport::PlainInDevelopment => tracing::warn!(
            "the LDAP directory takes plain connections, which only development allows; \
             passwords and secrets cross the wire in the clear"
        ),
    }
}

/// What the LDAP server runs with, when the directory listens.
fn settings(directory: &DirectoryConfig) -> Option<LdapConfig> {
    let listener = directory.listener.as_ref()?;
    let tls = match &listener.transport {
        DirectoryTransport::Tls(files) => Some(LdapTls {
            certificate: files.certificate.clone(),
            key: files.key.clone(),
            client_ca: directory
                .client_ca
                .as_ref()
                .map(|ca| ca.certificate.clone()),
        }),
        DirectoryTransport::EndedUpstream | DirectoryTransport::PlainInDevelopment => None,
    };
    Some(LdapConfig {
        listen: listener.address,
        tls,
        limits: LdapLimits {
            max_connections: directory.max_connections,
            idle_timeout: directory.idle_timeout,
            handshake_timeout: directory.handshake_timeout,
            binds_per_ip_per_minute: directory.binds_per_ip_per_minute,
        },
    })
}

/// The LDAP server's ports: the directory use cases over `deps`, and the
/// platform's dispatcher for every record.
fn ports(platform: &Platform, deps: &Deps) -> LdapPorts {
    let use_cases = ianua_assembly::ldap(&deps.adapters, &deps.settings);
    LdapPorts {
        bind: use_cases.bind,
        service_bind: use_cases.service_bind,
        search: use_cases.search,
        service_search: use_cases.service_search,
        users: UserWrites {
            add: use_cases.users.add,
            rename: use_cases.users.rename,
            change_email: use_cases.users.change_email,
            remove: use_cases.users.remove,
            change_password: use_cases.users.change_password,
        },
        groups: GroupWrites {
            add: use_cases.groups.add,
            rename: use_cases.groups.rename,
            remove: use_cases.groups.remove,
            add_member: use_cases.groups.add_member,
            remove_member: use_cases.groups.remove_member,
        },
        targets: Targets {
            users: use_cases.user_store,
            groups: use_cases.group_store,
        },
        events: Arc::clone(&platform.event_dispatcher),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ianua_boot::env::Env;
    use ianua_boot::environment::Environment::{Development, Production};

    use super::*;

    /// Behind something that ends TLS, the directory serves no certificate,
    /// so it checks no client certificate either.
    #[test]
    fn tls_ended_upstream_serves_no_certificate() {
        let vars = Env::of([
            ("LDAP_BIND_ADDR", "0.0.0.0:389"),
            ("LDAP_TLS_TERMINATED_UPSTREAM", "true"),
            ("LDAP_CLIENT_CA_CERT_PATH", "/run/pki/clients.crt"),
            ("LDAP_CLIENT_CA_KEY_PATH", "/run/pki/clients.key"),
        ]);

        let ldap = settings(&DirectoryConfig::read(&vars, Production).unwrap()).unwrap();

        assert!(ldap.tls.is_none());
    }

    /// With no listen address, no directory starts.
    #[test]
    fn without_a_listen_address_no_directory_starts() {
        let directory = DirectoryConfig::read(&Env::of([]), Production).unwrap();

        assert!(settings(&directory).is_none());
    }

    /// The directory serves its certificate and checks client certificates
    /// against the authority they are issued from.
    #[test]
    fn the_directory_checks_clients_against_the_issuing_authority() {
        let vars = Env::of([
            ("LDAP_BIND_ADDR", "0.0.0.0:636"),
            ("LDAP_TLS_CERT_PATH", "/run/pki/ldap.crt"),
            ("LDAP_TLS_KEY_PATH", "/run/pki/ldap.key"),
            ("LDAP_CLIENT_CA_CERT_PATH", "/run/pki/clients.crt"),
            ("LDAP_CLIENT_CA_KEY_PATH", "/run/pki/clients.key"),
        ]);

        let tls =
            settings(&DirectoryConfig::read(&vars, Production).unwrap()).and_then(|ldap| ldap.tls);

        assert_eq!(
            tls,
            Some(LdapTls {
                certificate: PathBuf::from("/run/pki/ldap.crt"),
                key: PathBuf::from("/run/pki/ldap.key"),
                client_ca: Some(PathBuf::from("/run/pki/clients.crt")),
            })
        );
    }

    /// The limits the directory runs under are the ones configured.
    #[test]
    fn the_directory_runs_under_the_configured_limits() {
        let vars = Env::of([
            ("LDAP_BIND_ADDR", "127.0.0.1:389"),
            ("LDAP_MAX_CONNECTIONS", "12"),
            ("LDAP_BINDS_PER_IP_PER_MINUTE", "5"),
        ]);

        let limits =
            settings(&DirectoryConfig::read(&vars, Development).unwrap()).map(|ldap| ldap.limits);

        assert!(matches!(
            limits,
            Some(LdapLimits {
                max_connections: 12,
                binds_per_ip_per_minute: 5,
                ..
            })
        ));
    }
}
