//! The gateway started beside the platform, through its own composition
//! root, as production runs it next to the control plane: its own database
//! role, the same keys, bus, cache and namespace, the platform's certificate
//! for the domain tenants' apps sit under from the stack's authority, and
//! the API's internal listener for app sign-in and approvals. It can be
//! started again on the ports it first took, as its process restarts.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ianua_boot::shutdown::Shutdown;
use ianua_infra::test_support::TestDb;
use ianua_zero::serve::{self, Serving};

use super::StackError;
use super::authority::Authority;
use super::settings::{GatewayPlace, Settings};

/// What the gateway runs beside.
pub(crate) struct Beside<'a> {
    /// The test database.
    pub(crate) database: &'a TestDb,
    /// The stack's files directory, where its certificate files are kept.
    pub(crate) files: &'a Path,
    /// The stack's authority, which issues the platform's certificate.
    pub(crate) authority: &'a Authority,
    /// The domain tenants' apps sit under.
    pub(crate) apps_domain: &'a str,
    /// The API's relay listener.
    pub(crate) api_relay: SocketAddr,
}

/// The gateway once started: where it listens, and the settings that start
/// it again on the same ports.
pub(crate) struct Started {
    /// Where it listens.
    pub(crate) serving: Serving,
    /// Its settings, every listener pinned to the port it took.
    pub(crate) settings: Settings,
}

/// The files the gateway reads: its certificate and key for the apps
/// domain, and the directory it keeps its secrets in.
struct Files {
    certificate: PathBuf,
    key: PathBuf,
    secrets: PathBuf,
}

/// Starts the gateway beside the platform `settings` describe, under
/// `shutdown`, and answers where it listens and how to start it again.
///
/// # Errors
///
/// [`StackError::Io`] when its files cannot be written, and
/// [`StackError::Gateway`] when it refuses its settings or cannot start.
pub(crate) async fn started(
    settings: &Settings,
    beside: &Beside<'_>,
    shutdown: &Shutdown,
) -> Result<Started, StackError> {
    let files = written(beside)?;
    let place = GatewayPlace {
        database: beside.database,
        certificate: &files.certificate,
        key: &files.key,
        secrets: &files.secrets,
        api_relay: beside.api_relay,
    };
    let mut gateway = settings.gateway(&place);
    let serving = serving(&gateway, shutdown).await?;
    for (name, taken) in taken_ports(&serving) {
        gateway.set(name, &taken.to_string());
    }
    Ok(Started {
        serving,
        settings: gateway,
    })
}

/// Each listener `serving` opened, by the setting that names its address.
fn taken_ports(serving: &Serving) -> Vec<(&'static str, SocketAddr)> {
    let optional = [
        ("GATEWAY_ACME_LISTEN", serving.acme),
        ("GATEWAY_RUNNER_LISTEN", serving.runners),
        ("GATEWAY_WORKFLOW_LISTEN", serving.workflows),
        ("GATEWAY_CONNECTOR_LISTEN", serving.connectors),
    ];
    [
        ("GATEWAY_LISTEN", serving.public),
        ("GATEWAY_STATUS_LISTEN", serving.status),
    ]
    .into_iter()
    .chain(
        optional
            .into_iter()
            .filter_map(|(name, taken)| taken.map(|address| (name, address))),
    )
    .collect()
}

/// Starts the gateway from its own `settings` under `shutdown`, as its
/// process starts, and answers where it listens.
///
/// # Errors
///
/// [`StackError::Gateway`] when it refuses its settings or cannot start.
pub(crate) async fn serving(
    settings: &Settings,
    shutdown: &Shutdown,
) -> Result<Serving, StackError> {
    serve::serving(&settings.env(), shutdown)
        .await
        .map_err(StackError::Gateway)
}

/// Writes the gateway's certificate for the apps domain and makes its
/// secrets directory under the stack's files.
///
/// # Errors
///
/// [`StackError::Io`] when a file cannot be written, and
/// [`StackError::Certificate`] when the certificate cannot be issued.
fn written(beside: &Beside<'_>) -> Result<Files, StackError> {
    let directory = beside.files.join("gateway");
    let secrets = directory.join("secrets");
    std::fs::create_dir_all(&secrets).map_err(|cause| StackError::Io {
        what: "gateway's files",
        cause,
    })?;
    let issued = beside.authority.issue_wildcard(beside.apps_domain)?;
    let certificate = directory.join("tls.crt");
    let key = directory.join("tls.key");
    for (path, text) in [(&certificate, issued.chain_pem()), (&key, issued.key_pem())] {
        std::fs::write(path, text).map_err(|cause| StackError::Io {
            what: "gateway's certificate",
            cause,
        })?;
    }
    Ok(Files {
        certificate,
        key,
        secrets,
    })
}
