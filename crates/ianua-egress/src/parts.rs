//! The egress gateway built from its configuration: the data plane's
//! databases with every tenant's route, the adapters the decision reads
//! through, the inbox its refusals are recorded in, and the TLS it serves.
//! Nothing is built anywhere else.

use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::use_cases::routing::egress::{DecidePorts, DecideUseCase};
use ianua_boot::shutdown::Shutdown;
use ianua_infra::crypto::{AesGcmSecretEncryptor, EventSeal, Pkcs8AssertionVerifier};
use ianua_infra::inbox::InboxEventDispatcher;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::agents::PgAgentExposureGate;
use ianua_infra::postgres::crypto::PgAssertionKeyStore;
use ianua_infra::postgres::routing::PgCrossTenantEgressPolicies;
use ianua_infra::postgres::tenant::load_tenant_databases;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::dial::{Reach, SystemResolver};
use crate::error::EgressError;
use crate::handler::{Decision, Egress, WayOutLimits};
use crate::tls::acceptor;

/// The egress gateway as built: the gateway, the TLS it serves, and the
/// databases whose routes are read again on a timer.
pub(crate) struct Built {
    /// The gateway.
    pub(crate) egress: Arc<Egress<SystemResolver>>,
    /// The TLS it serves.
    pub(crate) acceptor: TlsAcceptor,
    /// The data plane's databases.
    pub(crate) databases: Arc<Databases>,
}

/// The egress gateway `config` describes, its tunnels stopped with
/// `shutdown`.
///
/// # Errors
///
/// [`EgressError`] naming the part that could not be built: the tenants'
/// routes, or the TLS it serves.
pub(crate) async fn built(config: &Config, shutdown: &Shutdown) -> Result<Built, EgressError> {
    let databases = Arc::new(Databases::gateway(
        config.database.login.options.clone(),
        config.database.pools,
    ));
    load_tenant_databases(&databases)
        .await
        .map_err(EgressError::of("the tenants' database routes"))?;
    let reach = Reach {
        resolver: SystemResolver,
        networks: config.networks.clone(),
        timeout: config.limits.connect,
    };
    let limits = WayOutLimits {
        decision: config.limits.decision,
        request: config.limits.request,
        idle: config.limits.idle,
        tunnels: config.limits.tunnels,
    };
    let decision = decision(config, &databases);
    Ok(Built {
        egress: Arc::new(Egress::new(decision, reach, limits, shutdown.clone())),
        acceptor: acceptor(&config.listen.certificate, &config.listen.client_ca)?,
        databases,
    })
}

/// The decision on each way out, read under the data plane's role, its
/// refusals recorded in the data plane's sealed inbox.
fn decision(config: &Config, databases: &Arc<Databases>) -> Decision {
    let sealer: Arc<dyn SecretEncryptor> = Arc::new(AesGcmSecretEncryptor::new(
        config.keys.sealing_key.clone(),
        config.keys.retired_keys.clone(),
    ));
    let assertion_keys = Arc::new(PgAssertionKeyStore::new(Arc::clone(databases), sealer));
    let use_case = DecideUseCase::new(DecidePorts {
        policies: Arc::new(PgCrossTenantEgressPolicies::new(Arc::clone(databases))),
        assertions: Arc::new(Pkcs8AssertionVerifier::new(assertion_keys)),
        exposure: Arc::new(PgAgentExposureGate::new(Arc::clone(databases))),
    });
    let inbox = Arc::new(InboxEventDispatcher::new(
        Arc::clone(databases),
        EventSeal::data_plane(&config.keys.shared_root),
    ));
    Decision {
        use_case,
        auditor: RequestAuditor::system(inbox),
    }
}
