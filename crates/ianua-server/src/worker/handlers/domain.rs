//! The handlers of tenants' domains: certificate orders, through the
//! provisioners the worker builds once for this handler and the domain
//! sweeps alike.

use std::sync::Arc;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::use_cases::domain::certificates::{
    ProvisionTlsHandler, ProvisionTlsPorts, ProvisionTlsUseCase,
};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_infra::postgres::domain::{PgCertificateStore, PgRegisteredDomainStore};

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// The domains' handlers.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![provision_tls(parts)?])
}

/// The handler issuing a verified domain's certificate.
fn provision_tls(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let encryptor: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    let use_case = ProvisionTlsUseCase::new(ProvisionTlsPorts {
        domain_store: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
        certificate_store: Arc::new(PgCertificateStore::new(Arc::clone(databases), encryptor)),
        tls_provisioners: parts.tls.clone(),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = ProvisionTlsHandler::new(Arc::new(use_case))
        .map_err(PlatformError::of("the certificate handler"))?;
    Ok(Arc::new(handler))
}
