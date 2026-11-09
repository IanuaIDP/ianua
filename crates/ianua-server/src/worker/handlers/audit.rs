//! The handlers of audit stream records and audit log exports.

use std::sync::Arc;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::use_cases::audit::exports::{WriteExportHandler, WritePorts, WriteUseCase};
use ianua_app::use_cases::audit::{StreamRecordHandler, StreamRecordPorts, StreamRecordUseCase};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::crypto::Pkcs8JwtSigner;
use ianua_infra::files::FileAuditExportFiles;
use ianua_infra::http::HttpAuditStreamSender;
use ianua_infra::postgres::audit::{PgAuditExportSource, PgAuditExportStore, PgAuditStreamStore};

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// The handlers of audit stream records and audit log exports.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![stream_records(parts)?, write_exports(parts)?])
}

/// The handler sending one audit record along one of its tenant's
/// streams, each send held to `OUTBOUND_DELIVERY_TIMEOUT_SECONDS` and its
/// address screened against `UPSTREAM_NETWORKS`.
fn stream_records(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let encryptor: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    let sender = HttpAuditStreamSender::new(
        platform.outbound.upstream_networks.clone(),
        parts.config.http.delivery_timeout,
        encryptor,
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the audit stream sender"))?;
    let stream = StreamRecordUseCase::new(StreamRecordPorts {
        stream_store: Arc::new(PgAuditStreamStore::new(Arc::clone(&platform.databases))),
        sender: Arc::new(sender),
        records: Arc::clone(&parts.recorded_events),
    });
    let handler = StreamRecordHandler::new(Arc::new(stream))
        .map_err(PlatformError::of("the audit stream handler"))?;
    Ok(Arc::new(handler))
}

/// The handler writing an audit log export's file into the file store,
/// a tenant's sealed with its signing key.
fn write_exports(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let write = WriteUseCase::new(WritePorts {
        exports: Arc::new(PgAuditExportStore::new(Arc::clone(databases))),
        source: Arc::new(PgAuditExportSource::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        files: Arc::new(FileAuditExportFiles::new(
            Arc::clone(&platform.files),
            parts.platform.file_links.clone(),
        )),
        key_store: parts.signing_keys(),
        jwt_signer: Arc::new(Pkcs8JwtSigner),
        issuers: parts.issuers(),
    });
    let handler = WriteExportHandler::new(Arc::new(write))
        .map_err(PlatformError::of("the audit export handler"))?;
    Ok(Arc::new(handler))
}
