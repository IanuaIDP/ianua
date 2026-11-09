//! What every audit log export does once its reader's access is worked
//! out, whichever log it is of: open one within the log's cap on waiting
//! exports and queue the job that writes it, or answer one with a link once
//! it is written.

use std::num::NonZeroU32;

use ianua_domain::domains::audit::access::AuditLogAccess;
use ianua_domain::domains::audit::export::AuditLogExport;
use ianua_domain::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
use ianua_domain::domains::audit::export::state::AuditExportState;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{AuditExportId, HttpsUrl};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::{AuditExportFiles, AuditExportStore};
use crate::ports::scheduling::JobQueue;
use crate::use_cases::audit::exports::job::WriteJob;

/// Which records to export, and how to write them.
pub struct Selection {
    /// The records the file holds.
    pub filter: AuditExportFilter,
    /// The format the file is written in.
    pub format: AuditExportFormat,
}

/// The deployment's bounds on exports.
#[derive(Debug, Clone, Copy)]
pub struct ExportLimits {
    /// How many exports one log may have waiting for the worker at once.
    pub pending_per_log: NonZeroU32,
}

/// An export as its reader sees it, with a link to its file once written.
pub struct ExportAnswer {
    /// The stored request, including progress and file availability.
    pub export: AuditLogExport,
    /// A short-lived link that downloads the file once, while it is ready;
    /// `None` while it is still written, and once it failed or expired.
    pub download: Option<HttpsUrl>,
}

/// What opening an export works through.
pub(in crate::use_cases::audit::exports) struct Opening<'a> {
    /// Keeps the export.
    pub(in crate::use_cases::audit::exports) exports: &'a dyn AuditExportStore,
    /// Queues the job that writes it.
    pub(in crate::use_cases::audit::exports) jobs: &'a dyn JobQueue,
    /// How many may wait at once.
    pub(in crate::use_cases::audit::exports) limits: ExportLimits,
}

/// What answering an export works through.
pub(in crate::use_cases::audit::exports) struct Answering<'a> {
    /// Finds the export.
    pub(in crate::use_cases::audit::exports) exports: &'a dyn AuditExportStore,
    /// Makes the link to its file.
    pub(in crate::use_cases::audit::exports) files: &'a dyn AuditExportFiles,
}

/// Opens an export of the log `access` may read, queues the job that writes
/// it, and records `<scope>.audit_log_export_requested`.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when the log has as many exports waiting
///   as it may.
/// - `AppError::Internal` when the export cannot be kept or queued, or the
///   request cannot be recorded.
pub(in crate::use_cases::audit::exports) async fn opened(
    desk: Opening<'_>,
    access: &AuditLogAccess,
    request: Selection,
    auditor: &RequestAuditor,
) -> Result<AuditExportId, AppError> {
    ensure_room(&desk, access).await?;
    let mut export = AuditLogExport::request(access, request.filter, request.format);
    desk.exports.save(&export).await.or_internal()?;
    let job = WriteJob::of(&export).scheduled()?;
    desk.jobs.enqueue(&job).await.or_internal()?;
    auditor
        .dispatch_by(access.by(), export.take_events())
        .await
        .or_internal()?;
    Ok(*export.id())
}

/// Export `id` of the log `access` may read, with a link to its file when
/// it is ready, recording `<scope>.audit_log_export_downloaded` for the
/// link handed out.
///
/// # Errors
///
/// - `AppError::NotFound` when that log has no export `id`, or it holds
///   records its reader is not shown.
/// - `AppError::Internal` when the export cannot be read, the link cannot
///   be made, or the hand-out cannot be recorded.
pub(in crate::use_cases::audit::exports) async fn answered(
    desk: Answering<'_>,
    access: &AuditLogAccess,
    id: &AuditExportId,
    auditor: &RequestAuditor,
) -> Result<ExportAnswer, AppError> {
    let mut export = kept_export(&desk, access, id).await?;
    let now = clock::now();
    let AuditExportState::Ready {
        available_until, ..
    } = export.state()
    else {
        return Ok(without_link(export));
    };
    if !export.state().downloadable_at(now) {
        return Ok(without_link(export));
    }
    export
        .hand_out(access, now)
        .map_err(AppError::from_domain)?;
    let link = desk
        .files
        .download_link(export.id(), available_until)
        .await
        .or_internal()?;
    auditor
        .dispatch_by(access.by(), export.take_events())
        .await
        .or_internal()?;
    Ok(ExportAnswer {
        export,
        download: Some(link),
    })
}

/// The export `id` of the log `access` may read, when its reader is shown
/// all of it. One holding records of a tenant they do not reach is not
/// theirs to know of, whoever asked for it and whenever.
async fn kept_export(
    desk: &Answering<'_>,
    access: &AuditLogAccess,
    id: &AuditExportId,
) -> Result<AuditLogExport, AppError> {
    desk.exports
        .find(access.log(), id)
        .await
        .or_internal()?
        .filter(|export| export.is_shown_in_full_to(access))
        .ok_or_else(|| {
            AppError::NotFound(message!(
                "audit-no-such-audit-log-export",
                "no such audit log export"
            ))
        })
}

/// `export` as it stands, with no link: it is not written yet, or its
/// window has passed.
fn without_link(export: AuditLogExport) -> ExportAnswer {
    ExportAnswer {
        export,
        download: None,
    }
}

/// Refuses a new export of a log that has as many waiting as it may.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when the log is at its cap.
/// - `AppError::Internal` when the waiting exports cannot be counted.
async fn ensure_room(desk: &Opening<'_>, access: &AuditLogAccess) -> Result<(), AppError> {
    let waiting = desk
        .exports
        .pending_count(access.log())
        .await
        .or_internal()?;
    if waiting >= u64::from(desk.limits.pending_per_log.get()) {
        return Err(AppError::TooManyRequests(message!(
            "audit-this-audit-log-has-as-many",
            "this audit log has as many exports waiting as it may; wait for one to finish"
        )));
    }
    Ok(())
}
