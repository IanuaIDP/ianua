//! An export of an audit log, written in the background.
//!
//! A log can hold millions of records, more than one request should read.
//! So a reader asks for an export, and a worker writes the file in pages
//! while they wait. Once it is written the file may be downloaded for a
//! week through a short-lived link, by anyone who may read that log, and
//! then it is gone. A file the worker did not write within a day is given
//! up on, so a stuck export does not hold its place for ever.

/// What an audit log export holds: its filter and its format.
pub mod filter;
/// The digest and seal that let an auditor trust an export's file.
pub mod seal;
/// Where an audit log export stands.
pub mod state;

use time::{Duration, OffsetDateTime};

use crate::domains::audit::access::{AuditLogAccess, AuditLogOf};
use crate::domains::audit::events::{
    OrgAuditExportDownloaded, OrgAuditExportRequested, PlatformAuditExportDownloaded,
    PlatformAuditExportRequested, TenantAuditExportDownloaded, TenantAuditExportRequested,
};
use crate::domains::audit::export::filter::{AuditExportFilter, AuditExportFormat};
use crate::domains::audit::export::seal::{ExportSeal, FileDigest, SealStatement, WrittenFile};
use crate::domains::audit::export::state::{AuditExportState, AuditExportStatus};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{ActorRef, AuditExportId};

/// How long a written export may be downloaded.
pub const DOWNLOAD_WINDOW: Duration = Duration::days(7);

/// How long the worker has to write an export before it is given up on.
pub const WRITE_DEADLINE: Duration = Duration::days(1);

/// Tracks filtered log extraction, worker progress and the download window.
#[derive(Debug)]
pub struct AuditLogExport {
    id: AuditExportId,
    log: AuditLogOf,
    requested_by: ActorRef,
    filter: AuditExportFilter,
    format: AuditExportFormat,
    state: AuditExportState,
    seal: Option<ExportSeal>,
    requested_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// An export as storage keeps it, checked again by
/// [`AuditLogExport::reconstitute`].
pub struct AuditLogExportRow {
    /// The export's id.
    pub id: AuditExportId,
    /// The log it exports.
    pub log: AuditLogOf,
    /// Who asked for it.
    pub requested_by: ActorRef,
    /// Which records it holds.
    pub filter: AuditExportFilter,
    /// The format its file is written in.
    pub format: AuditExportFormat,
    /// Where it stands.
    pub state: AuditExportState,
    /// The seal over a written tenant export's file.
    pub seal: Option<ExportSeal>,
    /// When it was asked for.
    pub requested_at: OffsetDateTime,
}

impl AuditLogExport {
    /// Asks for an export of the log `access` may read, holding the records
    /// `filter` admits, written as `format`. Raises
    /// `<scope>.audit_log_export_requested` in the log's own scope.
    #[must_use]
    pub fn request(
        access: &AuditLogAccess,
        filter: AuditExportFilter,
        format: AuditExportFormat,
    ) -> Self {
        let now = crate::shared::clock::now();
        let mut export = Self {
            id: AuditExportId::new(),
            log: access.log(),
            requested_by: access.by().clone(),
            filter: filter.within(access.reach().clone()),
            format,
            state: AuditExportState::Pending,
            seal: None,
            requested_at: now,
            raised: RaisedEvents::default(),
        };
        export.raise_requested(now);
        export
    }

    /// Rebuilds an export from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it was written
    ///   or given up on before it was asked for, keeps a download window
    ///   other than [`DOWNLOAD_WINDOW`], exports the platform's log for
    ///   someone other than an operator, or has a seal only a ready tenant
    ///   export has, or lacks one.
    pub fn reconstitute(row: AuditLogExportRow) -> Result<Self, DomainError> {
        ensure_row_holds(&row)?;
        Ok(Self {
            id: row.id,
            log: row.log,
            requested_by: row.requested_by,
            filter: row.filter,
            format: row.format,
            state: row.state,
            seal: row.seal,
            requested_at: row.requested_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The export's id.
    #[must_use]
    pub fn id(&self) -> &AuditExportId {
        &self.id
    }

    /// The log it exports.
    #[must_use]
    pub fn log(&self) -> AuditLogOf {
        self.log
    }

    /// Whether whoever holds `access` is shown everything this export
    /// holds. A file made for an owner holds every tenant's records, and
    /// Vic, who reaches none, gets no link to it.
    #[must_use]
    pub fn is_shown_in_full_to(&self, access: &AuditLogAccess) -> bool {
        access.reach().covers(self.filter.reach())
    }

    /// Who asked for it.
    #[must_use]
    pub fn requested_by(&self) -> &ActorRef {
        &self.requested_by
    }

    /// Which records it holds.
    #[must_use]
    pub fn filter(&self) -> &AuditExportFilter {
        &self.filter
    }

    /// The format its file is written in.
    #[must_use]
    pub fn format(&self) -> AuditExportFormat {
        self.format
    }

    /// Where it stands, with its window and count once written.
    #[must_use]
    pub fn state(&self) -> AuditExportState {
        self.state
    }

    /// Where it stands.
    #[must_use]
    pub fn status(&self) -> AuditExportStatus {
        self.state.status()
    }

    /// When it was asked for.
    #[must_use]
    pub fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// The newest moment the file covers: the log as it stood when the
    /// export was asked for, or the filter's own end if earlier.
    #[must_use]
    pub fn covers_until(&self) -> OffsetDateTime {
        self.filter.until(self.requested_at)
    }

    /// Whether the worker is still writing it, so it counts against how
    /// many one log may have waiting.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status() == AuditExportStatus::Pending
    }

    /// The seal over a ready tenant export's file, which an auditor checks
    /// against the tenant's published keys. None for any other export.
    #[must_use]
    pub fn seal(&self) -> Option<&ExportSeal> {
        self.seal.as_ref()
    }

    /// What the seal over this export's file says, once it holds `rows`
    /// records digesting to `digest`. None for an organization's or the
    /// platform's log, which no published key signs.
    #[must_use]
    pub fn seal_statement(&self, rows: u64, digest: FileDigest) -> Option<SealStatement> {
        let AuditLogOf::Tenant(tenant_id) = self.log else {
            return None;
        };
        Some(SealStatement {
            export_id: self.id,
            tenant_id,
            format: self.format,
            covers_until: self.covers_until(),
            rows,
            digest,
        })
    }

    /// Marks `file` written at `now`: it may be downloaded for
    /// [`DOWNLOAD_WINDOW`].
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not pending.
    /// - [`DomainError::Validation`] when a tenant export comes without a
    ///   seal, or another export with one: no tenant file is handed out
    ///   that an auditor could not check.
    pub fn mark_written(
        &mut self,
        now: OffsetDateTime,
        file: WrittenFile,
    ) -> Result<(), DomainError> {
        let ready = AuditExportState::Ready {
            at: now,
            available_until: now.saturating_add(DOWNLOAD_WINDOW),
            rows: file.rows,
            digest: file.digest,
        };
        if file.seal.is_some() != is_sealed(self.log, ready) {
            return Err(DomainError::invalid(message!(
                "audit-only-a-tenant-export-is-sealed",
                "a tenant export is written with a seal, and no other export is"
            )));
        }
        self.move_to(ready)?;
        self.seal = file.seal;
        Ok(())
    }

    /// Gives up on a file the worker did not write within
    /// [`WRITE_DEADLINE`] of the request, as of `now`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not pending, or its
    ///   deadline is not over at `now`.
    pub fn give_up(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if now < self.requested_at.saturating_add(WRITE_DEADLINE) {
            return Err(DomainError::invalid_transition(message!(
                "audit-the-export-may-still-be-written",
                "the export may still be written"
            )));
        }
        self.move_to(AuditExportState::Failed { at: now })
    }

    /// Ends the download window once it is over at `now`, with the seal of
    /// the file that is gone. The caller deletes the file.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not ready, or its
    ///   window is not over at `now`.
    pub fn expire(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.state.downloadable_at(now) {
            return Err(DomainError::invalid_transition(message!(
                "audit-the-export-may-still-be-downloaded",
                "the export may still be downloaded"
            )));
        }
        self.move_to(AuditExportState::Expired)?;
        self.seal = None;
        Ok(())
    }

    /// Lets someone who may read the log download the file, while it is
    /// ready at `now`. Raises `<scope>.audit_log_export_downloaded`.
    ///
    /// Ann exported her tenant's log and Sam, who may not read it, got hold
    /// of the export's id. Without the check he downloads every record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `access` is to another log.
    /// - [`DomainError::Conflict`] when the file is not written yet, or its
    ///   window is over at `now`.
    pub fn hand_out(
        &mut self,
        access: &AuditLogAccess,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if access.log() != self.log {
            return Err(DomainError::forbidden(message!(
                "audit-the-export-is-of-a-log",
                "the export is of a log the caller may not read"
            )));
        }
        let AuditExportState::Ready { rows, .. } = self.state else {
            return Err(DomainError::conflict(message!(
                "audit-the-export-is-not-written-yet",
                "the export is not written yet"
            )));
        };
        if !self.state.downloadable_at(now) {
            return Err(DomainError::conflict(message!(
                "audit-the-export-s-download-window-is",
                "the export's download window is over"
            )));
        }
        self.raise_downloaded(rows, now);
        Ok(())
    }

    fn move_to(&mut self, to: AuditExportState) -> Result<(), DomainError> {
        self.status().try_transition(to.status())?;
        self.state = to;
        Ok(())
    }

    fn raise_requested(&mut self, now: OffsetDateTime) {
        let (export_id, format) = (self.id, self.format);
        match self.log {
            AuditLogOf::Tenant(tenant_id) => self.raised.raise_tenant(
                tenant_id,
                TenantAuditExportRequested {
                    export_id,
                    format,
                    occurred_at: now,
                },
            ),
            AuditLogOf::Organization(organization_id) => {
                self.raised.raise_organization(OrgAuditExportRequested {
                    organization_id,
                    export_id,
                    format,
                    occurred_at: now,
                });
            }
            AuditLogOf::Platform => self.raised.raise_platform(PlatformAuditExportRequested {
                export_id,
                format,
                occurred_at: now,
            }),
        }
    }

    fn raise_downloaded(&mut self, rows: u64, now: OffsetDateTime) {
        let export_id = self.id;
        match self.log {
            AuditLogOf::Tenant(tenant_id) => self.raised.raise_tenant(
                tenant_id,
                TenantAuditExportDownloaded {
                    export_id,
                    rows,
                    occurred_at: now,
                },
            ),
            AuditLogOf::Organization(organization_id) => {
                self.raised.raise_organization(OrgAuditExportDownloaded {
                    organization_id,
                    export_id,
                    rows,
                    occurred_at: now,
                });
            }
            AuditLogOf::Platform => self.raised.raise_platform(PlatformAuditExportDownloaded {
                export_id,
                rows,
                occurred_at: now,
            }),
        }
    }
}

impl RaisesComplete for AuditLogExport {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses a stored export whose parts break the rules an export keeps.
fn ensure_row_holds(row: &AuditLogExportRow) -> Result<(), DomainError> {
    let operator_asked = matches!(row.requested_by, ActorRef::Operator(_));
    RowCheck::of("audit log export")
        .in_order_if(
            row.requested_at,
            row.state.since(),
            "written or given up on before it was asked for",
        )
        .holds(
            row.state.keeps_the_download_window(DOWNLOAD_WINDOW),
            "a download window no export has",
        )
        .holds(
            row.log != AuditLogOf::Platform || operator_asked,
            "the platform's log exported for someone other than an operator",
        )
        .holds(
            row.seal.is_some() == is_sealed(row.log, row.state),
            "a seal on an export that has none, or a written tenant export without one",
        )
        .finish()
}

/// Whether an export of `log` standing at `state` carries a seal: a ready
/// tenant export does, and nothing else.
fn is_sealed(log: AuditLogOf, state: AuditExportState) -> bool {
    matches!(log, AuditLogOf::Tenant(_)) && state.status() == AuditExportStatus::Ready
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::audit::access::LogReach;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{OperatorId, OrganizationId, TenantId, UserId};

    fn tenant_access(tenant: TenantId) -> AuditLogAccess {
        AuditLogAccess::granted(AuditLogOf::Tenant(tenant), ActorRef::User(UserId::new()))
    }

    fn asked(access: &AuditLogAccess) -> AuditLogExport {
        AuditLogExport::request(access, AuditExportFilter::default(), AuditExportFormat::Csv)
    }

    fn digest() -> FileDigest {
        FileDigest::from_bytes(&[7; 32]).unwrap()
    }

    fn sealed(rows: u64) -> WrittenFile {
        WrittenFile {
            rows,
            digest: digest(),
            seal: Some(ExportSeal::new("eyJh.eyJi.c2ln").unwrap()),
        }
    }

    fn names(export: &mut AuditLogExport) -> Vec<&'static str> {
        export
            .take_events()
            .iter()
            .map(|event| event.event_type().as_str())
            .collect()
    }

    /// Ann asks for an export of Acme's log. It waits for the worker,
    /// names Acme's log and records the request in Acme.
    #[test]
    fn a_reader_asks_for_an_export_of_their_log() {
        let acme = TenantId::new();

        let mut export = asked(&tenant_access(acme));

        assert!(export.is_pending());
        assert_eq!(export.log(), AuditLogOf::Tenant(acme));
        let events = export.take_events();
        assert_eq!(
            events[0].event_type().as_str(),
            "tenant.audit_log_export_requested"
        );
        assert_eq!(events[0].tenant_id(), Some(&acme));
    }

    /// An operator exports the platform's log, and an owner their
    /// organization's. Each request is recorded in its log's own scope.
    #[test]
    fn a_request_is_recorded_in_the_scope_of_its_log() {
        let operator =
            AuditLogAccess::granted(AuditLogOf::Platform, ActorRef::Operator(OperatorId::new()));
        let organization = AuditLogAccess::granted(
            AuditLogOf::Organization(OrganizationId::new()),
            ActorRef::System,
        );

        assert_eq!(
            names(&mut asked(&operator)),
            ["operator.audit_log_export_requested"]
        );
        assert_eq!(
            names(&mut asked(&organization)),
            ["organization.audit_log_export_requested"]
        );
    }

    /// The worker writes 1,200 records. Ann downloads them within the week,
    /// and the download names how many records left.
    #[test]
    fn a_written_export_is_handed_out_inside_its_window() {
        let access = tenant_access(TenantId::new());
        let mut export = asked(&access);
        names(&mut export);
        let now = crate::shared::clock::now();
        export.mark_written(now, sealed(1_200)).unwrap();

        export.hand_out(&access, now + Duration::days(6)).unwrap();

        let events = export.take_events();
        assert_eq!(
            events[0].event_type().as_str(),
            "tenant.audit_log_export_downloaded"
        );
        assert_eq!(events[0].payload().get("rows"), Some("1200"));
    }

    /// Authority to read a different tenant's log cannot download a ready
    /// export of this tenant's records.
    #[test]
    fn an_export_is_handed_out_only_for_its_own_log() {
        let mut export = asked(&tenant_access(TenantId::new()));
        let now = crate::shared::clock::now();
        export.mark_written(now, sealed(3)).unwrap();

        let refused = export.hand_out(&tenant_access(TenantId::new()), now);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An export not written yet, and one whose week is over, are not handed
    /// out.
    #[test]
    fn an_export_is_handed_out_only_once_written_and_before_its_window_ends() {
        let access = tenant_access(TenantId::new());
        let mut export = asked(&access);
        let now = crate::shared::clock::now();

        let early = export.hand_out(&access, now);
        export.mark_written(now, sealed(3)).unwrap();
        let late = export.hand_out(&access, now + DOWNLOAD_WINDOW);

        assert!(matches!(early, Err(DomainError::Conflict(_))));
        assert!(matches!(late, Err(DomainError::Conflict(_))));
    }

    /// The worker never wrote the file. An hour in it may still be written;
    /// a day in it is given up on and no longer waits.
    #[test]
    fn an_export_not_written_within_a_day_is_given_up_on() {
        let mut export = asked(&tenant_access(TenantId::new()));
        let asked_at = export.requested_at();

        let early = export.give_up(asked_at + Duration::hours(1));
        export.give_up(asked_at + WRITE_DEADLINE).unwrap();

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(export.status(), AuditExportStatus::Failed);
        assert!(!export.is_pending());
    }

    /// After its week a written export expires. Expiring it a day early is
    /// refused.
    #[test]
    fn an_export_expires_once_its_window_is_over() {
        let mut export = asked(&tenant_access(TenantId::new()));
        let now = crate::shared::clock::now();
        export.mark_written(now, sealed(3)).unwrap();

        let early = export.expire(now + Duration::days(6));
        export.expire(now + DOWNLOAD_WINDOW).unwrap();

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(export.status(), AuditExportStatus::Expired);
        assert!(export.seal().is_none());
    }

    /// The worker writes Acme's export and keeps the seal it signed, which
    /// names the export, Acme, the count and the file's digest.
    #[test]
    fn a_tenant_export_is_written_with_its_seal() {
        let acme = TenantId::new();
        let mut export = asked(&tenant_access(acme));

        let statement = export.seal_statement(3, digest()).unwrap();
        export
            .mark_written(crate::shared::clock::now(), sealed(3))
            .unwrap();

        assert_eq!(statement.tenant_id, acme);
        assert_eq!(statement.export_id, *export.id());
        assert_eq!(statement.digest, digest());
        assert!(export.seal().is_some());
    }

    /// A tenant file without a seal would be one an auditor cannot check,
    /// so it is not handed out; it stays pending for the next try.
    #[test]
    fn a_tenant_export_without_a_seal_is_refused() {
        let mut export = asked(&tenant_access(TenantId::new()));
        let unsealed = WrittenFile {
            seal: None,
            ..sealed(3)
        };

        let refused = export.mark_written(crate::shared::clock::now(), unsealed);

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(export.is_pending());
    }

    /// No published key signs an organization's log, so its export has no
    /// statement to seal, and one given a seal is refused.
    #[test]
    fn an_organization_export_carries_no_seal() {
        let access = AuditLogAccess::granted(
            AuditLogOf::Organization(OrganizationId::new()),
            ActorRef::System,
        );
        let mut export = asked(&access);

        let statement = export.seal_statement(3, digest());
        let refused = export.mark_written(crate::shared::clock::now(), sealed(3));

        assert!(statement.is_none());
        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// Max reaches one tenant, so what he asks for is narrowed to it. He
    /// and an owner are shown the whole file; Vic, who reaches none, is not.
    #[test]
    fn an_export_holds_only_what_its_asker_is_shown() {
        let log = AuditLogOf::Organization(OrganizationId::new());
        let tenant = TenantId::new();
        let reader = |reach| AuditLogAccess::granted(log, ActorRef::System).within(reach);
        let max = reader(LogReach::Tenants(vec![tenant]));
        let owner = reader(LogReach::Every);
        let vic = reader(LogReach::Tenants(Vec::new()));

        let export = asked(&max);

        assert_eq!(export.filter().reach(), max.reach());
        assert!(export.is_shown_in_full_to(&max));
        assert!(export.is_shown_in_full_to(&owner));
        assert!(!export.is_shown_in_full_to(&vic));
    }

    /// A file an owner asked for holds every tenant's records, so nobody
    /// reaching fewer is shown it, whatever right to export they hold.
    #[test]
    fn an_owner_s_export_is_not_shown_to_someone_reaching_less() {
        let log = AuditLogOf::Organization(OrganizationId::new());
        let owner = AuditLogAccess::granted(log, ActorRef::System);
        let max = AuditLogAccess::granted(log, ActorRef::System)
            .within(LogReach::Tenants(vec![TenantId::new()]));

        let export = asked(&owner);

        assert!(!export.is_shown_in_full_to(&max));
    }

    fn row(log: AuditLogOf, requested_by: ActorRef, state: AuditExportState) -> AuditLogExportRow {
        AuditLogExportRow {
            id: AuditExportId::new(),
            log,
            requested_by,
            filter: AuditExportFilter::default(),
            format: AuditExportFormat::Json,
            state,
            seal: None,
            requested_at: crate::shared::clock::now(),
        }
    }

    /// A stored written tenant export without its seal is refused as
    /// corrupt, so an unsealed file is never handed out.
    #[test]
    fn a_stored_written_tenant_export_without_a_seal_is_refused() {
        let now = crate::shared::clock::now();
        let stored = AuditLogExportRow {
            requested_at: now,
            ..row(
                AuditLogOf::Tenant(TenantId::new()),
                ActorRef::System,
                AuditExportState::Ready {
                    at: now,
                    available_until: now + DOWNLOAD_WINDOW,
                    rows: 1,
                    digest: digest(),
                },
            )
        };

        assert!(refused_as_corrupt(&AuditLogExport::reconstitute(stored)));
    }

    /// A stored export written a day before it was asked for is refused as
    /// corrupt.
    #[test]
    fn a_stored_export_written_before_it_was_asked_for_is_refused() {
        let yesterday = crate::shared::clock::now() - Duration::days(1);
        let stored = row(
            AuditLogOf::Tenant(TenantId::new()),
            ActorRef::System,
            AuditExportState::Ready {
                at: yesterday,
                available_until: yesterday + DOWNLOAD_WINDOW,
                rows: 1,
                digest: digest(),
            },
        );

        assert!(refused_as_corrupt(&AuditLogExport::reconstitute(stored)));
    }

    /// A platform export attributed to a tenant user is refused as corrupt
    /// when reconstructed from storage.
    #[test]
    fn a_stored_platform_export_for_a_non_operator_is_refused() {
        let stored = row(
            AuditLogOf::Platform,
            ActorRef::User(UserId::new()),
            AuditExportState::Pending,
        );

        assert!(refused_as_corrupt(&AuditLogExport::reconstitute(stored)));
    }
}
