//! Copies of a person's data: the requests, gathering the file, the link it
//! is downloaded through, and telling the person it is ready.

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DataExportId, HttpsUrl, UserId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::ports::shared::MailRecipient;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The timestamp a background export sweep advances through.
    pub enum ExportSweepSortField {
        /// Build requested files in the order they were requested.
        RequestedAt => "requested_at",
        /// Remove ready files in the order their windows closed.
        AvailableUntil => "available_until",
    }
    default = RequestedAt;
}

impl SortKeys<ExportSweepSortField> for DataExportRequest<ResolvedTenant> {
    /// Supplies the immutable timestamp used by this sweep.
    fn sort_key(&self, field: ExportSweepSortField) -> SortKey {
        match field {
            ExportSweepSortField::RequestedAt => self.requested_at().into(),
            ExportSweepSortField::AvailableUntil => self.state().available_until().into(),
        }
    }

    /// Keeps requests sharing a timestamp in a stable order.
    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting requests for a copy of a person's data.
#[async_trait]
pub trait DataExportStore: Send + Sync + TenantScoped {
    /// Saves a new or changed request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// The request with `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the request cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DataExportId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError>;

    /// `user_id`'s request still asked for or ready to download, if there
    /// is one. A person has at most one open at a time.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be read.
    async fn open_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError>;

    /// Every request `user_id` has, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be read.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<DataExportRequest<ResolvedTenant>>, DomainError>;

    /// One page of requests made by `now` still waiting for their file,
    /// oldest first. Failed builds retain their place for the next run.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be read.
    async fn waiting(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError>;

    /// One page of ready requests whose download window is over at `now`,
    /// longest over first.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the requests cannot be read.
    async fn lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port gathering a person's data into one file.
///
/// The adapter reads each section the request names, writes them into one
/// file in a form another service reads, such as JSON, and keeps it under
/// the request's id in private storage. It writes no secret: no password
/// hash, factor secret, recovery code, key or token, only what exists and
/// when. It gives up after a bounded time and answers with an error, and the
/// request is built again on the next run.
#[async_trait]
pub trait DataExportBuilder: Send + Sync {
    /// Gathers `request`'s sections and keeps the file.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if a section cannot be read, the file cannot
    /// be written, or the work ran out of time.
    async fn build(
        &self,
        tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the files exports are kept in.
#[async_trait]
pub trait DataExportFiles: Send + Sync {
    /// A link that downloads the file of export `id` once, signed by the
    /// adapter and working for a few minutes and never past
    /// `available_until`. It names no person and carries no secret of the
    /// account.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the file is gone or no link can be made.
    async fn download_link(
        &self,
        tenant_id: &ScopedTenant,
        id: &DataExportId,
        available_until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError>;

    /// Deletes the file of export `id`. Deleting one already gone succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the file cannot be deleted.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &DataExportId) -> Result<(), DomainError>;
}

/// Dyn-safe port telling a person their export is ready.
///
/// The adapter mails the account's address, in the language the person
/// reads, the tenant's
/// [`ExportReady`](ianua_domain::domains::branding::email_template::EmailTemplateType::ExportReady)
/// mail: when the download window ends and where to sign in to download.
/// The mail carries no link that downloads on its own. It gives up after a
/// few seconds.
#[async_trait]
pub trait DataExportNotifier: Send + Sync {
    /// Tells `to` the export is ready until `available_until`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] if the mail could not be
    /// handed over.
    async fn ready(
        &self,
        tenant_id: &ScopedTenant,
        to: MailRecipient<'_>,
        available_until: OffsetDateTime,
    ) -> Result<(), DomainError>;
}
