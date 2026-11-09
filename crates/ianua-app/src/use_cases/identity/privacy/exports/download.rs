//! Download export: the person whose data an export copies fetches it,
//! through a short-lived link, while its download window is open.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, DataExportId, HttpsUrl};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{DataExportFiles, DataExportStore};
use crate::use_case::Command;
use crate::use_cases::identity::lookup::existing_export_of;

/// The ports [`DownloadExportUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DownloadExportPorts {
    /// The requests.
    pub export_store: Arc<dyn DataExportStore>,
    /// Makes the link the file is fetched through.
    pub files: Arc<dyn DataExportFiles>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Hands the person a link to their ready export.
pub struct DownloadExportUseCase {
    ports: DownloadExportPorts,
}

impl DownloadExportUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DownloadExportPorts) -> Self {
        Self { ports }
    }
}

impl Command for DownloadExportUseCase {
    type Caller = CallerContext;
    type Input = DataExportId;
    type Output = Result<HttpsUrl, AppError>;

    /// A short-lived link to export `export_id`'s file, for the person whose
    /// data it copies, and records `identity.data_export_downloaded`.
    ///
    /// The file holds everything kept about the person, so it goes to them
    /// alone, whoever asked for it. Sam asked for Bob's export when Bob
    /// wrote to support; he cannot download it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::NotFound` when there is no such export of the person
    ///   signed in; another person's export answers the same.
    /// - `AppError::Conflict` when it is not ready yet, or its window is
    ///   over.
    /// - `AppError::Internal` when the link cannot be made or the download
    ///   cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        export_id: DataExportId,
    ) -> Result<HttpsUrl, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.export_store.as_ref();
        let holder = person.account.id();
        let mut export = existing_export_of(store, &tenant, &export_id, holder).await?;
        export
            .download(&person.signed_in, clock::now())
            .map_err(AppError::from_domain)?;
        let until = export.state().available_until().ok_or_else(|| {
            AppError::Conflict(message!(
                "identity-the-export-is-not-ready",
                "the export is not ready"
            ))
        })?;
        let link = self
            .ports
            .files
            .download_link(&tenant, &export_id, until)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ActorRef::User(*holder), export.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(link)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeDataExportStore, asked_export_of, ready_export_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn download(
        store: FakeDataExportStore,
        id: DataExportId,
        authorities: FakeTenantAuthorities,
    ) -> (Result<HttpsUrl, AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = DownloadExportUseCase::new(DownloadExportPorts {
            export_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
            ..DownloadExportPorts::fakes()
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id));
        (result, sink)
    }

    /// Ann's export is ready. She gets a link to it, and the download is
    /// recorded.
    #[test]
    fn the_person_downloads_their_ready_export() {
        let export = ready_export_of(test_caller_id());
        let id = *export.id();

        let (result, sink) = download(
            FakeDataExportStore::holding(&export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(result.unwrap().as_str().contains(&id.to_string()));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.data_export_downloaded"]
        );
    }

    /// Ann's export is still being gathered. There is nothing to download
    /// yet.
    #[test]
    fn an_export_not_ready_yet_is_a_conflict() {
        let export = asked_export_of(test_caller_id());
        let id = *export.id();

        let (result, sink) = download(
            FakeDataExportStore::holding(&export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Downloading another person's ready export returns not found, even
    /// with administrative rights, and records no download event.
    #[test]
    fn someone_elses_export_is_not_found() {
        let export = ready_export_of(UserId::new());
        let id = *export.id();

        let (result, sink) = download(
            FakeDataExportStore::holding(&export),
            id,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out person cannot download their own ready export.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let export = ready_export_of(test_caller_id());
        let id = *export.id();

        let (result, _) = download(
            FakeDataExportStore::holding(&export),
            id,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
