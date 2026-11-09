//! Write an export: the worker reads the records an export holds, a keyset
//! page at a time, streams them into its file, seals a tenant's file, and
//! marks it ready.
//!
//! Run by the job a request queues. The log is read as it stood when the
//! export was asked for, so the file is a whole snapshot and never cut
//! short: every record the filter admits is written, however many. A try
//! that fails leaves the export pending and the queue tries again, writing
//! the file from the start.
//!
//! A tenant's file is sealed with the tenant's signing key in use now: a
//! statement naming the export, the tenant, how many records it holds and
//! the file's SHA-256, which an auditor checks against the keys the tenant
//! publishes. A tenant with no key to sign with gets no file: the try
//! fails and the export is given up on after a day, rather than handed out
//! unsealed.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::audit::export::AuditLogExport;
use ianua_domain::domains::audit::export::seal::{ExportSeal, SealStatement, WrittenFile};
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::Issuer;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::{
    AuditExportFiles, AuditExportSource, AuditExportStore, AuditExportUpload, AuditLogCursor,
    ExportPage, ExportPageStart,
};
use crate::ports::crypto::{JwtSigner, SigningKeyStore};
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::audit::exports::job::WriteJob;
use crate::use_cases::oauth::token::issuing::{active_key, signed};

/// How many records one page reads.
const PAGE: NonZeroU32 = NonZeroU32::MIN.saturating_add(999);

/// The ports [`WriteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct WritePorts {
    /// Loads pending requests and records the generated file's state.
    pub exports: Arc<dyn AuditExportStore>,
    /// Reads the records, a page at a time.
    pub source: Arc<dyn AuditExportSource>,
    /// Where each file is written.
    pub files: Arc<dyn AuditExportFiles>,
    /// The tenant's signing keys, which seal its files.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs a tenant file's seal.
    pub jwt_signer: Arc<dyn JwtSigner>,
    /// The issuer a seal names, the one the tenant's keys are published
    /// under.
    pub issuers: TenantIssuers,
}

/// Writes the file of one export.
pub struct WriteUseCase {
    ports: WritePorts,
}

impl WriteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: WritePorts) -> Self {
        Self { ports }
    }

    /// Streams every record `export` holds into its file, newest first, and
    /// answers how many were written and the file's digest.
    async fn written(&self, export: &AuditLogExport) -> Result<WrittenFile, AppError> {
        let mut upload = self
            .ports
            .files
            .create(export.id(), export.format())
            .await
            .or_internal()?;
        let rows = self.append_every_page(export, upload.as_mut()).await?;
        let digest = upload.finish().await.or_internal()?;
        Ok(WrittenFile {
            rows,
            digest,
            seal: None,
        })
    }

    /// Appends every record `export` holds to `upload`, a page at a time,
    /// and answers how many there were.
    async fn append_every_page(
        &self,
        export: &AuditLogExport,
        upload: &mut dyn AuditExportUpload,
    ) -> Result<u64, AppError> {
        let mut start = ExportPageStart::Newest;
        let mut rows: u64 = 0;
        loop {
            let page = ExportPage {
                log: export.log(),
                filter: export.filter(),
                until: export.covers_until(),
                start,
                limit: PAGE,
            };
            let entries = self.ports.source.page(page).await.or_internal()?;
            upload.append(&entries).await.or_internal()?;
            let count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
            rows = rows.saturating_add(count);
            let full = count >= u64::from(PAGE.get());
            let Some(last) = entries.last().filter(|_| full) else {
                break;
            };
            start = ExportPageStart::OlderThan(AuditLogCursor::past(last));
        }
        Ok(rows)
    }

    /// `file` with the seal its export's log calls for: a tenant's signed
    /// with the tenant's key, any other left without one.
    async fn sealed(
        &self,
        export: &AuditLogExport,
        file: WrittenFile,
    ) -> Result<WrittenFile, AppError> {
        let Some(statement) = export.seal_statement(file.rows, file.digest) else {
            return Ok(file);
        };
        let seal = self.seal(&statement).await?;
        Ok(WrittenFile {
            seal: Some(seal),
            ..file
        })
    }

    /// `statement` signed with its tenant's signing key in use now.
    async fn seal(&self, statement: &SealStatement) -> Result<ExportSeal, AppError> {
        let tenant = ScopedTenant::for_background(statement.tenant_id);
        let issuer = self.ports.issuers.of(&statement.tenant_id).await?;
        let key = active_key(self.ports.key_store.as_ref(), &tenant).await?;
        let claims = seal_claims(&issuer, statement, clock::now());
        let jws = signed(
            self.ports.jwt_signer.as_ref(),
            &key,
            &claims,
            JwtType::AuditSeal,
        )
        .await?;
        ExportSeal::new(jws.expose()).or_internal()
    }
}

impl Command for WriteUseCase {
    type Caller = ();
    type Input = WriteJob;
    type Output = Result<(), AppError>;

    /// Writes the file of the export `job` names, seals a tenant's, and
    /// marks it ready for its download window. An export already written,
    /// or given up on, is left as it is.
    ///
    /// It records nothing: the request was recorded when it was made, and
    /// each download is recorded when its link is handed out.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the log has no such export, or a
    ///   tenant's has no key to seal with, so the queue tries again.
    /// - `AppError::Internal` when the records cannot be read, the file
    ///   cannot be written or sealed, or the export cannot be kept; the
    ///   export stays pending for the next try.
    async fn execute(&self, (): &(), _: &RequestAuditor, job: WriteJob) -> Result<(), AppError> {
        let mut export = self
            .ports
            .exports
            .find(job.log.into(), &job.export_id)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::NotFound(message!(
                    "audit-no-such-audit-log-export",
                    "no such audit log export"
                ))
            })?;
        if !export.is_pending() {
            return Ok(());
        }
        let file = self.written(&export).await?;
        let file = self.sealed(&export, file).await?;
        export
            .mark_written(clock::now(), file)
            .map_err(AppError::from_domain)?;
        self.ports.exports.save(&export).await.or_internal()
    }
}

/// The claims of `statement`'s seal, made at `now` under `issuer`: the
/// export as its `jti`, the tenant as its `sub`, and what the file holds.
fn seal_claims(issuer: &Issuer, statement: &SealStatement, now: OffsetDateTime) -> String {
    serde_json::json!({
        "iss": issuer.as_str(),
        "sub": statement.tenant_id.to_string(),
        "jti": statement.export_id.to_string(),
        "iat": now.unix_timestamp(),
        "audit_export": {
            "format": statement.format.as_str(),
            "covers_until": statement.covers_until.unix_timestamp(),
            "rows": statement.rows,
            "sha256": statement.digest.hex(),
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ianua_domain::domains::audit::access::AuditLogOf;
    use ianua_domain::domains::audit::export::state::{AuditExportState, AuditExportStatus};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::audit::{
        FakeAuditExportFiles, FakeAuditExportSource, FakeAuditExportStore, fake_file_digest,
        pending_export_of, written_export_of,
    };
    use crate::test_support::crypto::{CompactJwtSigner, FakeSigningKeyStore, premigration_keys};
    use crate::test_support::tenant::test_tenant_for_ctx;
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor};

    struct Fixture {
        exports: Arc<FakeAuditExportStore>,
        source: Arc<FakeAuditExportSource>,
        files: Arc<FakeAuditExportFiles>,
        key_store: Arc<FakeSigningKeyStore>,
        signer: Arc<CompactJwtSigner>,
    }

    impl Fixture {
        fn holding(export: AuditLogExport, records: usize) -> Self {
            Self {
                exports: Arc::new(FakeAuditExportStore::holding(export)),
                source: Arc::new(FakeAuditExportSource::holding(records)),
                files: Arc::new(FakeAuditExportFiles::default()),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                signer: Arc::new(CompactJwtSigner::default()),
            }
        }

        fn run(&self, job: WriteJob) -> Result<(), AppError> {
            let use_case = WriteUseCase::new(WritePorts {
                exports: self.exports.clone(),
                source: self.source.clone(),
                files: self.files.clone(),
                key_store: self.key_store.clone(),
                jwt_signer: self.signer.clone(),
                issuers: TenantIssuers::fake(),
            });
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(use_case.execute(&(), &auditor, job))
        }

        fn signed(&self) -> Vec<(JwtType, serde_json::Value)> {
            self.signer
                .signed
                .lock()
                .unwrap()
                .iter()
                .map(|(typ, claims)| (*typ, serde_json::from_str(claims).unwrap()))
                .collect()
        }
    }

    fn acme() -> TenantId {
        *test_tenant_for_ctx().id()
    }

    /// Ann's tenant holds 25,000 records, more than the old export's
    /// 10,000. The worker writes every one, a page at a time, and the
    /// export is ready holding all of them.
    #[test]
    fn every_record_is_written_however_many() {
        let export = pending_export_of(AuditLogOf::Tenant(acme()));
        let id = *export.id();
        let job = WriteJob::of(&export);
        let fixture = Fixture::holding(export, 25_000);

        fixture.run(job).unwrap();

        let kept = fixture.exports.stored(&id).unwrap();
        assert!(matches!(
            kept.state(),
            AuditExportState::Ready { rows: 25_000, .. }
        ));
        assert_eq!(fixture.files.rows_written(&id), 25_000);
        assert_eq!(fixture.source.pages_read(), 26);
        assert!(fixture.files.finished(&id));
    }

    /// Acme's export is sealed as an audit seal, never as a token, naming
    /// the export, Acme, the count and the digest the file came to. The
    /// seal is kept with the export.
    #[test]
    fn a_tenant_export_is_sealed_with_the_file_digest() {
        let export = pending_export_of(AuditLogOf::Tenant(acme()));
        let id = *export.id();
        let job = WriteJob::of(&export);
        let fixture = Fixture::holding(export, 3);

        fixture.run(job).unwrap();

        let signed = fixture.signed();
        assert_eq!(signed.len(), 1);
        let (typ, claims) = &signed[0];
        assert_eq!(*typ, JwtType::AuditSeal);
        assert_eq!(claims["jti"], id.to_string());
        assert_eq!(claims["sub"], acme().to_string());
        assert_eq!(claims["audit_export"]["rows"], 3);
        assert_eq!(claims["audit_export"]["sha256"], fake_file_digest().hex());
        let seal = fixture
            .exports
            .stored(&id)
            .unwrap()
            .seal()
            .cloned()
            .unwrap();
        let payload = seal.as_str().split('.').nth(1).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&decoded).unwrap(),
            *claims
        );
    }

    /// Acme has no signing key in use. Its export is not handed out
    /// unsealed: the try fails and the export stays pending.
    #[test]
    fn a_tenant_without_a_signing_key_gets_no_unsealed_file() {
        let export = pending_export_of(AuditLogOf::Tenant(acme()));
        let id = *export.id();
        let job = WriteJob::of(&export);
        let mut fixture = Fixture::holding(export, 3);
        fixture.key_store = Arc::new(FakeSigningKeyStore::empty());

        let result = fixture.run(job);

        assert!(result.is_err());
        assert_eq!(
            fixture.exports.stored(&id).unwrap().status(),
            AuditExportStatus::Pending
        );
    }

    /// The platform's log has no published key, so its export is written
    /// with its digest and no seal, and nothing is signed.
    #[test]
    fn a_platform_export_is_written_without_a_seal() {
        let export = pending_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let job = WriteJob::of(&export);
        let fixture = Fixture::holding(export, 3);

        fixture.run(job).unwrap();

        let kept = fixture.exports.stored(&id).unwrap();
        assert!(kept.seal().is_none());
        assert!(fixture.signed().is_empty());
    }

    /// The export was already written by an earlier try. The job leaves it
    /// as it is and writes nothing again.
    #[test]
    fn a_written_export_is_left_as_it_is() {
        let export = written_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let job = WriteJob::of(&export);
        let fixture = Fixture::holding(export, 10);

        fixture.run(job).unwrap();

        assert_eq!(fixture.files.rows_written(&id), 0);
        assert_eq!(fixture.source.pages_read(), 0);
    }

    /// The log cannot be read this time. The job fails, so the queue tries
    /// again, and the export stays pending.
    #[test]
    fn an_unreadable_log_leaves_the_export_pending() {
        let export = pending_export_of(AuditLogOf::Platform);
        let id = *export.id();
        let job = WriteJob::of(&export);
        let mut fixture = Fixture::holding(export, 10);
        fixture.source = Arc::new(FakeAuditExportSource::failing());

        let result = fixture.run(job);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(
            fixture.exports.stored(&id).unwrap().status(),
            AuditExportStatus::Pending
        );
    }

    /// The job names an export its log does not hold. It fails as not
    /// found instead of writing anything.
    #[test]
    fn an_unknown_export_is_not_found() {
        let export = pending_export_of(AuditLogOf::Platform);
        let job = WriteJob::of(&export);
        let mut fixture = Fixture::holding(pending_export_of(AuditLogOf::Platform), 1);
        fixture.exports = Arc::new(FakeAuditExportStore::default());

        assert!(matches!(fixture.run(job), Err(AppError::NotFound(_))));
    }
}
