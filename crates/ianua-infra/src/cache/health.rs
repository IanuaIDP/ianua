//! What the gateway's health checks last saw of each service's backends,
//! kept on shared state for the API to read.
//!
//! One entry per tenant and service, replaced by each probe round and
//! lapsing with the window the gateway gives it, so a gateway that stops
//! probing leaves nothing behind that reads as healthy. With several
//! gateways, the entry holds whichever reported last.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::routing::{
    BackendHealth, BackendHealthReader, BackendHealthReports, BackendVerdict, ServiceHealthReport,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpUrl, ServiceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::cache::state::{SharedState, key};

/// Where the gateway files the health reports of every tenant's services,
/// on shared state.
pub struct CacheBackendHealthReports {
    state: Arc<dyn SharedState>,
}

impl CacheBackendHealthReports {
    /// The reports filed on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// Where the API reads the health reports the gateway filed, on shared
/// state.
pub struct CacheBackendHealthReader {
    state: Arc<dyn SharedState>,
}

impl CacheBackendHealthReader {
    /// The reports read from `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// The entry `tenant`'s `service` is reported under.
fn entry(tenant: &ScopedTenant, service: &ServiceId) -> String {
    key(&[
        "backend_health",
        &tenant.as_uuid().to_string(),
        &service.as_uuid().to_string(),
    ])
}

/// A report as the entry keeps it.
#[derive(Serialize, Deserialize)]
struct Kept {
    at: i64,
    backends: Vec<KeptBackend>,
}

#[derive(Serialize, Deserialize)]
struct KeptBackend {
    url: String,
    up: bool,
}

impl Kept {
    fn of(report: &ServiceHealthReport) -> Self {
        Self {
            at: report.observed_at.unix_timestamp(),
            backends: report
                .backends
                .iter()
                .map(|backend| KeptBackend {
                    url: backend.backend.as_str().to_owned(),
                    up: backend.verdict == BackendVerdict::Up,
                })
                .collect(),
        }
    }

    /// The report this entry keeps for `service`.
    fn into_report(self, service: ServiceId) -> Result<ServiceHealthReport, DomainError> {
        let unreadable = || DomainError::infra_msg("a backend health entry does not read");
        let backends = self
            .backends
            .into_iter()
            .map(|kept| {
                Ok(BackendHealth {
                    backend: HttpUrl::new(kept.url).map_err(|_| unreadable())?,
                    verdict: match kept.up {
                        true => BackendVerdict::Up,
                        false => BackendVerdict::Down,
                    },
                })
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        Ok(ServiceHealthReport {
            service_id: service,
            backends,
            observed_at: OffsetDateTime::from_unix_timestamp(self.at).map_err(|_| unreadable())?,
        })
    }
}

#[async_trait]
impl BackendHealthReports for CacheBackendHealthReports {
    async fn report(
        &self,
        tenant: &ScopedTenant,
        report: &ServiceHealthReport,
        valid_for: Duration,
    ) -> Result<(), DomainError> {
        let text = serde_json::to_string(&Kept::of(report)).map_err(DomainError::infra)?;
        self.state
            .swap(&entry(tenant, &report.service_id), &text, valid_for)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl BackendHealthReader for CacheBackendHealthReader {
    async fn latest(
        &self,
        tenant: &ScopedTenant,
        service: &ServiceId,
    ) -> Result<Option<ServiceHealthReport>, DomainError> {
        let Some(text) = self.state.text(&entry(tenant, service)).await? else {
            return Ok(None);
        };
        let kept: Kept = serde_json::from_str(&text).map_err(DomainError::infra)?;
        kept.into_report(*service).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::cache::MemoryState;

    struct Board {
        reports: CacheBackendHealthReports,
        reader: CacheBackendHealthReader,
    }

    fn board() -> Board {
        let state: Arc<dyn SharedState> = Arc::new(MemoryState::new(100));
        Board {
            reports: CacheBackendHealthReports::new(Arc::clone(&state)),
            reader: CacheBackendHealthReader::new(state),
        }
    }

    fn report(service: ServiceId) -> ServiceHealthReport {
        ServiceHealthReport {
            service_id: service,
            backends: vec![
                BackendHealth {
                    backend: HttpUrl::new("https://a.internal:8080").unwrap(),
                    verdict: BackendVerdict::Up,
                },
                BackendHealth {
                    backend: HttpUrl::new("https://b.internal:8080").unwrap(),
                    verdict: BackendVerdict::Down,
                },
            ],
            observed_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    /// The gateway reports one backend up and one down; the API reads the
    /// same back.
    #[tokio::test]
    async fn a_report_reads_back_as_it_was_made() {
        let board = board();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let service = ServiceId::new();

        board
            .reports
            .report(&tenant, &report(service), Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(
            board.reader.latest(&tenant, &service).await.unwrap(),
            Some(report(service))
        );
    }

    /// A health report disappears after its lifetime unless renewed.
    #[tokio::test]
    async fn a_report_not_renewed_lapses() {
        let board = board();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let service = ServiceId::new();

        board
            .reports
            .report(&tenant, &report(service), Duration::from_millis(20))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;

        assert_eq!(board.reader.latest(&tenant, &service).await.unwrap(), None);
    }

    /// Looking up a backend under another tenant returns no health report.
    #[tokio::test]
    async fn another_tenants_report_is_never_read() {
        let board = board();
        let acme = ScopedTenant::for_background(TenantId::new());
        let globex = ScopedTenant::for_background(TenantId::new());
        let service = ServiceId::new();

        board
            .reports
            .report(&acme, &report(service), Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(board.reader.latest(&globex, &service).await.unwrap(), None);
    }
}
