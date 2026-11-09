//! What the gateway's health checks last saw of each service's backends,
//! reported by the gateway and read by the API.
//!
//! The gateway probes every backend of a service that asks to be probed,
//! and marks each up or down by the service's thresholds. Each probe round
//! it reports what it holds now, the report good for a few probe intervals.
//! A report that is not renewed lapses, so a gateway that stopped probing,
//! or a service no longer probed, reads as unknown rather than as the last
//! thing it said.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpUrl, ServiceId};
use time::OffsetDateTime;

use crate::tenancy::ScopedTenant;

/// What a backend's health checks last concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendVerdict {
    /// It passed: it gets traffic.
    Up,
    /// It failed its checks in a row: it gets none until it passes again.
    Down,
}

/// One backend of a service and what its checks last concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealth {
    /// The backend, as the gateway dials it.
    pub backend: HttpUrl,
    /// The latest assessment of whether this backend can receive traffic.
    pub verdict: BackendVerdict,
}

/// What the gateway holds of one service's backends after a probe round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHealthReport {
    /// The backend pool assessed by this probe round.
    pub service_id: ServiceId,
    /// Each backend probed, and its verdict.
    pub backends: Vec<BackendHealth>,
    /// When the round ended.
    pub observed_at: OffsetDateTime,
}

/// Where the gateway reports what its health checks hold.
#[async_trait]
pub trait BackendHealthReports: Send + Sync {
    /// Keeps `report` for `tenant`'s service for `valid_for`, in place of
    /// the one before. Past that it lapses unless renewed.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when it cannot be kept. The
    /// gateway logs it and goes on probing: the report is for people, and
    /// routing never waits on it.
    async fn report(
        &self,
        tenant: &ScopedTenant,
        report: &ServiceHealthReport,
        valid_for: Duration,
    ) -> Result<(), DomainError>;
}

/// Where the API reads what the gateway's health checks hold.
#[async_trait]
pub trait BackendHealthReader: Send + Sync {
    /// The latest report on `tenant`'s `service`, or `None` when there is
    /// none still valid.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when it cannot be read.
    async fn latest(
        &self,
        tenant: &ScopedTenant,
        service: &ServiceId,
    ) -> Result<Option<ServiceHealthReport>, DomainError>;
}
