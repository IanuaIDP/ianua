//! Noting that a connector's link is open: once when it opens, then every
//! few minutes while it stays open, so the dashboard can say when each
//! connector was last seen. A failed or timed-out sighting is logged and
//! dropped; the link carries on, since a sighting decides nothing.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::routing::ConnectorSightings;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::causes;
use ianua_domain::types::{ConnectorId, TenantId};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

/// The longest one note may take.
const NOTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Which link to note, where, and how often.
pub(super) struct Sighting {
    /// Where sightings are noted.
    pub(super) sightings: Arc<dyn ConnectorSightings>,
    /// The tenant the link's certificate names.
    pub(super) tenant: TenantId,
    /// The connector it names.
    pub(super) connector: ConnectorId,
    /// How often an open link is noted again.
    pub(super) every: Duration,
}

impl Sighting {
    /// Notes the link now and every `every` after, until `closed` fires.
    pub(super) async fn note_while_open(self, closed: CancellationToken) {
        let mut ticks = tokio::time::interval(self.every);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = closed.cancelled() => return,
                _ = ticks.tick() => self.note().await,
            }
        }
    }

    /// Notes the link once.
    async fn note(&self) {
        let tenant = ScopedTenant::from_connector_certificate(self.tenant);
        let noted = tokio::time::timeout(
            NOTE_TIMEOUT,
            self.sightings
                .record(&tenant, &self.connector, clock::now()),
        )
        .await;
        match noted {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(
                tenant = %self.tenant,
                connector = %self.connector,
                error = %causes(&error),
                "a connector's sighting could not be noted"
            ),
            Err(_) => tracing::warn!(
                tenant = %self.tenant,
                connector = %self.connector,
                "noting a connector's sighting took too long"
            ),
        }
    }
}
