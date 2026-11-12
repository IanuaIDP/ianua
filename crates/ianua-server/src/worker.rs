//! The worker: the job processor, the sweep scheduler, the outbox relay,
//! the drain of the gateway's inbox and the event consumers.
//!
//! Every part is safe to run on as many workers as the deployment has, and
//! to stop at any moment. Jobs are claimed under a lease, so a job is run
//! by one worker at a time and taken again once a worker that died lets
//! its lease run out; each round of a sweep is claimed once in the
//! database; the relay locks the records it publishes, and the bus keeps
//! one copy of a record published twice; the inbox drain locks the events
//! it takes and appends and removes them in one transaction; each consumer reads a share of
//! the events every worker takes part in, an event handed to one worker
//! at a time and handed again until one is done with it, and each job it
//! queues is keyed by the event and its target, so a second delivery
//! queues nothing twice. The store caches' and the tenant databases'
//! followers run on every node, through `Platform::follow`, not here.

mod consumers;
mod handlers;
mod inbox;
mod jobs;
mod parts;
mod relay;
mod sweeps;

use std::sync::Arc;

use ianua_boot::shutdown::Shutdown;
use ianua_infra::postgres::foundation::workers::announcements::Announcements;

use crate::config::Config;
use crate::error::ServerError;
use crate::listeners;
use crate::platform::Platform;
use crate::worker::parts::Parts;

/// Starts the worker's loops on the platform as the configuration says,
/// each spawned through the shutdown so a stop lets the work in hand
/// finish, and returns once they run. A worker running without the API
/// opens the internal listener too, for its probes and metrics.
///
/// # Errors
///
/// [`ServerError`] when a loop's adapters cannot be built, a job type the
/// app queues has no handler, a sweep of the app has no runner, or the
/// internal listener cannot be opened.
pub async fn run(
    platform: &Platform,
    config: &Config,
    shutdown: &Shutdown,
) -> Result<(), ServerError> {
    let parts = Parts::build(platform, config)?;
    let announcements = Arc::new(Announcements::new());
    shutdown
        .spawn_until_stopped(Arc::clone(&announcements).listen(Arc::clone(&platform.databases)));
    jobs::start(&parts, &announcements, shutdown)?;
    sweeps::start(&parts, shutdown)?;
    consumers::start(&parts, shutdown)?;
    relay::start(platform, config, &announcements, shutdown);
    inbox::start(platform, config, &announcements, shutdown);
    if !config.mode().runs_api() {
        listeners::serve_runtime(platform, config, shutdown).await?;
    }
    Ok(())
}
