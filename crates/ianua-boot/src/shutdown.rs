//! The one stop signal and the tasks it stops.
//!
//! Every task a process spawns goes through [`Shutdown`], so a stop
//! reaches all of them and the process waits for each. A stop comes from
//! SIGTERM or Ctrl-C, or from a task the process cannot run without ending
//! on its own. Listeners stop taking new requests and finish the ones in
//! flight, loops finish the job in hand, and the process waits for them
//! for the grace period, then ends whatever is left.

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tokio_util::task::TaskTracker;

/// Why the process did not stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// The stop signal could not be listened for.
    #[error("the stop signal could not be listened for")]
    Signal(#[source] std::io::Error),
    /// Tasks were still running when the grace period ended.
    #[error("{running} tasks were still running when the {grace:?} grace period ended")]
    Unfinished {
        /// How many.
        running: usize,
        /// The grace period they had.
        grace: Duration,
    },
}

/// The stop signal and the tasks it stops.
#[derive(Debug, Clone)]
pub struct Shutdown {
    stop: CancellationToken,
    tasks: TaskTracker,
    grace: Duration,
}

impl Shutdown {
    /// A stop that waits `grace` for the tasks it stops.
    #[must_use]
    pub fn new(grace: Duration) -> Self {
        Self {
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            grace,
        }
    }

    /// Stops on SIGTERM or Ctrl-C, from now on.
    ///
    /// # Errors
    ///
    /// [`ShutdownError::Signal`] when SIGTERM cannot be listened for.
    pub fn stop_on_signals(&self) -> Result<(), ShutdownError> {
        let terminated = terminated().map_err(ShutdownError::Signal)?;
        let stop = self.stop.clone();
        self.spawn_until_stopped(async move {
            tokio::select! {
                () = wait_for_interrupt() => tracing::info!("interrupted; stopping"),
                () = terminated => tracing::info!("told to terminate; stopping"),
            }
            stop.cancel();
        });
        Ok(())
    }

    /// Asks every task to stop.
    pub fn stop(&self) {
        self.stop.cancel();
    }

    /// Whether a stop was asked for.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stop.is_cancelled()
    }

    /// Done once a stop is asked for, for a listener's graceful shutdown or
    /// a loop's `select!`.
    pub fn stopping(&self) -> WaitForCancellationFutureOwned {
        self.stop.clone().cancelled_owned()
    }

    /// Runs `task`, which must end once [`stopping`](Self::stopping) is
    /// done, and is waited for. A task that ends before a stop was asked
    /// for is one the process cannot run without, so its end stops every
    /// other task too; `name` says which in the log.
    pub fn spawn<F>(&self, name: &'static str, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let stop = self.stop.clone();
        self.tasks.spawn(async move {
            task.await;
            if stop.is_cancelled() {
                return;
            }
            tracing::error!(task = name, "a task the process needs ended; stopping");
            stop.cancel();
        });
    }

    /// Runs `task` until a stop is asked for, and drops it then: for a
    /// loop with nothing to finish, such as a follower.
    pub fn spawn_until_stopped<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let stop = self.stop.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                () = task => {}
            }
        });
    }

    /// Waits for every task to end once the stop was asked for, for at
    /// most the grace period. Spawning after this has begun is refused by
    /// nothing, but is not waited for.
    ///
    /// # Errors
    ///
    /// [`ShutdownError::Unfinished`] when tasks are still running at the
    /// end of the grace period; the process ends them as it exits.
    pub async fn join(&self) -> Result<(), ShutdownError> {
        self.stop.cancelled().await;
        self.tasks.close();
        if tokio::time::timeout(self.grace, self.tasks.wait())
            .await
            .is_ok()
        {
            return Ok(());
        }
        Err(ShutdownError::Unfinished {
            running: self.tasks.len(),
            grace: self.grace,
        })
    }
}

/// Done at Ctrl-C. When it cannot be listened for, never done: SIGTERM
/// still stops the process.
async fn wait_for_interrupt() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "Ctrl-C cannot be listened for");
        std::future::pending::<()>().await;
    }
}

/// Done at SIGTERM, listened for from now on.
#[cfg(unix)]
fn terminated() -> std::io::Result<impl Future<Output = ()> + Send> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        signal.recv().await;
    })
}

/// Never done: there is no SIGTERM off Unix.
#[cfg(not(unix))]
fn terminated() -> std::io::Result<impl Future<Output = ()> + Send> {
    Ok(std::future::pending::<()>())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    /// Cancellation completes an existing waiter and marks the shared signal as stopping.
    #[tokio::test]
    async fn a_stop_reaches_whoever_waits_for_it() {
        let shutdown = Shutdown::new(SHORT);
        let stopping = shutdown.stopping();

        shutdown.stop();

        assert!(tokio::time::timeout(SHORT, stopping).await.is_ok());
        assert!(shutdown.is_stopping());
    }

    /// Shutdown waits for an existing task to finish its work after the
    /// stop signal before joining successfully.
    #[tokio::test]
    async fn a_task_finishing_after_the_stop_is_waited_for() {
        let shutdown = Shutdown::new(Duration::from_secs(2));
        let finished = Arc::new(AtomicBool::new(false));
        let stopping = shutdown.stopping();
        let flag = Arc::clone(&finished);
        shutdown.spawn("listener", async move {
            stopping.await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag.store(true, Ordering::SeqCst);
        });

        shutdown.stop();
        let joined = shutdown.join().await;

        assert!(joined.is_ok());
        assert!(finished.load(Ordering::SeqCst));
    }

    /// A task that ignores shutdown produces an unfinished-task error
    /// after the grace period, including the number still running.
    #[tokio::test]
    async fn a_task_ignoring_the_stop_is_given_up_after_the_grace() {
        let shutdown = Shutdown::new(Duration::from_millis(50));
        shutdown.spawn("hung", std::future::pending());

        shutdown.stop();
        let joined = shutdown.join().await;

        assert!(matches!(
            joined,
            Err(ShutdownError::Unfinished { running: 1, .. })
        ));
    }

    /// A loop spawned until the stop is dropped at the stop.
    #[tokio::test]
    async fn a_loop_spawned_until_the_stop_is_dropped_at_it() {
        let shutdown = Shutdown::new(SHORT);
        shutdown.spawn_until_stopped(std::future::pending());

        shutdown.stop();

        assert!(shutdown.join().await.is_ok());
    }

    /// A required task ending on its own triggers shutdown, and the
    /// remaining cancellation-bound task joins successfully.
    #[tokio::test]
    async fn a_needed_task_ending_on_its_own_stops_the_rest() {
        let shutdown = Shutdown::new(SHORT);
        shutdown.spawn_until_stopped(std::future::pending());

        shutdown.spawn("listener", async {});

        assert!(
            tokio::time::timeout(SHORT, shutdown.stopping())
                .await
                .is_ok()
        );
        assert!(shutdown.join().await.is_ok());
    }

    /// The join waits for the stop before it waits for the tasks.
    #[tokio::test]
    async fn the_join_waits_for_the_stop() {
        let shutdown = Shutdown::new(SHORT);

        let joined = tokio::time::timeout(Duration::from_millis(50), shutdown.join()).await;

        assert!(joined.is_err());
    }
}
