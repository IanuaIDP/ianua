//! The cap on password hashes running at once on this node: a bounded
//! semaphore sized from the deployment's settings. A sign-in waits a short,
//! fixed bound for a place and is then answered busy, so no queue of
//! waiting sign-ins builds up behind it.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{HashPermit, HashingBusy, PasswordHashPermits};
use tokio::sync::Semaphore;

/// The places among the password hashes this node runs at once.
#[derive(Debug, Clone)]
pub struct LocalPasswordHashPermits {
    places: Arc<Semaphore>,
    wait: Duration,
}

impl LocalPasswordHashPermits {
    /// `places` hashes at once, each sign-in waiting at most `wait` for one.
    #[must_use]
    pub fn new(places: NonZeroUsize, wait: Duration) -> Self {
        Self {
            places: Arc::new(Semaphore::new(places.get())),
            wait,
        }
    }
}

#[async_trait]
impl PasswordHashPermits for LocalPasswordHashPermits {
    async fn take(&self) -> Result<HashPermit, HashingBusy> {
        let place = tokio::time::timeout(self.wait, Arc::clone(&self.places).acquire_owned())
            .await
            .map_err(|_| HashingBusy)?
            .map_err(|_| HashingBusy)?;
        Ok(HashPermit::new(place))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permits(places: usize) -> LocalPasswordHashPermits {
        LocalPasswordHashPermits::new(
            NonZeroUsize::new(places).unwrap(),
            Duration::from_millis(50),
        )
    }

    /// With both hashing permits held, a third acquisition returns busy.
    #[tokio::test]
    async fn a_full_node_answers_busy() {
        let permits = permits(2);
        let _first = permits.take().await.unwrap();
        let _second = permits.take().await.unwrap();

        let third = permits.take().await;

        assert_eq!(third.err(), Some(HashingBusy));
    }

    /// A place handed back by a finished hash is taken by the next sign-in.
    #[tokio::test]
    async fn a_place_handed_back_is_taken_again() {
        let permits = permits(1);
        let first = permits.take().await.unwrap();
        drop(first);

        let next = permits.take().await;

        assert!(next.is_ok());
    }
}
