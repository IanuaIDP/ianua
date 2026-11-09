//! Apps that never answer: one that holds every request open, as a backend
//! stuck on a lock does, and one that drops every connection, as a backend
//! crashing on each request does. Each counts the connections it took, so a
//! scenario can say a request reached it.

use std::io;
use std::time::Duration;

use super::serving::{Listening, Record};

/// How long the hanging app holds a connection: far past any timeout the
/// gateway may set, so only the gateway ends the wait.
const HELD_FOR: Duration = Duration::from_secs(3600);

/// An app that takes every connection and never answers.
pub struct Hanging {
    listening: Listening,
    taken: Record<()>,
}

impl std::fmt::Debug for Hanging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hanging")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl Hanging {
    /// The app, listening on a port of loopback until dropped.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start() -> io::Result<Self> {
        let taken = Record::default();
        let counting = taken.clone();
        let listening = Listening::open(move |stream| {
            let counting = counting.clone();
            async move {
                counting.keep(());
                tokio::time::sleep(HELD_FOR).await;
                drop(stream);
            }
        })
        .await?;
        Ok(Self { listening, taken })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// How many connections reached it.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.taken.all().len()
    }
}

/// An app that drops every connection without answering.
pub struct Failing {
    listening: Listening,
    taken: Record<()>,
}

impl std::fmt::Debug for Failing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Failing")
            .field("address", &self.listening.address())
            .finish_non_exhaustive()
    }
}

impl Failing {
    /// The app, listening on a port of loopback until dropped.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start() -> io::Result<Self> {
        let taken = Record::default();
        let counting = taken.clone();
        let listening = Listening::open(move |stream| {
            counting.keep(());
            drop(stream);
            async {}
        })
        .await?;
        Ok(Self { listening, taken })
    }

    /// The address a service names to reach it.
    #[must_use]
    pub fn url(&self) -> String {
        self.listening.url()
    }

    /// How many connections reached it.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.taken.all().len()
    }
}
