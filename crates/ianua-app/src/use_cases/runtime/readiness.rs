//! Check readiness: whether this process may take traffic, from what its
//! database, message bus and cache answer.
//!
//! Anyone may ask, signed in or not: an orchestrator's probe carries no
//! credentials. So the answer is only up or down. Which dependency failed,
//! and why, goes to the operator's logs and never to the caller, since it
//! would map the deployment for a stranger.

use std::sync::Arc;

use futures_util::future::join3;

use crate::ports::runtime::{Readiness, ReadinessProbe, UnreadyReason};
use crate::use_case::Query;

/// Whether the process may take traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceReadiness {
    /// Every dependency answered as it should.
    Ready,
    /// At least one did not.
    NotReady,
}

/// The ports [`CheckReadinessUseCase`] needs: one probe per dependency.
#[derive(ianua_macros::Fakes)]
pub struct CheckReadinessPorts {
    /// Asks the database.
    pub database: Arc<dyn ReadinessProbe>,
    /// Asks the message bus.
    pub message_bus: Arc<dyn ReadinessProbe>,
    /// Asks the cache.
    pub cache: Arc<dyn ReadinessProbe>,
}

/// Says whether the process may take traffic.
pub struct CheckReadinessUseCase {
    ports: CheckReadinessPorts,
}

impl CheckReadinessUseCase {
    /// A use case asking through `ports`.
    #[must_use]
    pub fn new(ports: CheckReadinessPorts) -> Self {
        Self { ports }
    }
}

impl Query for CheckReadinessUseCase {
    type Caller = ();
    type Input = ();
    type Output = ServiceReadiness;

    /// Asks every dependency at once and answers ready only when each one
    /// is. Each one that is not is logged with its reason; the answer
    /// carries neither.
    async fn execute(&self, (): &(), (): ()) -> ServiceReadiness {
        let (database, message_bus, cache) = join3(
            self.ports.database.check(),
            self.ports.message_bus.check(),
            self.ports.cache.check(),
        )
        .await;
        let unready = unready_dependencies([
            ("database", database),
            ("message bus", message_bus),
            ("cache", cache),
        ]);
        for (dependency, reason) in &unready {
            tracing::warn!(dependency, %reason, "a dependency is not ready");
        }
        readiness_of(&unready)
    }
}

/// The dependencies of `answers` that are not ready, with why.
fn unready_dependencies(
    answers: [(&'static str, Readiness); 3],
) -> Vec<(&'static str, UnreadyReason)> {
    answers
        .into_iter()
        .filter_map(|(dependency, answer)| match answer {
            Readiness::Ready => None,
            Readiness::NotReady(reason) => Some((dependency, reason)),
        })
        .collect()
}

/// Ready when no dependency is unready.
fn readiness_of(unready: &[(&'static str, UnreadyReason)]) -> ServiceReadiness {
    if unready.is_empty() {
        return ServiceReadiness::Ready;
    }
    ServiceReadiness::NotReady
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeReadinessProbe, block_on};

    /// What the process answers with `ports` behind it.
    fn check(ports: CheckReadinessPorts) -> ServiceReadiness {
        block_on(CheckReadinessUseCase::new(ports).execute(&(), ()))
    }

    /// The database, the message bus and the cache all answer. The process
    /// takes traffic.
    #[test]
    fn every_dependency_answering_is_ready() {
        let readiness = check(CheckReadinessPorts::fakes());

        assert_eq!(readiness, ServiceReadiness::Ready);
    }

    /// A refused database connection makes the process report not ready.
    #[test]
    fn a_database_that_does_not_answer_is_not_ready() {
        let readiness = check(CheckReadinessPorts {
            database: Arc::new(FakeReadinessProbe::not_ready("connection refused")),
            ..CheckReadinessPorts::fakes()
        });

        assert_eq!(readiness, ServiceReadiness::NotReady);
    }

    /// An unreachable message bus makes the process report not ready.
    #[test]
    fn a_message_bus_that_does_not_answer_is_not_ready() {
        let readiness = check(CheckReadinessPorts {
            message_bus: Arc::new(FakeReadinessProbe::not_ready("no route to host")),
            ..CheckReadinessPorts::fakes()
        });

        assert_eq!(readiness, ServiceReadiness::NotReady);
    }

    /// A timed-out cache probe prevents the process from reporting ready.
    #[test]
    fn a_cache_that_does_not_answer_is_not_ready() {
        let readiness = check(CheckReadinessPorts {
            cache: Arc::new(FakeReadinessProbe::not_ready("ping timed out")),
            ..CheckReadinessPorts::fakes()
        });

        assert_eq!(readiness, ServiceReadiness::NotReady);
    }
}
