//! Whether this process may take traffic, asked of each dependency it
//! needs: the database, the message bus and the cache.
//!
//! An orchestrator asks before routing requests to a replica and again
//! while it runs, so a replica that lost its database stops being sent
//! requests it can only fail. Each dependency answers through its own
//! probe; the use case asking them all decides whether the process is
//! ready.

use std::fmt;

use async_trait::async_trait;

/// What one dependency answered when asked whether it can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// It answered as it should.
    Ready,
    /// It did not, for the reason given.
    NotReady(UnreadyReason),
}

/// Why a dependency is not ready, as the operator reads it in the logs.
///
/// Written by the probe from what went wrong, such as a refused connection
/// or a timed-out ping. It never reaches a caller of the readiness
/// endpoint, and a probe keeps credentials and addresses out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadyReason(String);

impl UnreadyReason {
    /// The reason `text` says.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The reason as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnreadyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Dyn-safe port asking one dependency whether it can serve.
///
/// Infallible by type: a probe that cannot reach its dependency answers
/// [`Readiness::NotReady`] rather than failing, so no error is mistaken for
/// readiness. Each probe bounds its own wait, a second or two, and answers
/// not ready when it runs out: a hung dependency must not hang the check.
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    /// Whether the dependency answers now.
    async fn check(&self) -> Readiness;
}
