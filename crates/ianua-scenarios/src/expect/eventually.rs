//! Waiting for something the platform does later: asking again until it
//! is so, for a bounded time, never sleeping blind.

use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior};

/// How long [`eventually`] waits.
const PATIENCE: Duration = Duration::from_secs(20);

/// How often it asks again.
const ASK_EVERY: Duration = Duration::from_millis(100);

/// What `check` answers once it answers something, asking again every
/// tenth of a second for up to twenty seconds.
///
/// # Panics
///
/// When `check` answered nothing in that time, naming `what` was waited
/// for.
pub async fn eventually<T, F, Fut>(what: &str, check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    eventually_within(what, PATIENCE, check).await
}

/// What `check` answers once it answers something, asking again every
/// tenth of a second for up to `patience`.
///
/// # Panics
///
/// When `check` answered nothing in that time, naming `what` was waited
/// for.
pub async fn eventually_within<T, F, Fut>(what: &str, patience: Duration, check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let waiting = Waiting {
        patience,
        every: ASK_EVERY,
    };
    eventually_paced(what, waiting, check).await
}

/// How long to wait, and how often to ask meanwhile.
#[derive(Debug, Clone, Copy)]
pub struct Waiting {
    /// The longest the wait lasts.
    pub patience: Duration,
    /// How long between two asks: a check that calls the API asks no
    /// faster than a real client would, or the platform's own rate limit
    /// answers it.
    pub every: Duration,
}

/// What `check` answers once it answers something, asking as `waiting`
/// says.
///
/// # Panics
///
/// When `check` answered nothing in that time, naming `what` was waited
/// for.
pub async fn eventually_paced<T, F, Fut>(what: &str, waiting: Waiting, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = Instant::now() + waiting.patience;
    let mut asking = tokio::time::interval(waiting.every);
    asking.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        asking.tick().await;
        if let Some(found) = check().await {
            return found;
        }
        if Instant::now() >= deadline {
            panic!("gave up waiting for {what} after {:?}", waiting.patience);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// The answer comes once the check finds it.
    #[tokio::test]
    async fn the_answer_comes_once_the_check_finds_it() {
        let counter = AtomicU32::new(0);
        let asked = &counter;

        let found = eventually("the third ask", || async move {
            let count = asked.fetch_add(1, Ordering::SeqCst) + 1;
            (count == 3).then_some(count)
        })
        .await;

        assert_eq!(found, 3);
    }

    /// A check that never finds it fails, naming what was awaited.
    #[tokio::test]
    #[should_panic(expected = "gave up waiting for the mail")]
    async fn a_check_that_never_finds_it_fails_naming_it() {
        eventually_within("the mail", Duration::from_millis(250), || async {
            None::<()>
        })
        .await;
    }
}
