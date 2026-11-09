//! Shared state on a cache server every node reaches: any server that
//! speaks the Redis wire protocol, such as Valkey, KeyDB or Redis.
//!
//! The protocol client is the only part of the crate that knows which
//! protocol is spoken. Every key is put under the deployment's
//! [`Namespace`] here, as `<namespace>:<key>`, so two deployments sharing
//! one server never read or count each other's entries. Every step a port
//! needs done at once is one command
//! or one script the server runs whole, so two nodes never see half of a
//! step. Every call is held to a deadline: a cache that hangs fails the
//! call, it never holds a request.

use std::time::Duration;

use async_trait::async_trait;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, Cmd, FromRedisValue, Script};

use crate::cache::state::{CacheError, LogCapacity, LogEntry, SharedState};
use crate::namespace::Namespace;

/// Maximum base reconnect delay in milliseconds, before the client's jitter.
/// Keeps a recovered cache from waiting minutes after a short network outage.
const RECONNECT_DELAY_MILLIS: u64 = 1_000;

/// Adds to a counter, and starts its window when this addition made it.
const COUNT: &str = r"
local count = redis.call('INCRBY', KEYS[1], ARGV[1])
if count == tonumber(ARGV[1]) then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return count
";

/// Takes from a live counter, never below zero, and keeps its lapse. A
/// counter that is not there answers nothing and is not made.
const LOWER: &str = r"
if redis.call('EXISTS', KEYS[1]) == 0 then
    return false
end
local count = redis.call('DECRBY', KEYS[1], ARGV[1])
if count < 0 then
    redis.call('SET', KEYS[1], 0, 'KEEPTTL')
    return 0
end
return count
";

/// Adds members to a set, starts its window when the set is new, and
/// answers how many it holds.
const ADD_DISTINCT: &str = r"
local before = redis.call('EXISTS', KEYS[1])
for i = 2, #ARGV do
    redis.call('SADD', KEYS[1], ARGV[i])
end
if before == 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return redis.call('SCARD', KEYS[1])
";

/// Adds an entry to a log, drops what came before the cut, and keeps the
/// log for its window past the newest entry.
const LOG: &str = r"
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 1
";

/// Drops what came before the cut from a bounded log, adds an entry it
/// already holds or one it has room for, and keeps the log for its window.
const ENROLL: &str = r"
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1])
local held = redis.call('ZSCORE', KEYS[1], ARGV[3])
if not held and redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then
    return 0
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 1
";

/// `duration` in whole milliseconds, at least one, as the protocol counts
/// expiries.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Shared state on a cache server, every key under one namespace.
#[derive(Clone)]
pub struct ServerState {
    connection: ConnectionManager,
    namespace: Namespace,
    deadline: Duration,
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("namespace", &self.namespace)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ServerState {
    /// State on the server at `url`, every key under `namespace`, each
    /// call and connection attempt held to `deadline`. Reconnect delays are
    /// bounded so short outages cannot leave readiness unavailable for minutes.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the server cannot be reached in time.
    pub async fn connect(
        url: &str,
        namespace: &Namespace,
        deadline: Duration,
    ) -> Result<Self, CacheError> {
        let client = Client::open(url).map_err(|error| CacheError::Unreachable(Box::new(error)))?;
        let config = ConnectionManagerConfig::new()
            .set_factor(2)
            .set_max_delay(RECONNECT_DELAY_MILLIS)
            .set_connection_timeout(deadline)
            .set_response_timeout(deadline);
        let connection =
            tokio::time::timeout(deadline, client.get_connection_manager_with_config(config))
                .await
                .map_err(|_| CacheError::TimedOut)?
                .map_err(|error| CacheError::Unreachable(Box::new(error)))?;
        Ok(Self {
            connection,
            namespace: namespace.clone(),
            deadline,
        })
    }

    async fn run<T: FromRedisValue>(&self, command: &Cmd) -> Result<T, CacheError> {
        let mut connection = self.connection.clone();
        tokio::time::timeout(self.deadline, command.query_async::<T>(&mut connection))
            .await
            .map_err(|_| CacheError::TimedOut)?
            .map_err(|error| CacheError::Unreachable(Box::new(error)))
    }

    async fn script<T: FromRedisValue>(
        &self,
        source: &str,
        key: &str,
        args: &[String],
    ) -> Result<T, CacheError> {
        let script = Script::new(source);
        let mut invocation = script.key(self.namespace.key(key));
        for arg in args {
            invocation.arg(arg);
        }
        let mut connection = self.connection.clone();
        tokio::time::timeout(self.deadline, invocation.invoke_async::<T>(&mut connection))
            .await
            .map_err(|_| CacheError::TimedOut)?
            .map_err(|error| CacheError::Unreachable(Box::new(error)))
    }
}

#[async_trait]
impl SharedState for ServerState {
    async fn count(&self, key: &str, delta: u64, window: Duration) -> Result<u64, CacheError> {
        self.script(COUNT, key, &[delta.to_string(), millis(window).to_string()])
            .await
    }

    async fn read(&self, key: &str) -> Result<Option<u64>, CacheError> {
        self.run(redis::cmd("GET").arg(self.namespace.key(key)))
            .await
    }

    async fn lower(&self, key: &str, by: u64) -> Result<Option<u64>, CacheError> {
        self.script(LOWER, key, &[by.to_string()]).await
    }

    async fn hold(&self, key: &str, ttl: Duration) -> Result<(), CacheError> {
        let _: Option<String> = self
            .run(
                redis::cmd("SET")
                    .arg(self.namespace.key(key))
                    .arg(1)
                    .arg("PX")
                    .arg(millis(ttl)),
            )
            .await?;
        Ok(())
    }

    async fn add_distinct(
        &self,
        key: &str,
        members: &[String],
        window: Duration,
    ) -> Result<u64, CacheError> {
        let args: Vec<String> = std::iter::once(millis(window).to_string())
            .chain(members.iter().cloned())
            .collect();
        self.script(ADD_DISTINCT, key, &args).await
    }

    async fn distinct(&self, key: &str) -> Result<u64, CacheError> {
        self.run(redis::cmd("SCARD").arg(self.namespace.key(key)))
            .await
    }

    async fn claim_once(&self, key: &str, ttl: Duration) -> Result<bool, CacheError> {
        let set: Option<String> = self
            .run(
                redis::cmd("SET")
                    .arg(self.namespace.key(key))
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(millis(ttl)),
            )
            .await?;
        Ok(set.is_some())
    }

    async fn swap(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> Result<Option<String>, CacheError> {
        self.run(
            redis::cmd("SET")
                .arg(self.namespace.key(key))
                .arg(value)
                .arg("PX")
                .arg(millis(ttl))
                .arg("GET"),
        )
        .await
    }

    async fn keep(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        let _: Option<String> = self
            .run(
                redis::cmd("SET")
                    .arg(self.namespace.key(key))
                    .arg(value)
                    .arg("PX")
                    .arg(millis(ttl)),
            )
            .await?;
        Ok(())
    }

    async fn text(&self, key: &str) -> Result<Option<String>, CacheError> {
        self.run(redis::cmd("GET").arg(self.namespace.key(key)))
            .await
    }

    async fn forget(&self, key: &str) -> Result<(), CacheError> {
        let _: i64 = self
            .run(redis::cmd("DEL").arg(self.namespace.key(key)))
            .await?;
        Ok(())
    }

    async fn log(&self, key: &str, entry: &LogEntry<'_>, keep: Duration) -> Result<(), CacheError> {
        let args = [
            entry.forget_before.to_string(),
            entry.at.to_string(),
            entry.text.to_owned(),
            millis(keep).to_string(),
        ];
        let _: i64 = self.script(LOG, key, &args).await?;
        Ok(())
    }

    async fn log_since(&self, key: &str, since: i64) -> Result<Vec<String>, CacheError> {
        self.run(
            redis::cmd("ZRANGEBYSCORE")
                .arg(self.namespace.key(key))
                .arg(since)
                .arg("+inf"),
        )
        .await
    }

    async fn enroll(
        &self,
        key: &str,
        entry: &LogEntry<'_>,
        capacity: LogCapacity,
    ) -> Result<bool, CacheError> {
        let args = [
            entry.forget_before.to_string(),
            entry.at.to_string(),
            entry.text.to_owned(),
            capacity.entries.to_string(),
            millis(capacity.keep).to_string(),
        ];
        let enrolled: i64 = self.script(ENROLL, key, &args).await?;
        Ok(enrolled == 1)
    }

    async fn ping(&self) -> Result<(), CacheError> {
        let _: String = self.run(&redis::cmd("PING")).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::cache::{test_server, test_server_in};

    /// A roster entry with an explicit timestamp and expiry cutoff.
    fn entry(text: &str, at: i64, forget_before: i64) -> LogEntry<'_> {
        LogEntry {
            text,
            at,
            forget_before,
        }
    }

    /// Room for two roster entries, retained for one minute.
    fn roster_capacity() -> LogCapacity {
        LogCapacity {
            entries: 2,
            keep: Duration::from_secs(60),
        }
    }

    /// The server answers a ping, which the readiness probe asks.
    #[tokio::test]
    async fn the_server_answers_a_ping() {
        let state = test_server().await;

        let answered = state.ping().await;

        assert!(answered.is_ok());
    }

    /// A counter on the server counts within its window, set atomically
    /// with its lapse, and starts again after it.
    #[tokio::test]
    async fn a_counter_counts_within_its_window() {
        let state = test_server().await;
        let key = format!("test:count:{}", uuid::Uuid::now_v7());

        state
            .count(&key, 1, Duration::from_millis(200))
            .await
            .unwrap();
        let second = state
            .count(&key, 2, Duration::from_millis(200))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = state
            .count(&key, 1, Duration::from_millis(200))
            .await
            .unwrap();

        assert_eq!(second, 3);
        assert_eq!(after, 1);
    }

    /// Exactly one of two concurrent claims for the same nonce succeeds on the cache server.
    #[tokio::test]
    async fn a_claim_raced_by_two_is_won_once() {
        let state = test_server().await;
        let key = format!("test:claim:{}", uuid::Uuid::now_v7());

        let (first, second) = tokio::join!(
            state.claim_once(&key, Duration::from_secs(60)),
            state.claim_once(&key, Duration::from_secs(60))
        );

        assert_ne!(first.unwrap(), second.unwrap());
    }

    /// Distinct members are counted once each, from every caller.
    #[tokio::test]
    async fn distinct_members_are_counted_once() {
        let state = test_server().await;
        let key = format!("test:distinct:{}", uuid::Uuid::now_v7());
        let members = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };

        state
            .add_distinct(&key, &members(&["/a", "/b"]), Duration::from_secs(60))
            .await
            .unwrap();
        let total = state
            .add_distinct(&key, &members(&["/b", "/c"]), Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(total, 3);
    }

    /// A forgotten counter on the server starts again at its next count,
    /// and forgetting a key nothing holds is no error.
    #[tokio::test]
    async fn a_forgotten_counter_starts_again() {
        let state = test_server().await;
        let key = format!("test:forget:{}", uuid::Uuid::now_v7());
        state.count(&key, 3, Duration::from_secs(60)).await.unwrap();

        state.forget(&key).await.unwrap();
        state.forget(&format!("{key}:never")).await.unwrap();
        let again = state.count(&key, 1, Duration::from_secs(60)).await.unwrap();

        assert_eq!(again, 1);
    }

    /// A counter on the server is lowered while it counts, never below
    /// zero, and a counter that lapsed is not started by lowering it.
    #[tokio::test]
    async fn a_counter_is_lowered_only_while_it_counts() {
        let state = test_server().await;
        let key = format!("test:lower:{}", uuid::Uuid::now_v7());
        let gone = format!("{key}:gone");
        state.count(&key, 5, Duration::from_secs(60)).await.unwrap();

        let lowered = state.lower(&key, 2).await.unwrap();
        let floored = state.lower(&key, 10).await.unwrap();
        let nothing = state.lower(&gone, 1).await.unwrap();

        assert_eq!(lowered, Some(3));
        assert_eq!(floored, Some(0));
        assert_eq!(nothing, None);
        assert_eq!(state.read(&gone).await.unwrap(), None);
    }

    /// Renewing a server-backed hold keeps its value past the original expiry,
    /// then removes it after the renewed wait.
    #[tokio::test]
    async fn a_hold_restarts_its_wait() {
        let state = test_server().await;
        let key = format!("test:hold:{}", uuid::Uuid::now_v7());

        state.hold(&key, Duration::from_millis(200)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        state.hold(&key, Duration::from_millis(200)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        let held = state.read(&key).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let lapsed = state.read(&key).await.unwrap();

        assert_eq!(held, Some(1));
        assert_eq!(lapsed, None);
    }

    /// Text kept on the server reads back, without the value before being
    /// sent back.
    #[tokio::test]
    async fn kept_text_reads_back() {
        let state = test_server().await;
        let key = format!("test:keep:{}", uuid::Uuid::now_v7());

        state
            .keep(&key, "first", Duration::from_secs(60))
            .await
            .unwrap();
        state
            .keep(&key, "second", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(state.text(&key).await.unwrap().as_deref(), Some("second"));
    }

    /// A swap answers what was kept before.
    #[tokio::test]
    async fn a_swap_answers_the_value_before() {
        let state = test_server().await;
        let key = format!("test:swap:{}", uuid::Uuid::now_v7());

        let first = state
            .swap(&key, "normal", Duration::from_secs(60))
            .await
            .unwrap();
        let second = state
            .swap(&key, "high", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(first, None);
        assert_eq!(second.as_deref(), Some("normal"));
    }

    /// Text kept by a swap reads back from the server, and a key never
    /// written reads as nothing.
    #[tokio::test]
    async fn swapped_text_reads_back() {
        let state = test_server().await;
        let key = format!("test:text:{}", uuid::Uuid::now_v7());

        let before = state.text(&key).await.unwrap();
        state
            .swap(&key, "v1", Duration::from_secs(60))
            .await
            .unwrap();
        let after = state.text(&key).await.unwrap();

        assert_eq!(before, None);
        assert_eq!(after.as_deref(), Some("v1"));
    }

    /// A log answers its entries since a moment, oldest first, and forgets
    /// those before the cut.
    #[tokio::test]
    async fn a_log_answers_since_and_forgets_before() {
        let state = test_server().await;
        let key = format!("test:log:{}", uuid::Uuid::now_v7());
        let keep = Duration::from_secs(60);
        for (at, text) in [(10, "a"), (20, "b"), (30, "c")] {
            state
                .log(
                    &key,
                    &LogEntry {
                        text,
                        at,
                        forget_before: 15,
                    },
                    keep,
                )
                .await
                .unwrap();
        }

        let since = state.log_since(&key, 20).await.unwrap();

        assert_eq!(since, ["b", "c"]);
    }

    /// A full roster on the server takes no newcomer, keeps taking what it
    /// already holds, and takes a newcomer again once an entry lapses.
    #[tokio::test]
    async fn a_full_roster_takes_only_what_it_holds_until_one_lapses() {
        let state = test_server().await;
        let key = format!("test:roster:{}", uuid::Uuid::now_v7());
        let capacity = roster_capacity();
        state
            .enroll(&key, &entry("a", 10, 0), capacity)
            .await
            .unwrap();
        state
            .enroll(&key, &entry("b", 30, 0), capacity)
            .await
            .unwrap();

        let newcomer = state
            .enroll(&key, &entry("c", 30, 0), capacity)
            .await
            .unwrap();
        let again = state
            .enroll(&key, &entry("a", 40, 0), capacity)
            .await
            .unwrap();
        let after_lapse = state
            .enroll(&key, &entry("c", 50, 35), capacity)
            .await
            .unwrap();

        assert!(!newcomer);
        assert!(again);
        assert!(after_lapse);
        assert_eq!(state.log_since(&key, 0).await.unwrap(), ["a", "c"]);
    }

    /// A namespace no other test uses: `t` and the random end of a fresh
    /// id.
    fn fresh_namespace() -> Namespace {
        let id = uuid::Uuid::now_v7().simple().to_string();
        Namespace::new(&format!("t{}", &id[20..])).unwrap()
    }

    /// Counts, nonce claims and text values remain separate under two namespaces
    /// sharing one cache server.
    #[tokio::test]
    async fn two_namespaces_never_see_each_others_keys() {
        let ours = test_server_in(&fresh_namespace()).await;
        let theirs = test_server_in(&fresh_namespace()).await;
        let window = Duration::from_secs(60);

        theirs.count("rate:tenant:t1", 5, window).await.unwrap();
        theirs.claim_once("nonce:n1", window).await.unwrap();
        theirs
            .swap("sign-in-pressure:platform", "high", window)
            .await
            .unwrap();

        assert_eq!(ours.read("rate:tenant:t1").await.unwrap(), None);
        assert_eq!(ours.count("rate:tenant:t1", 1, window).await.unwrap(), 1);
        assert!(ours.claim_once("nonce:n1", window).await.unwrap());
        assert_eq!(ours.text("sign-in-pressure:platform").await.unwrap(), None);
        assert_eq!(theirs.read("rate:tenant:t1").await.unwrap(), Some(5));
    }

    /// The default namespace keeps a key where the platform always kept it,
    /// under `ianua:`.
    #[tokio::test]
    async fn the_default_namespace_keeps_keys_under_the_platform_prefix() {
        let state = test_server().await;
        let key = format!("test:prefix:{}", uuid::Uuid::now_v7());
        state
            .swap(&key, "kept", Duration::from_secs(60))
            .await
            .unwrap();

        let held: Option<String> = state
            .run(redis::cmd("GET").arg(format!("ianua:{key}")))
            .await
            .unwrap();

        assert_eq!(held.as_deref(), Some("kept"));
    }
}
