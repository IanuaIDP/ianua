//! One Redis call over a connection the platform opened: sign in with the
//! stream route's login, select the database, send the one command and
//! hand back what Redis answered.

use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::{failed, flow_of};
use ianua_integration::arguments::{argument, optional_values, required_count, required_text};
use ianua_integration::data::Through;
use redis::aio::MultiplexedConnection;
use redis::{ProtocolVersion, RedisConnectionInfo};
use serde_json::Value;

use crate::RedisSettings;
use crate::values::{answer_of, words_of};

/// What a call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Runs a command that only reads.
    Read,
    /// Runs any command the login may.
    Write,
}

impl Kind {
    /// The operation `name` names, if any.
    pub(crate) fn of(name: &str) -> Option<Self> {
        match name {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }

    /// The operation's name.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// The commands a `read` takes: each only reads, whatever its arguments.
const READING: &[&str] = &[
    "BITCOUNT",
    "BITPOS",
    "DBSIZE",
    "EXISTS",
    "GEODIST",
    "GEOHASH",
    "GEOPOS",
    "GEOSEARCH",
    "GET",
    "GETBIT",
    "GETRANGE",
    "HEXISTS",
    "HGET",
    "HGETALL",
    "HKEYS",
    "HLEN",
    "HMGET",
    "HRANDFIELD",
    "HSCAN",
    "HSTRLEN",
    "HVALS",
    "LINDEX",
    "LLEN",
    "LPOS",
    "LRANGE",
    "MGET",
    "PFCOUNT",
    "PTTL",
    "SCAN",
    "SCARD",
    "SDIFF",
    "SINTER",
    "SINTERCARD",
    "SISMEMBER",
    "SMEMBERS",
    "SMISMEMBER",
    "SRANDMEMBER",
    "SSCAN",
    "STRLEN",
    "SUNION",
    "TTL",
    "TYPE",
    "XLEN",
    "XRANGE",
    "XREVRANGE",
    "ZCARD",
    "ZCOUNT",
    "ZLEXCOUNT",
    "ZMSCORE",
    "ZRANDMEMBER",
    "ZRANGE",
    "ZRANGEBYLEX",
    "ZRANGEBYSCORE",
    "ZRANK",
    "ZREVRANGE",
    "ZREVRANK",
    "ZSCAN",
    "ZSCORE",
];

/// The commands neither operation takes: each changes the connection
/// itself, signing in again, switching database or protocol, or turning it
/// into a stream that never answers once.
const CHANGING_THE_CONNECTION: &[&str] = &[
    "AUTH",
    "CLIENT",
    "HELLO",
    "MONITOR",
    "MULTI",
    "PSUBSCRIBE",
    "PSYNC",
    "QUIT",
    "RESET",
    "SELECT",
    "SSUBSCRIBE",
    "SUBSCRIBE",
    "SYNC",
];

/// How `kind`, with `arguments`, went over `through`, held to `settings`.
pub(crate) async fn run(
    kind: Kind,
    arguments: &FlowData,
    through: &Through,
    settings: RedisSettings,
) -> ActionOutcome {
    let asked = match asked(kind, arguments) {
        Ok(asked) => asked,
        Err(refused) => return refused,
    };
    let (mut connection, driver) = match signed_in(through, &asked, settings).await {
        Ok(signed_in) => signed_in,
        Err(refused) => return refused,
    };
    let answer = asked.command().query_async(&mut connection).await;
    driver.abort();
    let answer = match answer {
        Ok(answer) => answer,
        Err(error) => return refused_by_redis(&error),
    };
    let output = answer_of(&answer).and_then(|result| {
        flow_of(&serde_json::json!({ "result": result }))
            .map_err(|_| failed("the answer is larger than workflow data may be"))
    });
    match output {
        Ok(output) => ActionOutcome::Succeeded {
            output,
            exposure: settings.ceiling,
        },
        Err(refused) => refused,
    }
}

/// The command a step asks for, its words and its database.
struct Asked {
    name: String,
    words: Vec<Vec<u8>>,
    database: i64,
}

impl Asked {
    /// The command as Redis takes it.
    fn command(&self) -> redis::Cmd {
        let mut command = redis::cmd(&self.name);
        for word in &self.words {
            command.arg(word.as_slice());
        }
        command
    }
}

/// What the step asks `kind` to run, refused when `kind` does not take it.
fn asked(kind: Kind, arguments: &FlowData) -> Result<Asked, ActionOutcome> {
    let name = required_text(arguments, "command")?
        .trim()
        .to_ascii_uppercase();
    ensure_taken(kind, &name)?;
    let words = words_of(&optional_values(arguments, "arguments")?.unwrap_or(Value::Null))?;
    let database = match argument(arguments, "database") {
        None => 0,
        Some(_) => i64::try_from(required_count(arguments, "database")?)
            .map_err(|_| failed("the database is not a Redis database number"))?,
    };
    Ok(Asked {
        name,
        words,
        database,
    })
}

/// Refuses a command `kind` does not take.
fn ensure_taken(kind: Kind, name: &str) -> Result<(), ActionOutcome> {
    if CHANGING_THE_CONNECTION.contains(&name) {
        return Err(failed(&format!(
            "{name} changes the connection itself, so no step runs it"
        )));
    }
    match kind {
        Kind::Read if !READING.contains(&name) => Err(failed(&format!(
            "{name} is not a command that only reads: run it as a write"
        ))),
        Kind::Read | Kind::Write => Ok(()),
    }
}

/// A connection signed in with the route's login to the step's database,
/// and the task driving it, to end when the call is done.
async fn signed_in(
    through: &Through,
    asked: &Asked,
    settings: RedisSettings,
) -> Result<(MultiplexedConnection, tokio::task::JoinHandle<()>), ActionOutcome> {
    let stream = through
        .protected_connection()
        .await
        .map_err(|_| failed("Redis could not be reached through the gateway, or its certificate is not the one its login asks for"))?;
    let info = RedisConnectionInfo {
        db: asked.database,
        username: Some(through.login.user.clone()),
        password: Some(through.login.password.expose().to_owned()),
        protocol: ProtocolVersion::RESP2,
    };
    let (connection, driver) = MultiplexedConnection::new_with_response_timeout(
        &info,
        stream,
        Some(settings.command_timeout),
    )
    .await
    .map_err(|_| failed("Redis refused the sign-in or the database"))?;
    Ok((connection, tokio::spawn(driver)))
}

/// The failure of a command Redis refused, in its own words, which name
/// the command's problem and never the login.
fn refused_by_redis(error: &redis::RedisError) -> ActionOutcome {
    let words = error
        .detail()
        .map_or_else(|| error.category().to_owned(), str::to_owned);
    failed(&format!("Redis refused the command: {words}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read takes a command that only reads.
    #[test]
    fn a_read_takes_a_reading_command() {
        assert!(ensure_taken(Kind::Read, "HGETALL").is_ok());
    }

    /// The command policy refuses DEL when the step declares a read.
    #[test]
    fn a_read_refuses_a_writing_command() {
        assert!(ensure_taken(Kind::Read, "DEL").is_err());
    }

    /// Both read and write command policies refuse AUTH.
    #[test]
    fn no_step_signs_in_again() {
        assert!(ensure_taken(Kind::Write, "AUTH").is_err());
        assert!(ensure_taken(Kind::Read, "AUTH").is_err());
    }

    /// The reading list is sorted, so a review sees each command once.
    #[test]
    fn the_command_lists_are_sorted() {
        assert!(READING.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            CHANGING_THE_CONNECTION
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
}
