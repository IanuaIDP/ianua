//! One Postgres call over a connection the platform opened: sign in with
//! the stream route's login, run the statement in a transaction held to a
//! time limit inside the database, and hand back what it gave.
//!
//! A query's transaction is read-only, so Postgres refuses a write however
//! the statement is written, and is rolled back once its rows are read. An
//! execute's transaction is committed only when the statement succeeded.
//! The connection's task ends with the call either way.

use std::time::Duration;

use futures_util::StreamExt as _;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::{failed, flow_of};
use ianua_integration::arguments::{optional_text, optional_values, required_text};
use ianua_integration::data::{DataLogin, Through, row_limit};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Transaction};

use crate::tls::{PostgresTls, Raw};
use crate::values::{bound, row_values};

/// The name each connection tells the database, so its owner can tell a
/// workflow's sessions apart.
const APPLICATION_NAME: &str = "ianua-workflow";

/// What a call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Reads rows, in a read-only transaction.
    Query,
    /// Changes the database, in a transaction committed on success.
    Execute,
}

impl Kind {
    /// The operation `name` names, if any.
    pub(crate) fn of(name: &str) -> Option<Self> {
        match name {
            "query" => Some(Self::Query),
            "execute" => Some(Self::Execute),
            _ => None,
        }
    }

    /// The operation's name.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Execute => "execute",
        }
    }
}

/// What one call is held to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// The longest one statement may run, set inside the database.
    pub(crate) statement_timeout: Duration,
    /// The most rows a query hands back.
    pub(crate) most_rows: u32,
    /// The data class the rows a query reads are counted as.
    pub(crate) ceiling: DataClassLevel,
}

/// The connection's task, ended when the call is done with it.
struct Session {
    client: Client,
    connection: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

/// How `kind`, with `arguments`, went over `through`, held to `limits`.
pub(crate) async fn run(
    kind: Kind,
    arguments: &FlowData,
    through: Through,
    limits: Limits,
) -> ActionOutcome {
    let inputs = match Inputs::read(arguments, limits.most_rows) {
        Ok(inputs) => inputs,
        Err(refused) => return refused,
    };
    let mut session = match signed_in(&through, inputs.database).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let call = Call {
        statement: inputs.statement,
        parameters: &inputs.parameters,
        row_limit: inputs.row_limit,
        limits,
    };
    match kind {
        Kind::Query => call.query(&mut session.client).await,
        Kind::Execute => call.execute(&mut session.client).await,
    }
}

/// Validated statement arguments, read before opening a database connection.
struct Inputs<'a> {
    statement: &'a str,
    parameters: Value,
    database: Option<String>,
    row_limit: u32,
}

impl<'a> Inputs<'a> {
    /// Reads inputs in request order and bounds the requested result size.
    fn read(arguments: &'a FlowData, most_rows: u32) -> Result<Self, ActionOutcome> {
        let statement = required_text(arguments, "statement")?;
        let parameters = optional_values(arguments, "parameters")?.unwrap_or(Value::Null);
        let database = optional_text(arguments, "database")?.map(str::to_owned);
        let row_limit = row_limit(arguments, most_rows)?;
        Ok(Self {
            statement,
            parameters,
            database,
            row_limit,
        })
    }
}

/// A session signed in over a new connection with the route's login, to
/// `database` or the login's own, inside TLS when the login asks for it.
async fn signed_in(through: &Through, database: Option<String>) -> Result<Session, ActionOutcome> {
    let unreachable = |_| failed("the database could not be reached through the gateway");
    let tls = through
        .tls()
        .map_err(|_| failed("the database's TLS settings do not read"))?;
    let connection = through.connection().await.map_err(unreachable)?;
    let mut config = config_for(&through.login, database.as_deref());
    let tls = PostgresTls(tls);
    config.ssl_mode(tls.ssl_mode());
    let (client, connection) = config
        .connect_raw(Raw(connection), tls)
        .await
        .map_err(|_| {
            failed("the database refused the sign-in, or did not serve the TLS its login asks for")
        })?;
    let connection = tokio::spawn(async move {
        drop(connection.await);
    });
    Ok(Session { client, connection })
}

/// The settings signing in as `login` to `database` or the login's own.
fn config_for(login: &DataLogin, database: Option<&str>) -> tokio_postgres::Config {
    let mut config = tokio_postgres::Config::new();
    config
        .user(&login.user)
        .password(login.password.expose())
        .dbname(database.unwrap_or(&login.user))
        .application_name(APPLICATION_NAME);
    config
}

/// One statement, its values and limits.
struct Call<'a> {
    statement: &'a str,
    parameters: &'a Value,
    row_limit: u32,
    limits: Limits,
}

impl Call<'_> {
    /// The rows the statement reads, in a read-only transaction rolled back
    /// once they are read.
    async fn query(&self, client: &mut Client) -> ActionOutcome {
        let Ok(transaction) = client.build_transaction().read_only(true).start().await else {
            return failed("the database did not start a read-only transaction");
        };
        let read = self.rows(&transaction).await;
        drop(transaction.rollback().await);
        match read {
            Ok(output) => match flow_of(&output) {
                Ok(output) => ActionOutcome::Succeeded {
                    output,
                    exposure: self.limits.ceiling,
                },
                Err(_) => failed(
                    "the rows are larger than workflow data may be, or a column needs a name a workflow can hold: give it one with AS",
                ),
            },
            Err(refused) => refused,
        }
    }

    /// The rows the statement reads in `transaction`, at most the row
    /// limit, streamed so no more than one row past it is ever read.
    async fn rows(&self, transaction: &Transaction<'_>) -> Result<Value, ActionOutcome> {
        self.set_timeout(transaction).await?;
        let prepared = transaction
            .prepare(self.statement)
            .await
            .map_err(|error| refused_by_database(&error))?;
        let values = bound(self.parameters, prepared.params())?;
        let stream = transaction
            .query_raw(&prepared, values.as_params())
            .await
            .map_err(|error| refused_by_database(&error))?;
        let most = usize::try_from(self.row_limit).unwrap_or(usize::MAX);
        let mut stream = std::pin::pin!(stream);
        let mut read = Vec::new();
        let mut truncated = false;
        while let Some(row) = stream.next().await {
            let row = row.map_err(|error| refused_by_database(&error))?;
            if read.len() == most {
                truncated = true;
                break;
            }
            read.push(Value::Object(row_values(&row)?));
        }
        Ok(json!({ "row_count": read.len(), "truncated": truncated, "rows": read }))
    }

    /// How many rows the statement changed, committed only on success.
    async fn execute(&self, client: &mut Client) -> ActionOutcome {
        let Ok(transaction) = client.transaction().await else {
            return failed("the database did not start a transaction");
        };
        let rows_affected = match self.changed(&transaction).await {
            Ok(rows_affected) => rows_affected,
            Err(refused) => {
                drop(transaction.rollback().await);
                return refused;
            }
        };
        if transaction.commit().await.is_err() {
            return failed("the database did not commit the change");
        }
        let output = json!({ "rows_affected": rows_affected });
        match flow_of(&output) {
            Ok(output) => ActionOutcome::Succeeded {
                output,
                exposure: self.limits.ceiling,
            },
            Err(_) => failed("the answer could not be held as workflow data"),
        }
    }

    /// The rows the statement changes in `transaction`.
    async fn changed(&self, transaction: &Transaction<'_>) -> Result<u64, ActionOutcome> {
        self.set_timeout(transaction).await?;
        let prepared = transaction
            .prepare(self.statement)
            .await
            .map_err(|error| refused_by_database(&error))?;
        let values = bound(self.parameters, prepared.params())?;
        transaction
            .execute_raw(&prepared, values.as_params())
            .await
            .map_err(|error| refused_by_database(&error))
    }

    /// Holds the transaction's statements to the time limit, inside the
    /// database, so a long one is stopped there and not merely left behind.
    async fn set_timeout(&self, transaction: &Transaction<'_>) -> Result<(), ActionOutcome> {
        let millis = self.limits.statement_timeout.as_millis().max(1);
        transaction
            .batch_execute(&format!("SET LOCAL statement_timeout = {millis}"))
            .await
            .map_err(|_| failed("the database did not take the time limit"))
    }
}

/// The failure of a statement the database refused, in its own words,
/// which name the statement's problem and never the login.
fn refused_by_database(error: &tokio_postgres::Error) -> ActionOutcome {
    let words = error.as_db_error().map_or_else(
        || "the database could not run the statement".to_owned(),
        |db| db.message().to_owned(),
    );
    failed(&format!("the database refused the statement: {words}"))
}
