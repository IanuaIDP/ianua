//! One MySQL call over connections the platform opens: sign in through the
//! door with the stream route's login, run the statement in a transaction
//! held to a time limit, and hand back what it gave.
//!
//! A query's transaction is read-only, so MySQL refuses a write however the
//! statement is written, and nothing it did is kept. An execute's
//! transaction is committed only when the statement succeeded. The
//! connection is closed with the call either way, and MySQL rolls back
//! whatever was not committed.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::{failed, flow_of};
use ianua_integration::arguments::{optional_text, optional_values, required_text};
use ianua_integration::data::{DataTls, DoorKind, Through, row_limit};
use mysql_async::prelude::Queryable as _;
use mysql_async::{Conn, OptsBuilder, SslOpts};
use serde_json::{Value, json};

use crate::values::{bound, row_values};

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
    /// The longest one query may run, set inside the database.
    pub(crate) statement_timeout: Duration,
    /// The most rows a query hands back.
    pub(crate) most_rows: u32,
    /// The data class the rows a query reads are counted as.
    pub(crate) ceiling: DataClassLevel,
}

/// How `kind`, with `arguments`, went over `through`, held to `limits`.
pub(crate) async fn run(
    kind: Kind,
    arguments: &FlowData,
    through: Through,
    limits: Limits,
) -> ActionOutcome {
    let call = match Call::asked(arguments, limits) {
        Ok(call) => call,
        Err(refused) => return refused,
    };
    let through = Arc::new(through);
    let Ok(door) = through.door(DoorKind::AsHanded).await else {
        return failed("the worker could not open its door to the database");
    };
    let options = options(&through, door.address().port(), call.database.clone());
    let Ok(mut connection) = Conn::new(options).await else {
        return failed(
            "the database refused the sign-in, could not be reached, or did not serve the TLS its login asks for",
        );
    };
    let outcome = match kind {
        Kind::Query => call.query(&mut connection).await,
        Kind::Execute => call.execute(&mut connection).await,
    };
    drop(connection.disconnect().await);
    outcome
}

/// The settings signing in through the door on `port` with the route's
/// login, to `database` or the login's default, inside TLS when the login
/// asks for it, never moving to a local socket.
fn options(through: &Through, port: u16, database: Option<String>) -> OptsBuilder {
    let options = OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .prefer_socket(false)
        .user(Some(through.login.user.clone()))
        .pass(Some(through.login.password.expose().to_owned()))
        .db_name(database)
        .stmt_cache_size(0);
    let DataTls::Required(check) = &through.tls else {
        return options;
    };
    let roots = check
        .authority()
        .map(|pem| vec![pem.as_bytes().to_vec().into()])
        .unwrap_or_default();
    let tls = SslOpts::default()
        .with_root_certs(roots)
        .with_danger_tls_hostname_override(Some(check.server_name().to_owned()));
    options.ssl_opts(tls)
}

/// One statement, its values and limits.
struct Call {
    statement: String,
    parameters: Value,
    database: Option<String>,
    row_limit: u32,
    limits: Limits,
}

impl Call {
    /// The call `arguments` ask for, held to `limits`.
    fn asked(arguments: &FlowData, limits: Limits) -> Result<Self, ActionOutcome> {
        Ok(Self {
            statement: required_text(arguments, "statement")?.to_owned(),
            parameters: optional_values(arguments, "parameters")?.unwrap_or(Value::Null),
            database: optional_text(arguments, "database")?.map(str::to_owned),
            row_limit: row_limit(arguments, limits.most_rows)?,
            limits,
        })
    }

    /// The rows the statement reads, in a read-only transaction.
    async fn query(&self, connection: &mut Conn) -> ActionOutcome {
        if let Err(refused) = self
            .start_transaction(connection, "START TRANSACTION READ ONLY")
            .await
        {
            return refused;
        }
        match self.rows(connection).await {
            Ok(output) => self.succeeded(&output),
            Err(refused) => refused,
        }
    }

    /// The rows the statement reads, at most the row limit, read one at a
    /// time so no more than one row past it is ever taken.
    async fn rows(&self, connection: &mut Conn) -> Result<Value, ActionOutcome> {
        let values = bound(&self.parameters)?;
        let mut result = connection
            .exec_iter(self.statement.as_str(), values)
            .await
            .map_err(|error| refused_by_database(&error))?;
        let most = usize::try_from(self.row_limit).unwrap_or(usize::MAX);
        let mut read = Vec::new();
        let mut truncated = false;
        while let Some(row) = result
            .next()
            .await
            .map_err(|error| refused_by_database(&error))?
        {
            if read.len() == most {
                truncated = true;
                break;
            }
            read.push(Value::Object(row_values(&row)?));
        }
        Ok(json!({ "row_count": read.len(), "truncated": truncated, "rows": read }))
    }

    /// How many rows the statement changed, committed only on success.
    async fn execute(&self, connection: &mut Conn) -> ActionOutcome {
        if let Err(refused) = self
            .start_transaction(connection, "START TRANSACTION")
            .await
        {
            return refused;
        }
        let values = match bound(&self.parameters) {
            Ok(values) => values,
            Err(refused) => return refused,
        };
        if let Err(error) = connection.exec_drop(self.statement.as_str(), values).await {
            return refused_by_database(&error);
        }
        let rows_affected = connection.affected_rows();
        if connection.query_drop("COMMIT").await.is_err() {
            return failed("the database did not commit the change");
        }
        self.succeeded(&json!({ "rows_affected": rows_affected }))
    }

    /// Holds the session's reads to the time limit inside the database, and
    /// starts the transaction with `start`.
    async fn start_transaction(
        &self,
        connection: &mut Conn,
        start: &str,
    ) -> Result<(), ActionOutcome> {
        let millis = self.limits.statement_timeout.as_millis().max(1);
        connection
            .query_drop(format!("SET SESSION MAX_EXECUTION_TIME = {millis}"))
            .await
            .map_err(|_| failed("the database did not take the time limit"))?;
        connection
            .query_drop(start)
            .await
            .map_err(|_| failed("the database did not start a transaction"))
    }

    /// The call's success, with `output` held as workflow data.
    fn succeeded(&self, output: &Value) -> ActionOutcome {
        match flow_of(output) {
            Ok(output) => ActionOutcome::Succeeded {
                output,
                exposure: self.limits.ceiling,
            },
            Err(_) => failed(
                "the rows are larger than workflow data may be, or a column needs a name a workflow can hold: give it one with AS",
            ),
        }
    }
}

/// The failure of a statement the database refused, in its own words,
/// which name the statement's problem and never the login.
fn refused_by_database(error: &mysql_async::Error) -> ActionOutcome {
    let words = match error {
        mysql_async::Error::Server(server) => server.message.clone(),
        _ => "the database could not run the statement".to_owned(),
    };
    failed(&format!("the database refused the statement: {words}"))
}
