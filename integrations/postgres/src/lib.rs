//! Protected data steps for Postgres: a query run as a workflow's person
//! through the gateway, over a stream route an admin opened to workflows,
//! with the login the platform keeps for it.
//!
//! The platform opens the connection and hands it over with the login, so
//! this crate never dials anything and never decides who may connect. It
//! only speaks Postgres over the connection. A `query` runs inside a
//! read-only transaction, so Postgres itself refuses any write, whatever
//! the statement says; an `execute` writes, and is risky enough to need an
//! approval wherever the tenant asks for one. Statements carry their
//! values as bound parameters, never pasted into the text, and every call
//! is held to a row limit and a time limit set inside the database.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod guides;
mod query;
mod tls;
mod values;

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, OperationKey, OperationSpec,
    OperationSpecParams, ROUTE_INPUT,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::answer::failed;
use ianua_integration::data::Through;
use ianua_integration::describe::{ProfileText, profile};
use ianua_integration::{Called, Integration};

use crate::query::{Kind, Limits};

/// The most rows a query hands back, whatever a step asks for.
pub const MOST_ROWS: u32 = 1_000;

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Postgres",
    description: "Runs a query on a company's own Postgres database behind the gateway, as the person the run acts for.",
    icon: "postgres",
    picture: include_str!("../assets/icon.svg"),
    brand: "336791",
};

/// What the Postgres steps are held to.
#[derive(Debug, Clone, Copy)]
pub struct PostgresSettings {
    /// The longest one statement may run, set inside the database.
    pub statement_timeout: Duration,
    /// The most rows a query hands back, at most [`MOST_ROWS`].
    pub most_rows: u32,
    /// The data class the rows a query reads are counted as.
    pub ceiling: DataClassLevel,
}

/// The Postgres Protected data integration, installed under `postgres`.
pub struct Postgres {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    settings: PostgresSettings,
}

impl Postgres {
    /// The integration, held to `settings`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when an operation or a guide breaks a rule
    /// of the workflow domain, which a change here would cause.
    pub fn new(settings: PostgresSettings) -> Result<Self, DomainError> {
        let key = IntegrationKey::new("postgres")?;
        let settings = PostgresSettings {
            most_rows: settings.most_rows.clamp(1, MOST_ROWS),
            ..settings
        };
        Ok(Self {
            profile: profile(&key, &PROFILE)?,
            operations: operations_of(&key, settings.ceiling)?,
            guides: guides::guides_of()?,
            settings,
        })
    }
}

#[async_trait]
impl Integration for Postgres {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// Postgres keeps no accounts: each call signs in with the login its
    /// stream route keeps.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
        failed("a Postgres step is called over a connection to its stream route").into()
    }

    async fn call_through(&self, call: &ActionCall, through: Through) -> Called {
        let Some(kind) = Kind::of(call.operation.as_str()) else {
            return failed("the operation is not one this integration offers").into();
        };
        let limits = Limits {
            statement_timeout: self.settings.statement_timeout,
            most_rows: self.settings.most_rows,
            ceiling: self.settings.ceiling,
        };
        query::run(kind, &call.arguments, through, limits)
            .await
            .into()
    }
}

/// The two operations: a read-only `query` and a writing `execute`, each
/// acting as the run's person on the stream route it names.
fn operations_of(
    key: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Vec<OperationSpec>, DomainError> {
    [Kind::Query, Kind::Execute]
        .into_iter()
        .map(|kind| {
            OperationSpec::new(OperationSpecParams {
                integration: key.clone(),
                operation: OperationKey::new(kind.name())?,
                inputs: inputs_of(kind)?,
                effect: DeclaredAction::Declared(match kind {
                    Kind::Query => ActionClass::Read,
                    Kind::Execute => ActionClass::Write,
                }),
                account: AccountNeed::RunPersonData,
                ceiling,
            })
        })
        .collect()
}

/// The inputs `kind` takes: the stream route, the statement, its values,
/// the database, and for a query the most rows it hands back.
fn inputs_of(kind: Kind) -> Result<Vec<InputSpec>, DomainError> {
    let mut inputs = vec![
        InputSpec::new(FieldName::new(ROUTE_INPUT)?, InputNeed::Required),
        InputSpec::new(FieldName::new("statement")?, InputNeed::Required),
        InputSpec::new(FieldName::new("parameters")?, InputNeed::Optional),
        InputSpec::new(FieldName::new("database")?, InputNeed::Optional),
    ];
    if kind == Kind::Query {
        inputs.push(InputSpec::new(
            FieldName::new("row_limit")?,
            InputNeed::Optional,
        ));
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn postgres() -> Postgres {
        Postgres::new(PostgresSettings {
            statement_timeout: Duration::from_secs(10),
            most_rows: 50_000,
            ceiling: DataClassLevel::Confidential,
        })
        .unwrap()
    }

    /// The integration offers a query that reads and an execute that
    /// writes, each acting as the run's person on a stream route, each
    /// explained by a guide.
    #[test]
    fn it_offers_a_read_and_a_write_on_protected_data() {
        let postgres = postgres();

        let named: Vec<_> = postgres
            .operations()
            .iter()
            .map(|spec| (spec.operation().as_str(), spec.account()))
            .collect();

        assert_eq!(
            named,
            [
                ("query", AccountNeed::RunPersonData),
                ("execute", AccountNeed::RunPersonData)
            ]
        );
        assert_eq!(postgres.guides().len(), 2);
    }

    /// A row limit asked past the most is held to the most.
    #[test]
    fn the_row_limit_is_held_to_the_most() {
        assert_eq!(postgres().settings.most_rows, MOST_ROWS);
    }
}
