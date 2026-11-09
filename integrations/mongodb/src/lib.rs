//! Protected data steps for MongoDB: finds and changes run as a workflow's
//! person through the gateway, over a stream route an admin opened to
//! workflows, with the login the platform keeps for it.
//!
//! The platform opens the connections and hands them over with the login,
//! so this crate never decides who may connect. MongoDB's client dials an
//! address itself and opens a few connections of its own, so it dials a
//! door on the worker's own loopback address that carries each one through
//! the gateway, inside TLS from the first byte when the login asks for it,
//! checked against the database's certificate; the client itself speaks
//! no TLS and talks to that one server directly. The login is a user kept
//! in the `admin` database. A `find` and an `aggregate` only read, an
//! aggregate refusing the stages that write; an `insert`, `update` and
//! `delete` write, and are risky enough to need an approval wherever the
//! tenant asks for one. What the login may do is MongoDB's own decision.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod documents;
mod guides;
mod operation;

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

use crate::operation::Kind;

/// The most documents a find or an aggregate hands back, whatever a step
/// asks for.
pub const MOST_DOCUMENTS: u32 = 1_000;

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "MongoDB",
    description: "Finds and changes documents in a company's own MongoDB behind the gateway, as the person the run acts for.",
    icon: "mongodb",
    picture: include_str!("../assets/icon.svg"),
    brand: "47a248",
};

/// What the MongoDB steps are held to.
#[derive(Debug, Clone, Copy)]
pub struct MongoDbSettings {
    /// The longest one find or aggregate may run, set inside the database.
    pub operation_timeout: Duration,
    /// The most documents a read hands back, at most [`MOST_DOCUMENTS`].
    pub most_documents: u32,
    /// The data class the documents a read returns are counted as.
    pub ceiling: DataClassLevel,
}

/// The MongoDB Protected data integration, installed under `mongodb`.
pub struct MongoDb {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    settings: MongoDbSettings,
}

impl MongoDb {
    /// The integration, held to `settings`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when an operation or a guide breaks a rule
    /// of the workflow domain, which a change here would cause.
    pub fn new(settings: MongoDbSettings) -> Result<Self, DomainError> {
        let key = IntegrationKey::new("mongodb")?;
        let settings = MongoDbSettings {
            most_documents: settings.most_documents.clamp(1, MOST_DOCUMENTS),
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
impl Integration for MongoDb {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// MongoDB keeps no accounts: each call signs in with the login its
    /// stream route keeps.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
        failed("a MongoDB step is called over a connection to its stream route").into()
    }

    async fn call_through(&self, call: &ActionCall, through: Through) -> Called {
        let Some(kind) = Kind::of(call.operation.as_str()) else {
            return failed("the operation is not one this integration offers").into();
        };
        operation::run(kind, &call.arguments, through, self.settings)
            .await
            .into()
    }
}

/// Every operation, each acting as the run's person on the stream route it
/// names.
fn operations_of(
    key: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Vec<OperationSpec>, DomainError> {
    Kind::ALL
        .into_iter()
        .map(|kind| {
            OperationSpec::new(OperationSpecParams {
                integration: key.clone(),
                operation: OperationKey::new(kind.name())?,
                inputs: inputs_of(kind)?,
                effect: DeclaredAction::Declared(match kind {
                    Kind::Find | Kind::Aggregate => ActionClass::Read,
                    Kind::Insert | Kind::Update | Kind::Delete => ActionClass::Write,
                }),
                account: AccountNeed::RunPersonData,
                ceiling,
            })
        })
        .collect()
}

/// The inputs `kind` takes: the stream route, the database and collection,
/// and what the operation itself asks for.
fn inputs_of(kind: Kind) -> Result<Vec<InputSpec>, DomainError> {
    let mut inputs = vec![
        InputSpec::new(FieldName::new(ROUTE_INPUT)?, InputNeed::Required),
        InputSpec::new(FieldName::new("database")?, InputNeed::Required),
        InputSpec::new(FieldName::new("collection")?, InputNeed::Required),
    ];
    for (name, need) in kind.own_inputs() {
        inputs.push(InputSpec::new(FieldName::new(*name)?, *need));
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mongodb() -> MongoDb {
        MongoDb::new(MongoDbSettings {
            operation_timeout: Duration::from_secs(10),
            most_documents: 50_000,
            ceiling: DataClassLevel::Confidential,
        })
        .unwrap()
    }

    /// The integration offers two reads and three writes, each acting as
    /// the run's person on a stream route, each explained by a guide.
    #[test]
    fn it_offers_reads_and_writes_on_protected_data() {
        let mongodb = mongodb();

        let named: Vec<_> = mongodb
            .operations()
            .iter()
            .map(|spec| spec.operation().as_str())
            .collect();

        assert_eq!(named, ["find", "aggregate", "insert", "update", "delete"]);
        assert!(
            mongodb
                .operations()
                .iter()
                .all(|spec| spec.account() == AccountNeed::RunPersonData)
        );
        assert_eq!(mongodb.guides().len(), 5);
    }

    /// A document limit asked past the most is held to the most.
    #[test]
    fn the_document_limit_is_held_to_the_most() {
        assert_eq!(mongodb().settings.most_documents, MOST_DOCUMENTS);
    }
}
