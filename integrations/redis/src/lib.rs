//! Protected data steps for Redis: a command run as a workflow's person
//! through the gateway, over a stream route an admin opened to workflows,
//! with the login the platform keeps for it.
//!
//! The platform opens the connection and hands it over with the login, so
//! this crate never dials anything and never decides who may connect. It
//! signs in with Redis's own access lists (`AUTH user password`), inside
//! TLS from the first byte when the login asks for it, and sends one
//! command. A `read` takes only commands that read; a `write` takes any
//! command the login may run, and is risky enough to need an approval
//! wherever the tenant asks for one. What the login may run is Redis's
//! own decision. A command that would change the connection itself, such
//! as signing in again or subscribing, is refused by both.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod command;
mod guides;
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

use crate::command::Kind;

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Redis",
    description: "Runs a command on a company's own Redis behind the gateway, as the person the run acts for.",
    icon: "redis",
    picture: include_str!("../assets/icon.svg"),
    brand: "ff4438",
};

/// What the Redis steps are held to.
#[derive(Debug, Clone, Copy)]
pub struct RedisSettings {
    /// The longest Redis may take to answer the command.
    pub command_timeout: Duration,
    /// The data class what a command reads is counted as.
    pub ceiling: DataClassLevel,
}

/// The Redis Protected data integration, installed under `redis`.
pub struct Redis {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    settings: RedisSettings,
}

impl Redis {
    /// The integration, held to `settings`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when an operation or a guide breaks a rule
    /// of the workflow domain, which a change here would cause.
    pub fn new(settings: RedisSettings) -> Result<Self, DomainError> {
        let key = IntegrationKey::new("redis")?;
        Ok(Self {
            profile: profile(&key, &PROFILE)?,
            operations: operations_of(&key, settings.ceiling)?,
            guides: guides::guides_of()?,
            settings,
        })
    }
}

#[async_trait]
impl Integration for Redis {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// Redis keeps no accounts: each call signs in with the login its
    /// stream route keeps.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
        failed("a Redis step is called over a connection to its stream route").into()
    }

    async fn call_through(&self, call: &ActionCall, through: Through) -> Called {
        let Some(kind) = Kind::of(call.operation.as_str()) else {
            return failed("the operation is not one this integration offers").into();
        };
        command::run(kind, &call.arguments, &through, self.settings)
            .await
            .into()
    }
}

/// The two operations: a `read` and a `write`, each acting as the run's
/// person on the stream route it names.
fn operations_of(
    key: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Vec<OperationSpec>, DomainError> {
    [Kind::Read, Kind::Write]
        .into_iter()
        .map(|kind| {
            OperationSpec::new(OperationSpecParams {
                integration: key.clone(),
                operation: OperationKey::new(kind.name())?,
                inputs: vec![
                    InputSpec::new(FieldName::new(ROUTE_INPUT)?, InputNeed::Required),
                    InputSpec::new(FieldName::new("command")?, InputNeed::Required),
                    InputSpec::new(FieldName::new("arguments")?, InputNeed::Optional),
                    InputSpec::new(FieldName::new("database")?, InputNeed::Optional),
                ],
                effect: DeclaredAction::Declared(match kind {
                    Kind::Read => ActionClass::Read,
                    Kind::Write => ActionClass::Write,
                }),
                account: AccountNeed::RunPersonData,
                ceiling,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The integration offers a read and a write, each acting as the run's
    /// person on a stream route, each explained by a guide.
    #[test]
    fn it_offers_a_read_and_a_write_on_protected_data() {
        let redis = Redis::new(RedisSettings {
            command_timeout: Duration::from_secs(10),
            ceiling: DataClassLevel::Confidential,
        })
        .unwrap();

        let named: Vec<_> = redis
            .operations()
            .iter()
            .map(|spec| (spec.operation().as_str(), spec.account()))
            .collect();

        assert_eq!(
            named,
            [
                ("read", AccountNeed::RunPersonData),
                ("write", AccountNeed::RunPersonData)
            ]
        );
        assert_eq!(redis.guides().len(), 2);
    }
}
