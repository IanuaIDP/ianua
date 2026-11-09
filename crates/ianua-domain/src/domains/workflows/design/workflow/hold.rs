//! A version in service held because an account it acts through can no
//! longer be used for its publisher.
//!
//! Pat publishes "Weekly planning", whose calendar step acts through the
//! team calendar she shared. On Friday she leaves, and the account stops
//! lending itself. Rather than fail every Monday run at that step, the
//! version is held: nothing starts it, and the people who wrote it are told
//! which step needs which account. Bob picks his own calendar and publishes
//! the next version, which is not held.

use crate::domains::workflows::design::node::NodeKey;
use crate::domains::workflows::design::workflow::{Workflow, WorkflowStatus};
use crate::domains::workflows::events::WorkflowVersionHeld;
use crate::domains::workflows::integration::{ActionAccount, IntegrationKey, OperationKey};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::IntegrationAccountId;

/// Where in a version an account is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountUse {
    /// By its trigger, registered at the service through the account.
    Trigger,
    /// By the action step with this key.
    Step(NodeKey),
}

impl AccountUse {
    /// How the place is written for people and records: `trigger`, or the
    /// step's key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Trigger => "trigger",
            Self::Step(key) => key.as_str(),
        }
    }
}

/// One account a version acts through, where, and for what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedAccount {
    /// The connected credential this version needs to act through.
    pub account: IntegrationAccountId,
    /// The integration it must be for.
    pub integration: IntegrationKey,
    /// Where it is used.
    pub at: AccountUse,
    /// The operation it is used for; none for a trigger.
    pub operation: Option<OperationKey>,
}

/// Why an account can no longer be used for a version's publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountUnusable {
    /// The tenant no longer keeps it.
    Gone,
    /// It was switched off.
    Disabled,
    /// Its owner may no longer lend it, as when they left.
    OwnerCannotLend,
    /// It is kept to its owner, and someone else published the version.
    NotLent,
    /// It is limited to other operations, or is another integration's.
    NotForThisUse,
}

impl AccountUnusable {
    /// The word it is recorded and stored as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gone => "gone",
            Self::Disabled => "disabled",
            Self::OwnerCannotLend => "owner_cannot_lend",
            Self::NotLent => "not_lent",
            Self::NotForThisUse => "not_for_this_use",
        }
    }
}

/// An account a held version needs: which, where, and why it cannot be
/// used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingAccount {
    /// The connected credential whose absence or lost authority holds publication.
    pub account: IntegrationAccountId,
    /// Where the version uses it.
    pub at: AccountUse,
    /// Why it cannot be used.
    pub why: AccountUnusable,
}

/// Whether a version in service may be started.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Hold {
    /// Nothing holds it.
    #[default]
    Clear,
    /// It needs an account: nothing starts it until a next version with a
    /// usable account is published.
    NeedsAccount(MissingAccount),
}

impl<T: TenantScope> Workflow<T> {
    /// Whether it is held for want of an account.
    #[must_use]
    pub fn hold(&self) -> &Hold {
        &self.hold
    }

    /// Every account it acts through: its trigger's, then each action
    /// step's, a loop's own steps included, in the order of its steps.
    #[must_use]
    pub fn accounts_used(&self) -> Vec<UsedAccount> {
        let trigger = match &self.trigger {
            Trigger::Service(on) => Some(UsedAccount {
                account: on.account(),
                integration: on.integration().clone(),
                at: AccountUse::Trigger,
                operation: None,
            }),
            Trigger::Manual
            | Trigger::Schedule(_)
            | Trigger::Webhook
            | Trigger::Event(_)
            | Trigger::Before(_) => None,
        };
        let steps = self.graph.action_steps().filter_map(|(node, step)| {
            let ActionAccount::Account(account) = step.account() else {
                return None;
            };
            Some(UsedAccount {
                account,
                integration: step.integration().clone(),
                at: AccountUse::Step(node.key().clone()),
                operation: Some(step.operation().clone()),
            })
        });
        trigger.into_iter().chain(steps).collect()
    }

    /// Holds this version in service because `missing` can no longer be
    /// used for its publisher: nothing starts it until a next version is
    /// published. Raises `workflows.version_held` the first time; a version
    /// already held stays held as it was, raising nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when it is not in service.
    pub fn hold_for(&mut self, missing: MissingAccount) -> Result<(), DomainError> {
        if self.status != WorkflowStatus::Published {
            return Err(DomainError::conflict(message!(
                "workflows-only-a-version-in-service-is",
                "only a version in service is held"
            )));
        }
        if self.hold != Hold::Clear {
            return Ok(());
        }
        self.hold = Hold::NeedsAccount(missing.clone());
        self.touch();
        self.raised.raise(WorkflowVersionHeld {
            version: self.version_ref(),
            missing,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Refuses starting this version while it is held.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when it needs an account, naming where.
    pub fn ensure_startable(&self) -> Result<(), DomainError> {
        let Hold::NeedsAccount(missing) = &self.hold else {
            return Ok(());
        };
        Err(DomainError::conflict(message!(
            "workflows-the-workflow-needs-an-account",
            format!(
                "this workflow needs an account at {}; pick a usable account and publish it again",
                missing.at.as_str()
            )
        )))
    }
}
