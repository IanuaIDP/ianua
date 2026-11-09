//! The contract every integration follows.

use async_trait::async_trait;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::events::{ServiceEventGuide, ServiceEventSpec};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::shared::security::secret::Secret;

use crate::answer::failed;
use crate::connect::SignIn;
use crate::data::Through;
use crate::events::Events;

/// Whether a call changed the account's credential on the way. Its
/// credential prints redacted.
#[derive(Debug)]
pub enum Renewed {
    /// The credential is as it was.
    Unchanged,
    /// The service issued this one in its place, as a rotating refresh
    /// grant does; the old one no longer works, so it must be kept.
    To(Secret),
}

/// What a service said of a credential, and the credential to keep if
/// asking replaced it.
pub struct Checked {
    /// What the service said.
    pub verdict: AccountCheck,
    /// Whether asking changed the credential.
    pub renewed: Renewed,
}

/// What one call came to.
pub struct Called {
    /// How the call went.
    pub outcome: ActionOutcome,
    /// Whether the account's credential changed on the way.
    pub renewed: Renewed,
}

impl From<ActionOutcome> for Called {
    fn from(outcome: ActionOutcome) -> Self {
        Self {
            outcome,
            renewed: Renewed::Unchanged,
        }
    }
}

/// One integration: how it presents itself, the operations it declares and
/// how it explains them, checking an account's credential, the work, and,
/// where its service allows, signing in to connect an account and the
/// events a workflow may start on.
///
/// The platform hands a call over only once it found the operation among
/// [`operations`](Self::operations) and opened the account's credential,
/// and only an operation that acts through an account is handed one. It
/// installs an integration only when every operation and every event has
/// exactly one guide that explains it.
#[async_trait]
pub trait Integration: Send + Sync {
    /// How it presents itself, under the key it is installed under.
    fn profile(&self) -> &IntegrationProfile;

    /// The key it is installed under.
    fn key(&self) -> &IntegrationKey {
        self.profile().key()
    }

    /// The operations it offers now, each naming this integration.
    fn operations(&self) -> &[OperationSpec];

    /// How it explains each operation, one guide per operation.
    fn guides(&self) -> &[OperationGuide];

    /// What its service says of `credential`, asked before an account is
    /// kept with it. Anything short of the service taking it, such as a
    /// timeout, is never [`AccountCheck::Accepted`].
    async fn check_account(&self, credential: &Secret) -> AccountCheck;

    /// What its service says of `credential`, as [`check_account`], with
    /// the credential asking replaced, for a service whose grants rotate
    /// on every use. The platform asks this one and keeps what it says.
    ///
    /// [`check_account`]: Integration::check_account
    async fn checked(&self, credential: &Secret) -> Checked {
        Checked {
            verdict: self.check_account(credential).await,
            renewed: Renewed::Unchanged,
        }
    }

    /// Makes `call`, through `credential` when the operation acts through
    /// an account. Reports [`ActionOutcome::TurnedAway`] only when nothing
    /// was done; anything that may have acted is [`ActionOutcome::Failed`].
    /// A credential the service replaced on the way comes back beside the
    /// outcome, whatever the outcome.
    async fn call(&self, call: &ActionCall, credential: Option<&Secret>) -> Called;

    /// Whether `credential` holds a lasting grant whose short-lived token
    /// should be exchanged before the next call. The platform then makes
    /// the exchange itself, one per account at a time. Never for a
    /// credential that holds no grant, and so never by default.
    fn grant_due(&self, _credential: &Secret) -> bool {
        false
    }

    /// Exchanges the grant `credential` holds at once, whatever is left of
    /// its token, and hands back the credential to keep. A credential that
    /// holds no grant is unchanged.
    ///
    /// # Errors
    ///
    /// A failed outcome when the service refuses the grant; turned away
    /// when its token address cannot be reached or is busy.
    async fn renew_grant(&self, _credential: &Secret) -> Result<Renewed, ActionOutcome> {
        Ok(Renewed::Unchanged)
    }

    /// Makes `call` over `through`, for an operation acting as the run's
    /// person on a stream route: a connection the platform opened through
    /// the gateway, and the login the route keeps for workflows. An
    /// integration reaching no protected data fails such a call, by
    /// default.
    async fn call_through(&self, _call: &ActionCall, _through: Through) -> Called {
        failed("the integration reaches no protected data").into()
    }

    /// The events its service sends that a workflow may start on, each
    /// naming this integration. None by default.
    fn events(&self) -> &[ServiceEventSpec] {
        &[]
    }

    /// How it explains each event, one guide per event.
    fn event_guides(&self) -> &[ServiceEventGuide] {
        &[]
    }

    /// Signing in at its service to connect an account, when the
    /// deployment registered an app with it. None by default.
    fn sign_in(&self) -> Option<&dyn SignIn> {
        None
    }

    /// Registering workflows for its events and reading what its service
    /// sends, offered with every event. None by default.
    fn watcher(&self) -> Option<&dyn Events> {
        None
    }
}
