//! Making one action step's call through its integration, and what the
//! call goes through: nothing, an account's sealed credential, a pass made
//! for it alone, or such a pass with the login a stream route keeps.

use async_trait::async_trait;
use ianua_domain::domains::routing::stream::{LoginTls, LoginUser};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::security::secret::Secret;

use crate::ports::TenantScoped;
use crate::ports::authentication::SealedAt;
use crate::ports::workflows::Renewal;
use crate::tenancy::ScopedTenant;

/// What one action step's call came to.
#[derive(Debug)]
pub struct ActionRun {
    /// How the call went.
    pub outcome: ActionOutcome,
    /// Whether the account's credential was renewed on the way.
    pub renewal: Renewal,
}

/// Dyn-safe port making one action step's call through its integration.
///
/// The adapter opens the sealed credential itself, bounds the call with a
/// timeout, and reports how it went. A timeout, a crash or anything that may
/// have acted is [`ActionOutcome::Failed`]; only a call the integration
/// turned away before doing anything is [`ActionOutcome::TurnedAway`]. A
/// credential the service renewed comes back sealed, however the call went.
#[async_trait]
pub trait ActionRunner: Send + Sync + TenantScoped {
    /// Makes `call` for the tenant, through `credential`.
    async fn run(
        &self,
        tenant_id: &ScopedTenant,
        call: &ActionCall,
        credential: CallCredential<'_>,
    ) -> ActionRun;
}

/// What an action step's call is made through.
#[derive(Debug, Clone, Copy)]
pub enum CallCredential<'a> {
    /// Nothing: the operation acts through no account.
    Nothing,
    /// An account's credential, sealed for the account it belongs to.
    Account(&'a SealedAt),
    /// A pass made for this one call, acting as the run's person.
    Pass(&'a Secret),
    /// A pass made for this one call on a stream route, acting as the run's
    /// person, with the login the route keeps for workflows.
    Data(&'a DataCall),
}

/// What a Protected data step's call goes through: a connection the
/// adapter opens through the gateway with `pass`, then signs in over as
/// `login` says.
#[derive(Debug)]
pub struct DataCall {
    /// The pass made for this one call, naming the stream route.
    pub pass: Secret,
    /// The user name the login signs in as.
    pub user: LoginUser,
    /// Its password, sealed for the stream route it belongs to.
    pub password: SealedAt,
    /// How the connection to the system is protected.
    pub tls: LoginTls,
}
