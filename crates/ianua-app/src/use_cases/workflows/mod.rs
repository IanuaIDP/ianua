//! Workflows: graphs of steps a tenant designs, publishes and runs.
//!
//! - `definitions`: drafting, editing, publishing and archiving versions.
//! - `executions`: starting runs by hand, on a trigger or a webhook call,
//!   starting a failed one again, the worker that drives them, and the
//!   people who approve, deny or cancel them.
//! - `evaluations`: a workflow's sample cases, and its versions tried
//!   against them as test runs, a few at a time.
//! - `flows`: agent flows, made and started at once.
//! - `triggers`: the secrets workflows' webhooks are called with.
//! - `catalog`: the operations a builder may use, and a tenant raising how
//!   risky one counts as.
//! - `accounts`: the integration accounts actions act through, connected
//!   by hand or by signing in at their service.
//! - `published`: holding versions in service that lost an account, and
//!   keeping them registered at the services whose events start them.
//! - `sandboxes`: named recipes of code and pinned packages, their saved
//!   versions and the job building each version's bundle.
//! - `memories`: named stores of texts and their vectors that steps keep
//!   texts in and search, and the sweep deleting them for good.
//!
//! What the person a workflow acts for holds is worked out again before
//! every start and every step, from their account as it stands
//! ([`account_now`](crate::services::account_now)).

pub mod accounts;
pub mod catalog;
pub mod definitions;
pub mod evaluations;
pub mod executions;
pub mod flows;
mod lookup;
pub mod memories;
mod offers;
pub mod published;
mod runnable;
pub mod sandboxes;
pub mod triggers;
