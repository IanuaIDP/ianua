//! What an organization pays for: the stores of
//! `ports/organization/billing.rs` that keep it in Postgres, the ledger of
//! the payment provider's events acted on, and the
//! counter of the usage a plan is checked against, read fresh over the
//! tables of the other contexts.
//!
//! The payment provider is reached over the network, so it does not live
//! here.

mod events;
mod subscriptions;
mod usage;

pub use events::PgPaymentEventLedger;
pub use subscriptions::PgOrgSubscriptionStore;
pub use usage::PgPlanUsageCounter;
