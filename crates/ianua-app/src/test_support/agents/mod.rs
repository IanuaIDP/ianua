//! Fakes for the agent ports, by topic: who an agent is and how it proves
//! it, what it acts under, asks for and may reach, how it runs, the watch
//! kept over it, and the agents seen at work that nobody registered.
//! Stores keep records per tenant, in memory.

mod approvals;
mod approving;
mod catalogue;
mod delegation;
mod identity;
mod oversight;
mod proof;
mod reach;
mod requests;
mod run;
mod runner;
mod shelf;
mod sightings;
mod use_cases;
mod workload;

pub use approvals::*;
pub use approving::*;
pub use catalogue::*;
pub use delegation::*;
pub use identity::*;
pub use oversight::*;
pub use proof::*;
pub use reach::*;
pub use requests::*;
pub use run::*;
pub use runner::*;
pub use sightings::*;
pub use use_cases::*;
pub use workload::*;
