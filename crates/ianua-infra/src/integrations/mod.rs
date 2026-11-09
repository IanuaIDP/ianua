//! The integrations a workflow's action steps call: the set installed in
//! this deployment, the catalog of what they offer, the runner that makes
//! one call through them, the verifier that asks one whether an account's
//! credential works, signing in at a service to connect an account,
//! registering workflows for services' events and reading what they send,
//! and reading and pushing sandbox code in repositories.
//!
//! Each integration follows the contract in `ianua-integration`; the
//! outside services, such as GitHub and Slack, are crates of their own
//! under `integrations/`. Three are built in here: an HTTP request to an
//! address the tenant chose ([`HttpRequests`]), screened as every such
//! call is, a call to an app behind the gateway as the run's person
//! ([`ProtectedApps`]), and the memory steps the platform runs itself
//! ([`MemorySteps`]). A Protected data step's call goes over a
//! connection [`DataLink`] opens at the gateway's workflow listener.

mod accounts;
mod apps;
mod catalog;
mod company;
mod data;
mod installed;
mod memory;
mod repositories;
mod requests;
mod runner;
mod watches;

pub use accounts::{InstalledAccountVerifier, InstalledGrantExchanger, InstalledServiceSignIn};
pub use apps::{AppSettings, ProtectedApps};
pub use catalog::InstalledIntegrationCatalog;
pub use company::CompanyIntegration;
pub use data::{DataLink, InstalledOpener};
pub use installed::Installed;
pub use memory::MemorySteps;
pub use repositories::InstalledCodeRepositories;
pub use requests::{HttpRequests, RequestSettings};
pub use runner::InstalledActionRunner;
pub use watches::{
    EventAddresses, InstalledServiceChannelSetup, InstalledServiceEventReader,
    InstalledServiceRegistrar,
};
