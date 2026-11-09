//! Each outside service as a workflow step, against a stand-in for its API
//! that shows what arrived: the account's credential, the address and the
//! body, written the way the service reads them.
//!
//! - `calls`: what the services' scenarios share: a refused credential, a
//!   published run of a chain of steps, the one call of a kind that
//!   arrived.
//! - `events`: connecting by signing in at each service that offers it,
//!   and each service's events starting workflows.
//! - `development`: code hosts, issue trackers and paging.
//! - `messages`: chat, mail and texts.
//! - `sales`: customers and their money.
//! - `tasks`: task boards, documents, tables and calendars.

mod calls;
mod development;
mod events;
mod messages;
mod sales;
mod tasks;
