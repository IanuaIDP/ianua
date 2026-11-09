//! The directory over LDAP: binding as a person or as an application's
//! service account, searching what they may read, writing users and groups
//! as a person, and the client certificates a person's bind needs.
//!
//! The LDAP adapter terminates the protocol and asks these use cases for the
//! decisions; it holds no authentication or authorization logic of its own.

mod admission;
pub(crate) mod bind_user;
pub mod certificates;
pub mod groups;
pub mod listing;
pub mod principal;
pub(crate) mod search;
pub mod service_accounts;
pub mod users;

pub use bind_user::{BindPorts, BindRequest, BindUseCase};
pub(crate) use search::MAX_DIRECTORY_ENTRIES;
pub use search::{DirectoryGroup, DirectoryListing, DirectoryUser, SearchPorts, SearchUseCase};
