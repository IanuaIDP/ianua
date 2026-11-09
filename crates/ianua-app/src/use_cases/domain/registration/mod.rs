//! Registering custom domains: adding, reading, listing and removing them.
//! Handing one to another tenant is
//! [`handover`](crate::use_cases::domain::handover).

pub(crate) mod add;
pub(crate) mod get;
pub(crate) mod list_domains;
pub(crate) mod remove;

pub use add::{AddDomainPorts, AddDomainRequest, AddDomainUseCase, DelegationOffer};
pub use get::{DomainDetail, GetDomainPorts, GetDomainUseCase};
pub use list_domains::{ListDomainsPorts, ListDomainsRequest, ListDomainsUseCase};
pub use remove::{RemoveDomainPorts, RemoveDomainUseCase};
