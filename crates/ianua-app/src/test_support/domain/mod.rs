//! Fakes for the custom domain use cases: the registrations, the DNS they
//! are proved and served through, and the certificates issued for them or
//! uploaded by their tenants.

mod certificates;
mod dns;
mod handovers;
mod issuance;
mod platform;
mod registered;
mod seeds;
mod uploads;

pub use certificates::*;
pub use dns::*;
pub use handovers::*;
pub use issuance::*;
pub use platform::*;
pub use registered::*;
pub use seeds::*;
pub use uploads::*;
