//! The steps every way in shares: choosing the organization, landing, opening and finishing the session.

pub(crate) mod choice;
pub(crate) mod finishing;
pub(crate) mod landing;
pub(in crate::use_cases::organization) mod opening;
pub use choice::{OfferedOrganization, OrgLoginOutcome, OrganizationChoice};
pub use finishing::FinishingPorts;
pub use landing::LandedTenant;
