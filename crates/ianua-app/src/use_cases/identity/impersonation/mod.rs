//! Support impersonation: a tenant admin asks to act as one of the tenant's
//! people for a short while, the person approves or declines, either side
//! ends it, and every use of it is checked again.

pub(crate) mod act_as;
pub(crate) mod approve;
pub(crate) mod decline;
pub(crate) mod end;
pub(crate) mod list_impersonations;
mod lookup;
pub(crate) mod request;

pub use act_as::{ActAsPorts, ActAsUseCase, ActingAs};
pub use approve::{ApprovePorts, ApproveUseCase};
pub use decline::{DeclinePorts, DeclineUseCase};
pub use end::{EndPorts, EndUseCase};
pub use list_impersonations::{
    ImpersonationListing, ListImpersonationsPorts, ListImpersonationsUseCase,
};
pub use request::{RequestPorts, RequestRequest, RequestUseCase};
