//! What an emailed link or address is worth: where a link belongs, asking for
//! another one, what a link is worth before it is spent, a link refused,
//! whether an admin vouches for an address, and how an invitation's link
//! went out.

mod invitation_delivery;
mod invitation_policy;
mod links;
mod refused_link;
mod resend;
mod verification;
mod vouching;

pub use invitation_delivery::*;
pub use invitation_policy::*;
pub use links::*;
pub(crate) use refused_link::refused_link;
pub use resend::*;
pub use verification::*;
pub use vouching::*;
