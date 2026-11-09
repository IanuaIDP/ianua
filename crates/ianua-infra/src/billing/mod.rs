//! The payment provider that holds organizations' payment methods and
//! charges them, and the notices it posts back; or none, on a deployment
//! that bills nobody.

mod none;
mod stripe;

pub use none::NoPaymentProvider;
pub use stripe::{STRIPE_API, StripePaymentProvider, StripeSettings};
