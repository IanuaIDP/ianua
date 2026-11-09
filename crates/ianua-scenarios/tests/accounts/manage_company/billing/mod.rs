//! What Ann's company pays: the plans anyone may read, the bill and what
//! it uses against the plan, the plan Bob the operator arranges, the
//! checkout, and the notices a payment provider posts with nobody signed
//! in.
//!
//! - `plans`: the plans on sale, the plan Bob arranges, and the checkout.
//! - `usage`: the subscription and what is used, and who may read them.
//! - `notices`: signed notices from the payment provider, forged ones,
//!   and notices that arrive twice or out of order.

mod notices;
mod plans;
mod usage;
