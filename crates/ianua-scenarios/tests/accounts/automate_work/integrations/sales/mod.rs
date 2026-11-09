//! Services that keep customers and their money.
//!
//! - `hubspot`: the token is checked before it is kept, and a run adds a
//!   contact and changes it; a contact HubSpot already has fails the run.
//! - `salesforce`: a domain the deployment does not allow, or a grant
//!   Salesforce refuses, is never connected.
//! - `stripe`: the key is checked before it is kept, and a refund reaches
//!   Stripe as its form only after two administrators approved it.

mod hubspot;
mod salesforce;
mod stripe;
