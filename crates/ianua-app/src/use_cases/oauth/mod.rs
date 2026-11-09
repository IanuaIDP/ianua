//! OAuth use cases: registering clients and API keys, apps registering
//! themselves, the flows that take people through consent and sign-out,
//! and the token endpoint that hands out tokens.

pub mod api_keys;
pub mod clients;
pub mod flows;
mod lookup;
pub mod presented;
pub mod registration;
pub mod sender;
pub mod token;
