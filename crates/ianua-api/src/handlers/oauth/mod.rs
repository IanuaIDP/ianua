//! OAuth handlers, by app area: clients, API keys, apps registering
//! themselves, the flows that hand out codes and sign people out, and the
//! token endpoint with the endpoints beside it.

pub mod api_keys;
pub mod clients;
pub mod flows;
pub mod registration;
pub mod token;
