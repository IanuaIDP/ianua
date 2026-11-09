//! Untrusted request fields turned into checked instructions: partial
//! updates, and checks on tokens, codes and passwords before anything is
//! hashed or looked up.

mod patch;
mod validation;

pub use patch::*;
pub(crate) use validation::{
    validate_password, validate_pkce_verifier, validate_secret, validate_short_code, validate_token,
};
