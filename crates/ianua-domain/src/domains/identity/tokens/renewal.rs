//! The new link an emailed offer gets when its old link ran out.

use crate::types::{Lifetime, TokenHash};

/// The new link a dead one is renewed with, mailed to the same address.
///
/// The infra layer makes and hashes the new raw token. The domain never
/// sees it.
#[derive(Debug)]
pub struct RenewedLink {
    /// The hash of the new link's token.
    pub token_hash: TokenHash,
    /// How long the new link works from now.
    pub lifetime: Lifetime,
}
