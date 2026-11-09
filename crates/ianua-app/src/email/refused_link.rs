//! What a person who followed an emailed link is told when the domain
//! refuses it.

use ianua_domain::message;
use ianua_domain::types::{TokenRefused, TokenState};

use crate::error::AppError;

/// The answer for a link the domain refused.
///
/// A link that ran out of time, or went to an address the account has
/// since left, can be replaced, so it is told apart from one that never
/// existed. One already spent says so. A link for another account, or one
/// that signs into a shut account, answers as if it did not exist: saying
/// anything more would tell a stranger about an account that is not theirs.
pub(crate) fn refused_link(refused: TokenRefused) -> AppError {
    match refused.state() {
        TokenState::Expired | TokenState::Superseded => AppError::LinkExpired(message!(
            "app-this-link-has-expired",
            "this link has expired"
        )),
        TokenState::Consumed => AppError::NotFound(message!(
            "app-this-link-was-already-used",
            "this link was already used"
        )),
        TokenState::Usable | TokenState::ForAnotherAccount | TokenState::AccountShut => {
            AppError::NotFound(message!("app-invalid-link", "invalid link"))
        }
    }
}
