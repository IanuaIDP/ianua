//! Making a new emailed link: the raw token to mail, and what the record it
//! belongs to keeps of it.

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::renewal::RenewedLink;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Lifetime;

use crate::error::{AppError, OrInternal};

/// A new link made by `generator`, good for `lifetime`. Tenant and
/// organization links alike are renewed with one.
///
/// # Errors
///
/// - `AppError::Internal` when the token cannot be made.
pub(in crate::use_cases) fn renewed_link(
    generator: &dyn RefreshTokenGenerator,
    lifetime: Lifetime,
) -> Result<(Secret, RenewedLink), AppError> {
    let (raw_token, token_hash) = generator.generate().or_internal()?.into_parts();
    Ok((
        raw_token,
        RenewedLink {
            token_hash,
            lifetime,
        },
    ))
}
