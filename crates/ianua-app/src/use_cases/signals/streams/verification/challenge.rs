//! The challenge a stream's endpoint echoes to prove it is the receiver's:
//! made at random when the endpoint is set, and sent to it as a
//! verification event once the stream is stored.

use ianua_domain::domains::signals::stream::EndpointChallenge;

use crate::error::AppError;
use crate::ports::crypto::SecureTokenGenerator;

/// Random bytes in a challenge, well past what anyone could guess.
const CHALLENGE_BYTES: usize = 32;

/// A fresh random challenge for an endpoint.
///
/// # Errors
///
/// `AppError::Internal` when the generator hands back something that is not
/// a challenge.
pub(in crate::use_cases::signals::streams) fn fresh_challenge(
    generator: &dyn SecureTokenGenerator,
) -> Result<EndpointChallenge, AppError> {
    EndpointChallenge::new(generator.generate(CHALLENGE_BYTES).expose()).map_err(AppError::internal)
}
