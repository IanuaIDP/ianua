//! Services that hold no person's session, proving themselves to the
//! tenant with a secret or a key of their own.
//!
//! - `credentials`: a service gets tokens with its secret, a rotated
//!   secret and a revoked client lose them; a resource server is told what
//!   a token is worth, a client ends only its own tokens.
//! - `exchange`: a service trades its token for a narrower one meant for
//!   another service, nothing widened, nothing taken from elsewhere.
//! - `assertions`: a service proves itself with a JWT it signs, each one
//!   good once, and every way of forging one is refused.

mod assertions;
mod credentials;
mod exchange;
