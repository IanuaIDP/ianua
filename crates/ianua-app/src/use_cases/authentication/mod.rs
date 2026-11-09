//! Authentication use cases: signing in and out, refreshing sessions,
//! passwords, second factors, passkeys, single sign-on, trusted devices and
//! break-glass access.

/// Signing in, up and out on the host of an app behind the gateway.
pub mod app_sign_in;
/// Single sign-on through a federation connection's identity provider.
pub mod federation;
mod held_factors;
/// Second factors, and recovery codes in their place.
pub mod mfa;
/// Passkeys: registering, signing in with, and managing them.
pub mod passkeys;
/// Password and magic-link sign-in, and changing or resetting a password.
pub mod password;
/// Sessions, trusted devices, break-glass access and sign-in options.
pub mod sessions;
mod signed_in_event;
mod timing;
