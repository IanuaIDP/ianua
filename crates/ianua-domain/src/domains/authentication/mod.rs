/// Proof that a workspace or organization admitted a sign-in attempt.
pub mod admission;
/// Passwords, passkeys and breach detection.
pub mod credentials;
/// A tenant user remembering or forgetting a device, as it is recorded.
pub mod device_change;
/// Trusted device lifecycle: trusted or revoked.
pub mod device_status;
/// Trusted device management.
pub mod device_trust;
/// Accounts applications bind to the LDAP directory as.
pub mod directory_service;
/// Authentication domain events.
pub mod events;
/// Who may rename or take away an account's ways in, and end its sessions.
pub mod keeper;
/// LDAP client certificates. They are the possession factor that a simple
/// bind cannot carry.
pub mod ldap_certificate;
/// The ways a caller may prove who they are, and how hard they must try.
pub mod methods;
/// MFA enrollment and verification.
pub mod mfa;
/// Sign-in steps whose rules span more than one aggregate.
pub mod operations;
/// Account recovery through recovery codes and password resets.
pub mod recovery;
/// Risk scoring, rate limiting and step-up policies.
pub mod risk_engine;
/// Session lifecycle, handoffs, second-factor challenges and timeouts.
pub mod sessions;
/// The numbers every sign-in configuration sets, and their ranges.
pub mod sign_in_limits;
/// Refresh tokens.
pub mod tokens;
