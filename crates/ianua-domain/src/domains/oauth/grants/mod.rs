//! What OAuth hands out: codes, tokens and device authorizations.

pub mod access_token;
pub mod authorization_code;
/// An authorization request a browser brings, screened before anyone signs in.
pub mod authorization_request;
/// Where a device authorization request stands: pending, approved, denied,
/// expired or redeemed.
pub mod device_auth_status;
pub mod device_authorization;
pub mod id_token;
/// The grant an ID token is issued for: a code, a refresh or a device
/// approval.
pub mod id_token_grant;
/// What a verified `id_token_hint` says.
pub mod id_token_hint;
/// Access tokens as signed JWTs a resource server checks on its own.
pub mod jwt_access_token;
/// Where a person goes after an app signs them out through ianua.
pub mod logout;
/// How an app's server took the logout token it was sent.
pub mod logout_delivery;
/// Telling apps that a person signed out: logout tokens and front-channel
/// pages.
pub mod logout_notice;
/// Authorization requests a client pushes before sending the browser.
pub mod pushed_request;
/// What a client brings to start or use a refresh token, and why a use is
/// refused.
pub mod refresh_terms;
/// Refresh tokens, rotated on each use, their family revoked on reuse.
pub mod refresh_token;
/// What a token is asked to be meant for, and the tunnels a token may open.
pub mod resource;
/// The claims about a person a grant's scopes let out.
pub mod scoped_claims;
/// Tokens bound to a key or certificate their holder proves.
pub mod token_binding;
/// Exchanging a token for a narrower one for another audience.
pub mod token_exchange;
/// The claims `userinfo` answers with.
pub mod userinfo;
