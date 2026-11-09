//! App sign-in: the gateway answering sign-in addresses on an app's host.
//!
//! A service's app sign-in names the hosts and paths. A request to one of
//! them never reaches the app: the gateway checks that a page on the host
//! itself sent it (a mailed link and a provider sending the browser back
//! excepted), counts it against its address's limit, reads it, and relays it
//! to the API, which decides. The answer comes back as values, and the
//! cookies the browser gets are set here: every one `__Host-`, `Secure`,
//! `HttpOnly` but the CSRF value, `Path=/`, named by the request layer,
//! which takes them all out of what it forwards to the app.
//!
//! Every action the wire defines is answered: logging in, signing up, the
//! second factor, the mailed links (each at an address of its own:
//! verifying an address, confirming a sign-in, resetting a password,
//! changing one), signing out, single sign-on and its return by `GET` or
//! `POST`, passkeys, asking for and setting a new password, the new password
//! a sign-in owes, tokens for a service accepting the sign-in by token, and
//! the hops setting it on hosts of a service's own cookie. Under the prefix,
//! loading an address shows its page, which the API draws and the gateway
//! serves under a policy that runs no script but the login page's passkey
//! script, which the gateway serves itself at one fixed address; anything
//! else under the prefix is refused and never reaches the app.
//!
//! A hop's code works only in the browser that signed in. The browser first
//! keeps a random value in a cookie of the other host, then fetches a code
//! bound to its digest from the owner's host, where its session is, and
//! brings the code back beside the value. A hop link sent to someone else
//! sets nothing in their browser.
//!
//! The request layer asks [`addressed`] what a request on such a host is,
//! hands a sign-in request to [`answer`] and a hop to [`hop`], and answers a
//! refused address with [`respond::page_refused`].

mod address;
mod answer;
mod commands;
mod cookies;
mod fields;
mod origin;
mod respond;
mod signed_out;

pub use address::{Addressed, Asked, addressed};
pub use answer::{Arrived, Gate, Inbound, answer};
pub(crate) use answer::{HopArrived, hop};
pub(crate) use signed_out::login_redirect;

/// What the gateway answers a request at a sign-in address with.
pub type Response = http::Response<http_body_util::Full<hyper::body::Bytes>>;
