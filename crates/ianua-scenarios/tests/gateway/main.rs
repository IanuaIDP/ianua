//! The gateway, as tenants' apps and the people and agents who use them
//! meet it: started beside the platform, in front of real apps, every route
//! made through the API and awaited until the gateway serves it. Each
//! scenario reads what the gateway recorded of its requests, and what the
//! app behind the route saw.
//!
//! - `starts`: the gateway starts ready beside the platform, refuses a
//!   host it does not serve, and stops cleanly.
//! - `public`: anyone reaches a public route, and no identity a client
//!   claims reaches the app.
//! - `signed_in`: Pat signed in on the shop's own host, at its API by the
//!   tokens its pages fetch, and registering at the shop; nobody else gets
//!   through, and a sign-in owing a code is finished only in Pat's browser.
//! - `hosts`: Wiki on the tenant's random platform label, flat and nested,
//!   on no other tenant's label, and on a readable name only once Tess
//!   opts in.
//! - `federation`: independent OIDC and SAML providers sign Pat in at the
//!   shop, only in the browser that began the sign-in; a forged SAML
//!   answer lets nobody in.
//! - `passkeys`: Pat's passkey signs in at the shop once; a copied answer
//!   opens no second session.
//! - `handoffs`: a second app of the shop's lets Pat in only once the
//!   handoff sets a cookie of its own there.
//! - `agents`: an agent with its task token and its key's proof reaches
//!   an app, acting for whoever delegated to it; without the proof nothing
//!   does.
//! - `policy`: a tenant's policy refusing a group holds at the gateway,
//!   and its records name the rule and the version that decided.
//! - `failures`: an app that never answers times out at the route's
//!   timeout, one that drops the connection is a bad gateway.
//! - `access`: who a route lets in by permission, group and role, how a
//!   change reaches the next request, and a route that cannot be decided.
//! - `trust`: what a caller claims is dropped and only the gateway's signed
//!   word reaches the app; forged sessions and tokens, and a session left
//!   idle, let nobody in.
//! - `traffic`: WebSocket and bodies moved through without being held,
//!   rate limits, an outage refusing rather than letting through, and a
//!   stuck app holding nobody else up.

#![cfg(test)]

mod access;
mod agents;
mod failures;
mod federation;
mod handoffs;
mod hosts;
mod passkeys;
mod policy;
mod public;
mod signed_in;
mod starts;
mod support;
mod traffic;
mod trust;
