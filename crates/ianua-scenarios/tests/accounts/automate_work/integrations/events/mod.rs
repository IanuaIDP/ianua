//! Connecting an account by signing in at its service, and the service's
//! events starting workflows, each against a stand-in that issues tokens,
//! takes registrations and sends what the service sends.
//!
//! - `azure`: Tess signs in through Microsoft naming the organization, and
//!   a work item created in Web starts Ann's workflow through the service
//!   hook publishing subscribed.
//! - `connect`: what they share: signing in at a stand-in, a signed
//!   delivery, the address with its secret, the runs a delivery started.
//! - `github`: Tess signs in at GitHub, and an issue opened in acme/web
//!   starts Ann's workflow once, through the webhook publishing
//!   registered; a forged or resent delivery starts nothing.
//! - `gitlab`: an issue opened in project 42 starts Ann's workflow once,
//!   through the project webhook publishing registered with the
//!   registration's secret as its token; another token or a resent
//!   delivery starts nothing.
//! - `google`: Tess signs in at Google, and a change to the team calendar
//!   starts Ann's workflow through the watch channel publishing opened; a
//!   notification with another token, and the channel's first message,
//!   start nothing.
//! - `jira`: Tess signs in at Atlassian naming acme.atlassian.net, and an
//!   issue created in OPS starts Ann's workflow through the webhook
//!   registered on Acme's site.
//! - `linear`: an issue created in the engineering team starts Ann's
//!   workflow through the webhook publishing registered, signed with its
//!   secret and sent just now; one signed otherwise or minutes ago starts
//!   nothing.
//! - `mailgun`: mail failing for good on the domain starts Ann's workflow
//!   through the webhook whose address carries its secret.
//! - `pagerduty`: an incident triggered on checkout starts Ann's workflow
//!   once, through the subscription publishing made with the secret in a
//!   header of its own; an incident on another service, a resend and a
//!   delivery without the secret start nothing.
//! - `replays`: a made-up state, a replayed callback and a spent one-time
//!   code reach no second token and connect nothing.
//! - `slack`: Tess signs in at Slack, and a message posted in #support
//!   starts Ann's workflow, which replies in its thread; a forged delivery
//!   and the bot's own reply start nothing.
//! - `trello`: Trello's `HEAD` check of an event address is answered alike
//!   for every address, before any registration is kept; a card created
//!   on the Web board starts Ann's workflow through the address with its
//!   secret, and the bare address starts nothing.
//! - `twilio`: a text to the support number starts Ann's workflow, which
//!   texts back, through the number pointed at the registration.
//!
//! A delivery to a registration's address without its secret, or signed
//! otherwise, starts nothing in each.

mod azure;
pub(super) mod connect;
mod github;
mod gitlab;
mod google;
mod jira;
mod linear;
mod mailgun;
mod pagerduty;
mod replays;
mod slack;
mod trello;
mod twilio;
