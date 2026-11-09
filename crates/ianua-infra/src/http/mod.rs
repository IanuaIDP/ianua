//! Outbound HTTP: the clients every call out of the deployment is made
//! with, and the adapters that call out.
//!
//! Every address a tenant chose is checked before the call and screened
//! again when its name resolves ([`client::screened`]); every address the
//! platform chose goes through [`client::fixed`]. Each call has its own
//! time limit, no redirect is followed, and an answer that is read is
//! read within a size limit. An error names the status it ended on, never
//! the address, the body or a credential. The gateway asks the API's
//! internal listener about app sign-ins and agent approvals over one sealed
//! channel, each kind under a key of its own. The runner beside an agent's
//! sandbox attests and exchanges its agent's task tokens with the API.

mod approvals;
mod calls;
pub mod client;
mod deliveries;
mod logs;
mod models;
mod posture;
mod relay;
mod runner;
mod sign_in;
mod signing;
mod tools;

pub use approvals::{HttpApprovalBroker, NoApprovalBroker};
pub use deliveries::{
    HttpDestinationPoster, HttpPushDeliverer, HttpSignalDeliverer, HttpWebhookBodies,
    HttpWebhookDeliverer,
};
pub use logs::{HttpAuditStreamSender, HttpLogShipper};
pub use models::{HttpEmbedder, HttpModelClient, PlatformEmbeddings};
pub use posture::{HttpPostureProvider, NoPostureProvider};
pub use runner::{HttpRunnerKeys, HttpRunnerTokens, RunnerAgent, SvidFiles, TokenAsk};
pub use sign_in::{
    ChallengeSettings, HttpAppSignInBroker, HttpBackChannelLogoutSender, HttpChallengeVerifier,
    HttpCredentialBreachChecker, HttpOidcValidator, HttpPublishedKeys, PWNED_PASSWORDS,
    TURNSTILE_SITEVERIFY,
};
pub use tools::HttpToolInvoker;
