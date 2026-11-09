//! Reaching a customer's own cloud account: proving the credential they
//! handed us opens the account it claims to, and listing the places in it
//! a database could live.
//!
//! One factory per cloud builds its verifier and its discovery over one
//! shared client, so a network found in one cloud is never paired with
//! another cloud's credential. Every cloud is called over its HTTP API: a
//! cloud's own hosts through the fixed client, a customer's Kubernetes
//! API server, an address they chose, through the screened one. Each call
//! is held to a few seconds and each whole check to a little more.
//!
//! A refusal by the cloud of the customer's credential is theirs to fix
//! and reads as forbidden, with a reason they can act on. Anything else,
//! our own credentials refused, a cloud that fails or does not answer, an
//! answer that cannot be read, is ours and reads as an infrastructure
//! error. No secret, token or signature ever reaches an error or a log.

mod answers;
mod aws;
mod azure;
mod digitalocean;
mod endpoint;
mod gcp;
mod kubernetes;
mod registry;

pub use aws::{AwsCloudProviderFactory, AwsPlatformCredentials};
pub use azure::AzureCloudProviderFactory;
pub use digitalocean::DigitalOceanCloudProviderFactory;
pub use endpoint::CloudEndpoint;
pub use gcp::GcpCloudProviderFactory;
pub use kubernetes::KubernetesCloudProviderFactory;
pub use registry::ConfiguredCloudProviderRegistry;
