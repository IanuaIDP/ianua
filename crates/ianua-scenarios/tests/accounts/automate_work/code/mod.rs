//! Code steps and the sandboxes they run in.
//!
//! - `running`: a workflow runs real JavaScript and Python in containers of
//!   their own, through the container command, the sandbox gate and pods
//!   on Kubernetes; code finds no network, is stopped at its limit, and a
//!   second run on the cluster takes a warm pod.
//! - `gate`: the sandbox gate as a self-hosted server runs it; a forged ask
//!   starts nothing.
//! - `network`: a version reaches the hosts it names through the network
//!   filter and no other, and does not run where there is no filter.
//! - `building`: a saved version's packages are fetched once each, checked
//!   against their fingerprints and built into a bundle; a fingerprint that
//!   does not match fails the version.
//! - `trials`: a version is tried on sample input and its answer or error
//!   read back; only those who may change workflows try one.
//! - `repositories`: a version's code is imported from a GitHub file at
//!   the commit its branch points to, and a version is pushed back.
//! - `registry`: a stand-in npm registry for those packages.
//! - `held_agents`: a version holding an agent and the code checking its
//!   answers; an answer the check turns back is tried again, and the step
//!   fails when every try breaks the rule.
//! - `images`: a company's own image from an allowed registry, pinned to
//!   its digest and scanned before it runs, answering JSON for JSON; a
//!   registry nobody allowed and a critical finding are refused.

mod building;
mod gate;
mod held_agents;
mod images;
mod network;
mod registry;
mod repositories;
mod running;
mod trials;
