//! What routing use cases share: reachability of upstreams, signing a
//! connector's certificate, and holding stages to the tenant's own
//! classification rules.

pub(crate) mod connector_certificates;
pub(crate) mod reachability;
pub(crate) mod rule_sets;
