//! How the worker reaches the gateway's workflow listener, which its
//! Protected apps steps call: `GATEWAY_WORKFLOW_URL`, over mutual TLS with
//! the internal authority in `GATEWAY_WORKFLOW_CA_FILE` and the worker's
//! own certificate and key, or plain HTTP outside production. The rules
//! are the shared ones of `ianua_boot::internal_link`.

use ianua_boot::internal_link::LinkSettings;

/// The settings the workflow link is read from.
pub(crate) const WORKFLOW_LINK: LinkSettings = LinkSettings {
    url: "GATEWAY_WORKFLOW_URL",
    authority: "GATEWAY_WORKFLOW_CA_FILE",
    certificate: "GATEWAY_WORKFLOW_CLIENT_CERT_FILE",
    key: "GATEWAY_WORKFLOW_CLIENT_KEY_FILE",
};
