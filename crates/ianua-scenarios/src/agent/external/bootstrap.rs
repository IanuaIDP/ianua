//! An agent that holds no standing key: it proves where it runs with a
//! platform attestation, and the platform enrols the key it made for that
//! one bootstrap.

use super::attest::{SPIFFE, Workload};
use super::{ExternalAgent, UnenrolledAgent};
use crate::agent::keys::{ALGORITHM, AgentKey};
use crate::api::TenantPath;
use crate::api::agents::{attestation, lifecycle};
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::Answer;
use crate::wire::agents::attestation::{Attestation, Bootstrap, Challenge};
use crate::wire::agents::identity::{Credential, EnrolledKey, NewAgent};

/// The most seconds between two attestations an agent made here is held
/// to.
const RE_ATTEST_EVERY: u32 = 3600;

/// The external agent's name and the workload identity proving its bootstrap.
#[derive(Clone, Copy)]
pub struct BootstrapAgent<'a> {
    /// The agent's label in the API and scenario diagnostics.
    pub name: &'a str,
    /// The workload whose SVID proves the agent's origin.
    pub workload: &'a Workload,
}

impl ExternalAgent {
    /// Creates the requested agent in `tenant` for `owner`, bootstrapped
    /// from its workload's SVID.
    ///
    /// # Panics
    ///
    /// When the agent cannot be made, or its bootstrap is refused.
    pub async fn bootstrapped(
        stack: &Stack,
        tenant: &TenantPath,
        owner: &Client,
        request: BootstrapAgent<'_>,
    ) -> Self {
        let BootstrapAgent { name, workload } = request;
        let made = NewAgent {
            name: name.to_owned(),
            description: Some(format!("{name}, attested by its workload")),
            trusted_methods: Some(vec![SPIFFE.to_owned()]),
            re_attest_every: Some(RE_ATTEST_EVERY),
            allowed_origins: Some(vec![workload.spiffe_id().to_owned()]),
            key: None,
        };
        let created = lifecycle::create(tenant, &made).send(owner).await.ok();
        let mut agent = Self::unenrolled(
            stack,
            tenant,
            UnenrolledAgent {
                name,
                id: &created.id,
                key: AgentKey::generate(),
            },
        );
        let credential = agent.attest(workload).await.ok();
        agent.kid = credential.kid;
        agent.credential_id = credential.id;
        agent
    }

    /// A single-use challenge for its next bootstrap.
    pub async fn challenge(&self) -> Answer<Challenge> {
        attestation::challenge(&self.tenant, &self.id)
            .send(&self.client)
            .await
    }

    /// Bootstraps its own key with `presented`.
    pub async fn bootstrap(&self, presented: Attestation) -> Answer<Credential> {
        let bootstrap = Bootstrap {
            key: EnrolledKey {
                algorithm: ALGORITHM.to_owned(),
                public_key: self.key.public_pem(),
            },
            attestation: presented,
        };
        attestation::bootstrap(&self.tenant, &self.id, &bootstrap)
            .send(&self.client)
            .await
    }

    /// Asks for a challenge and bootstraps its own key as `workload`.
    ///
    /// # Panics
    ///
    /// When no challenge is issued.
    pub async fn attest(&self, workload: &Workload) -> Answer<Credential> {
        let challenge = self.challenge().await.ok();
        self.bootstrap(workload.attestation(&challenge.nonce, &self.key))
            .await
    }
}
