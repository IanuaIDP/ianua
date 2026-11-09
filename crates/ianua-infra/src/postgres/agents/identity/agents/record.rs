//! An agent as its row holds it: read back into the aggregate, and written
//! out from it. Its owner and the person it was offered to are kept as a
//! human is everywhere, and its attestation policy whole, as JSON.

use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, AgentIdentityRow, AgentProof, Containment, OwnershipOffer,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, Human, Label};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, human_from, maybe_human_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const AGENT: Stored = Stored("agent");

const ATTESTATION_POLICY: Kept = Kept {
    entity: AGENT.0,
    column: "attestation_policy",
    shape: 1,
};

/// An agent as it is read. The store's checked queries fill it.
pub(crate) struct AgentRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) owner_kind: String,
    pub(crate) owner_id: Uuid,
    pub(crate) owner_person: String,
    pub(crate) offered_to_kind: Option<String>,
    pub(crate) offered_to_id: Option<Uuid>,
    pub(crate) offered_to_person: Option<String>,
    pub(crate) offered_at: Option<OffsetDateTime>,
    pub(crate) offer_expires_at: Option<OffsetDateTime>,
    pub(crate) status: String,
    pub(crate) attestation_policy: Option<Value>,
    pub(crate) reattestation_required_since: Option<OffsetDateTime>,
    pub(crate) last_attested_at: Option<OffsetDateTime>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl AgentRecord {
    /// The agent the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, half an offer is kept, or the row
    /// breaks a rule the agent keeps.
    pub(crate) fn into_agent(mut self) -> Result<AgentIdentity<ResolvedTenant>, DomainError> {
        let offer = self.offer()?;
        AgentIdentity::reconstitute(AgentIdentityRow {
            id: AgentId::from_uuid(self.id),
            name: AGENT.value("name", Label::new("name", self.name))?,
            description: self
                .description
                .map(|text| AGENT.value("description", Label::new("description", text)))
                .transpose()?,
            owner: human_from(AGENT, &self.owner_kind, self.owner_id, self.owner_person)?,
            offer,
            status: AGENT.choice(&self.status)?,
            proof: proof_from(self.attestation_policy)?,
            containment: containment_from(self.reattestation_required_since),
            last_attested_at: self.last_attested_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// The offer the five offer columns hold: none when all are empty.
    fn offer(&mut self) -> Result<OwnershipOffer, DomainError> {
        let recipient = maybe_human_from(
            AGENT,
            self.offered_to_kind.take(),
            self.offered_to_id.take(),
            self.offered_to_person.take(),
        )?;
        match (recipient, self.offered_at, self.offer_expires_at) {
            (None, None, None) => Ok(OwnershipOffer::Unoffered),
            (Some(recipient), Some(offered_at), Some(expires_at)) => Ok(OwnershipOffer::Open {
                recipient,
                offered_at,
                expires_at,
            }),
            (_, _, _) => Err(DomainError::corrupt_row(AGENT.0, "half an offer")),
        }
    }
}

/// How the agent proves itself: by attesting under the stored policy, or
/// with an enrolled key when none is stored.
fn proof_from(policy: Option<Value>) -> Result<AgentProof, DomainError> {
    let Some(policy) = policy else {
        return Ok(AgentProof::EnrolledKey);
    };
    Ok(AgentProof::Attestation(ATTESTATION_POLICY.open(policy)?))
}

fn containment_from(since: Option<OffsetDateTime>) -> Containment {
    since.map_or(Containment::Free, |since| {
        Containment::ReattestationRequired { since }
    })
}

/// An agent's columns, as they are written.
pub(super) struct AgentColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) description: Option<&'a str>,
    pub(super) owner: HumanColumns<'a>,
    pub(super) offered_to: Option<HumanColumns<'a>>,
    pub(super) offered_at: Option<OffsetDateTime>,
    pub(super) offer_expires_at: Option<OffsetDateTime>,
    pub(super) status: &'static str,
    pub(super) attestation_policy: Option<Value>,
    pub(super) reattestation_required_since: Option<OffsetDateTime>,
    pub(super) last_attested_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> AgentColumns<'a> {
    /// The columns `agent` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the attestation policy
    /// cannot be written out as JSON.
    pub(super) fn of(agent: &'a AgentIdentity<ResolvedTenant>) -> Result<Self, DomainError> {
        let attestation_policy = agent
            .attestation_policy()
            .map(|policy| ATTESTATION_POLICY.seal(policy))
            .transpose()?;
        Ok(Self {
            id: agent.id().as_uuid(),
            name: agent.name().as_str(),
            description: agent.description().map(Label::as_str),
            owner: HumanColumns::of(agent.owner()),
            offered_to: recipient_of(agent.offer()).map(HumanColumns::of),
            offered_at: agent.offer().offered_at(),
            offer_expires_at: agent.offer().expires_at(),
            status: agent.status().word(),
            attestation_policy,
            reattestation_required_since: agent.containment().since(),
            last_attested_at: agent.last_attested_at(),
            created_at: agent.created_at(),
            updated_at: agent.updated_at(),
        })
    }

    /// The kind of the account the agent was offered to, if it was.
    pub(super) fn offered_to_kind(&self) -> Option<&'static str> {
        self.offered_to.as_ref().map(|columns| columns.kind)
    }

    /// The account the agent was offered to, if it was.
    pub(super) fn offered_to_id(&self) -> Option<Uuid> {
        self.offered_to.as_ref().map(|columns| columns.id)
    }

    /// The person the agent was offered to, if it was.
    pub(super) fn offered_to_person(&self) -> Option<&'a str> {
        self.offered_to.as_ref().map(|columns| columns.person)
    }
}

/// The person `offer` was made to, open or lapsed.
fn recipient_of(offer: &OwnershipOffer) -> Option<&Human> {
    match offer {
        OwnershipOffer::Open { recipient, .. } => Some(recipient),
        OwnershipOffer::Unoffered => None,
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin,
    };
    use ianua_domain::types::Seconds;
    use serde_json::json;

    use super::*;

    /// An attestation policy is written in the shape pinned here, and a row
    /// in that shape reads back the same.
    #[test]
    fn an_attestation_policy_is_stored_in_its_pinned_shape() {
        let policy = AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://acme/agents").unwrap()],
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "trusted_methods": ["Spiffe"],
            "reattest_interval_seconds": 3600,
            "allowed_origins": ["spiffe://acme/agents"],
            "workload_trusts": [],
        }});

        assert_eq!(ATTESTATION_POLICY.seal(&policy).unwrap(), stored);
        let read: AttestationPolicy = ATTESTATION_POLICY.open(stored.clone()).unwrap();
        assert_eq!(ATTESTATION_POLICY.seal(&read).unwrap(), stored);
    }
}
