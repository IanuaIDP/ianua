//! A delegation as its row holds it: read back into the aggregate, and
//! written out from it. What it grants and its limits are each one JSON
//! value; the sources a minted one was cut from are rows of their own, and
//! so are the named resources it grants a relation on, kept for lookup.

use std::collections::HashMap;

use ianua_app::ports::agents::{ResourceHolder, RevokedDelegation};
use ianua_domain::domains::agents::authority::capability::{Relation, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentCredentialId, AgentId, DelegationId, Label, PrincipalRef};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::agents::identity::delegations::words::LineageKind;
use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const DELEGATION: Stored = Stored("delegation");

const GRANTED: Kept = Kept {
    entity: DELEGATION.0,
    column: "granted",
    shape: 1,
};

const LIMITS: Kept = Kept {
    entity: DELEGATION.0,
    column: "limits",
    shape: 1,
};

/// A delegation as it is read. The store's checked queries fill it.
pub(super) struct DelegationRecord {
    pub(super) id: Uuid,
    pub(super) delegator_kind: String,
    pub(super) delegator_id: Uuid,
    pub(super) delegate_id: Uuid,
    pub(super) granted: Value,
    pub(super) limits: Value,
    pub(super) lineage: String,
    pub(super) parent_id: Option<Uuid>,
    pub(super) minted_delegator_kind: Option<String>,
    pub(super) minted_delegator_id: Option<Uuid>,
    pub(super) minted_credential_id: Option<Uuid>,
    pub(super) minted_from: Vec<Uuid>,
    pub(super) depth: i16,
    pub(super) status: String,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) renewed_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
    pub(super) name: Option<String>,
}

impl DelegationRecord {
    /// The delegation the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the lineage misses its parent or its
    /// sources, or the row breaks a rule the delegation keeps.
    pub(super) fn into_delegation(self) -> Result<Delegation<ResolvedTenant>, DomainError> {
        let lineage = self.lineage()?;
        Delegation::reconstitute(DelegationRow {
            id: DelegationId::from_uuid(self.id),
            delegator: principal_from(DELEGATION, &self.delegator_kind, self.delegator_id)?,
            delegate: AgentId::from_uuid(self.delegate_id),
            granted: GRANTED.open(self.granted)?,
            constraints: LIMITS.open(self.limits)?,
            lineage,
            depth: u8::try_from(self.depth)
                .map_err(|_| DomainError::corrupt_row(DELEGATION.0, "a depth out of range"))?,
            status: DELEGATION.choice(&self.status)?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            renewed: self
                .renewed_at
                .map_or(DelegationRenewal::NotRenewed, DelegationRenewal::RenewedAt),
            updated_at: self.updated_at,
            name: self
                .name
                .map(|text| DELEGATION.value("name", Label::new("name", text)))
                .transpose()?,
        })
    }

    /// Where the delegation sits in its chain, from its lineage word and
    /// the columns beside it.
    fn lineage(&self) -> Result<Lineage, DomainError> {
        match DELEGATION.choice::<LineageKind>(&self.lineage)? {
            LineageKind::Root => Ok(Lineage::Root),
            LineageKind::Under => {
                let parent = self.parent_id.ok_or_else(|| {
                    DomainError::corrupt_row(DELEGATION.0, "a sub-delegation without its parent")
                })?;
                Ok(Lineage::Under(DelegationId::from_uuid(parent)))
            }
            LineageKind::Minted => self.minted(),
        }
    }

    /// The lineage of a minted delegation: the sources it was cut from, who
    /// granted them, and the key the agent signed in with to mint it.
    fn minted(&self) -> Result<Lineage, DomainError> {
        let (Some(kind), Some(id)) = (
            self.minted_delegator_kind.as_deref(),
            self.minted_delegator_id,
        ) else {
            return Err(DomainError::corrupt_row(
                DELEGATION.0,
                "a minted delegation without who granted its sources",
            ));
        };
        let Some(key) = self.minted_credential_id else {
            return Err(DomainError::corrupt_row(
                DELEGATION.0,
                "a minted delegation without the key it was minted with",
            ));
        };
        Ok(Lineage::Minted {
            from: self
                .minted_from
                .iter()
                .copied()
                .map(DelegationId::from_uuid)
                .collect(),
            delegator: principal_from(DELEGATION, kind, id)?,
            signed_in_with: AgentCredentialId::from_uuid(key),
        })
    }
}

/// An agent holding a relation on one resource, as the holders query
/// reads it.
pub(super) struct HolderRecord {
    pub(super) delegate_id: Uuid,
    pub(super) relation: String,
}

impl HolderRecord {
    /// The holder the record names.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the relation no longer
    /// passes its rules.
    pub(super) fn into_holder(self) -> Result<ResourceHolder, DomainError> {
        Ok(ResourceHolder {
            agent: AgentId::from_uuid(self.delegate_id),
            relation: DELEGATION.value("relation", Relation::new(self.relation))?,
        })
    }
}

/// One root and descendant reached by the batched revocation walk.
pub(super) struct ClosureRecord {
    pub(super) root: Uuid,
    pub(super) id: Uuid,
}

/// Groups reached descendants under their roots without changing each
/// root's returned order.
pub(super) fn closures_from(
    records: Vec<ClosureRecord>,
) -> HashMap<DelegationId, Vec<DelegationId>> {
    let mut closures: HashMap<DelegationId, Vec<DelegationId>> = HashMap::new();
    for record in records {
        closures
            .entry(DelegationId::from_uuid(record.root))
            .or_default()
            .push(DelegationId::from_uuid(record.id));
    }
    closures
}

/// A delegation a revoke changed, as the revoke reads it back.
pub(super) struct RevokedRecord {
    pub(super) id: Uuid,
    pub(super) delegate_id: Uuid,
}

impl RevokedRecord {
    /// The revoked delegation the record names.
    pub(super) fn into_revoked(self) -> RevokedDelegation {
        RevokedDelegation {
            id: DelegationId::from_uuid(self.id),
            delegate: AgentId::from_uuid(self.delegate_id),
        }
    }
}

/// A delegation's columns, as they are written, with the rows kept beside
/// it.
pub(super) struct DelegationColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) delegator_kind: &'static str,
    pub(super) delegator_id: Uuid,
    pub(super) delegate_id: &'a Uuid,
    pub(super) granted: Value,
    pub(super) limits: Value,
    pub(super) lineage: &'static str,
    pub(super) parent_id: Option<Uuid>,
    pub(super) minted_delegator_kind: Option<&'static str>,
    pub(super) minted_delegator_id: Option<Uuid>,
    pub(super) minted_credential_id: Option<Uuid>,
    pub(super) sources: Vec<Uuid>,
    pub(super) depth: i16,
    pub(super) status: &'static str,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) renewed_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
    pub(super) name: Option<&'a str>,
    pub(super) relations: Vec<String>,
    pub(super) resource_refs: Vec<String>,
}

impl<'a> DelegationColumns<'a> {
    /// The columns `delegation` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when what it grants or its
    /// limits cannot be written out as JSON.
    pub(super) fn of(delegation: &'a Delegation<ResolvedTenant>) -> Result<Self, DomainError> {
        let (relations, resource_refs) = resource_columns(delegation.granted().resources());
        Ok(Self {
            id: delegation.id().as_uuid(),
            delegator_kind: kind_word(delegation.delegator()),
            delegator_id: delegation.delegator().id(),
            delegate_id: delegation.delegate().as_uuid(),
            granted: GRANTED.seal(delegation.granted())?,
            limits: LIMITS.seal(delegation.constraints())?,
            lineage: LineageKind::from(delegation.lineage()).word(),
            parent_id: delegation.parent().map(|parent| *parent.as_uuid()),
            minted_delegator_kind: minted_delegator(delegation.lineage())
                .map(|delegator| kind_word(&delegator)),
            minted_delegator_id: minted_delegator(delegation.lineage())
                .map(|delegator| delegator.id()),
            minted_credential_id: minted_with(delegation.lineage()),
            sources: sources_of(delegation.lineage()),
            depth: i16::from(delegation.depth()),
            status: status_of(delegation).word(),
            issued_at: delegation.created_at(),
            expires_at: delegation.expires_at(),
            renewed_at: delegation.renewed().at(),
            updated_at: delegation.updated_at(),
            name: delegation.name().map(Label::as_str),
            relations,
            resource_refs,
        })
    }
}

/// Keeps each relation aligned with its resource reference for the bulk write.
fn resource_columns(resources: &[ResourceCapability]) -> (Vec<String>, Vec<String>) {
    resources
        .iter()
        .map(|capability| {
            (
                capability.relation().as_str().to_owned(),
                capability.resource_ref().as_str().to_owned(),
            )
        })
        .unzip()
}

/// Who granted the sources of a minted delegation, if it is one.
fn minted_delegator(lineage: &Lineage) -> Option<PrincipalRef> {
    match lineage {
        Lineage::Minted { delegator, .. } => Some(*delegator),
        Lineage::Root | Lineage::Under(_) => None,
    }
}

/// The key a minted delegation was minted with, if it is one.
fn minted_with(lineage: &Lineage) -> Option<Uuid> {
    match lineage {
        Lineage::Minted { signed_in_with, .. } => Some(*signed_in_with.as_uuid()),
        Lineage::Root | Lineage::Under(_) => None,
    }
}

/// The delegations a minted delegation was cut from, in their order; none
/// for any other.
fn sources_of(lineage: &Lineage) -> Vec<Uuid> {
    match lineage {
        Lineage::Minted { from, .. } => from.iter().map(|source| *source.as_uuid()).collect(),
        Lineage::Root | Lineage::Under(_) => Vec::new(),
    }
}

fn status_of(delegation: &Delegation<ResolvedTenant>) -> DelegationStatus {
    if delegation.is_revoked() {
        return DelegationStatus::Revoked;
    }
    DelegationStatus::Active
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints, ResourceCapability, ResourceRef,
    };
    use ianua_domain::types::Seconds;
    use serde_json::json;

    use super::*;

    /// What a delegation grants is written in the shape pinned here, and a
    /// row in that shape reads back the same.
    #[test]
    fn what_a_delegation_grants_is_stored_in_its_pinned_shape() {
        let granted = CapabilitySet::empty().with_resources(vec![ResourceCapability::new(
            Relation::new("reader").unwrap(),
            ResourceRef::new("calendar:q1").unwrap(),
        )]);
        let stored = json!({"v": 1, "value": {
            "http": [],
            "messaging": [],
            "resources": [{"relation": "reader", "resource_ref": "calendar:q1"}],
            "mcp": {"classed_tools": [], "resources": [], "prompts": []},
        }});

        assert_eq!(GRANTED.seal(&granted).unwrap(), stored);
        let read: CapabilitySet = GRANTED.open(stored.clone()).unwrap();
        assert_eq!(GRANTED.seal(&read).unwrap(), stored);
    }

    /// A delegation's limits are written in the shape pinned here, and a
    /// row in that shape reads back the same.
    #[test]
    fn the_limits_of_a_delegation_are_stored_in_their_pinned_shape() {
        let limits = DelegationConstraints::new(Seconds::new(600), 2).unwrap();
        let stored = json!({"v": 1, "value": {
            "ttl_seconds": 600,
            "max_depth": 2,
            "task": null,
            "budget": "unrestricted",
            "intent": "unrestricted",
            "resource_scope": "unrestricted",
            "apps": "no_apps",
            "approval": "not_required",
            "binding": "bearer",
            "max_data_class": "unrestricted",
            "template": "unrestricted",
        }});

        assert_eq!(LIMITS.seal(&limits).unwrap(), stored);
        let read: DelegationConstraints = LIMITS.open(stored.clone()).unwrap();
        assert_eq!(LIMITS.seal(&read).unwrap(), stored);
    }
}
