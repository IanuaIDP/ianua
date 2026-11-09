//! An egress policy as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_app::ports::routing::ClaimedEgressPolicy;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::egress::{EgressPolicy, EgressPolicyRow, ServiceIdentity};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EgressPolicyId, Label, PrincipalRef, TenantId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const EGRESS_POLICY: Stored = Stored("egress policy");

const DESTINATIONS: Kept = Kept {
    entity: EGRESS_POLICY.0,
    column: "destinations",
    shape: 1,
};

/// An egress policy as it is read. The store's checked queries fill it.
pub(super) struct EgressPolicyRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) service: String,
    pub(super) destinations: Value,
    pub(super) max_data_class: String,
    pub(super) created_by_kind: String,
    pub(super) created_by: Uuid,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl EgressPolicyRecord {
    /// The policy the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the policy
    /// keeps.
    pub(super) fn into_policy(self) -> Result<EgressPolicy<ResolvedTenant>, DomainError> {
        EgressPolicy::reconstitute(EgressPolicyRow {
            id: EgressPolicyId::from_uuid(self.id),
            name: EGRESS_POLICY.value("name", Label::new("name", self.name))?,
            service: EGRESS_POLICY.value("service", ServiceIdentity::new(self.service))?,
            destinations: DESTINATIONS.open(self.destinations)?,
            max_data_class: DataClassLevel::from_stored(&self.max_data_class)?,
            created_by: PrincipalRef::from_parts(&self.created_by_kind, self.created_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// One tenant's egress policy for a service, as the egress gateway reads
/// it across tenants. The store's checked query fills it.
pub(super) struct ClaimRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) service: String,
    pub(super) destinations: Value,
    pub(super) max_data_class: String,
    pub(super) created_by_kind: String,
    pub(super) created_by: Uuid,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ClaimRecord {
    /// The tenant's policy the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// As [`EgressPolicyRecord::into_policy`].
    pub(super) fn into_claim(self) -> Result<ClaimedEgressPolicy, DomainError> {
        let policy = EgressPolicyRecord {
            id: self.id,
            name: self.name,
            service: self.service,
            destinations: self.destinations,
            max_data_class: self.max_data_class,
            created_by_kind: self.created_by_kind,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .into_policy()?;
        Ok(ClaimedEgressPolicy {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            policy,
        })
    }
}

/// An egress policy's columns, as they are written.
pub(super) struct EgressPolicyColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) service: &'a str,
    pub(super) destinations: Value,
    pub(super) max_data_class: &'static str,
    pub(super) created_by_kind: &'static str,
    pub(super) created_by: Uuid,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> EgressPolicyColumns<'a> {
    /// The columns `policy` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its destinations cannot be
    /// written out as JSON.
    pub(super) fn of(policy: &'a EgressPolicy<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: policy.id().as_uuid(),
            name: policy.name().as_str(),
            service: policy.service().as_str(),
            destinations: DESTINATIONS.seal(&policy.destinations())?,
            max_data_class: policy.max_data_class().as_str(),
            created_by_kind: policy.created_by().kind(),
            created_by: policy.created_by().id(),
            created_at: policy.created_at(),
            updated_at: policy.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::routing::egress::EgressDestination;
    use ianua_domain::types::DomainName;
    use serde_json::json;

    use super::*;

    /// The destinations are written in the shape pinned here, and a row in
    /// that shape reads back.
    #[test]
    fn the_destinations_are_stored_in_their_pinned_shape() {
        let destinations =
            vec![EgressDestination::new(DomainName::new("api.github.com").unwrap(), 443).unwrap()];
        let stored = json!({"v": 1, "value": [{"host": "api.github.com", "port": 443}]});

        assert_eq!(DESTINATIONS.seal(&destinations).unwrap(), stored);
        assert_eq!(
            DESTINATIONS.open::<Vec<EgressDestination>>(stored).unwrap(),
            destinations
        );
    }
}
