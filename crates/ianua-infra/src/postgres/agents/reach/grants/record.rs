//! A resource grant as its row holds it: the relation held and the
//! resource it is held on, read back into the domain's capability, and the
//! columns a grant is written to.

use ianua_domain::domains::agents::authority::capability::{
    Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PrincipalRef;
use uuid::Uuid;

use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::stored::Stored;

const GRANT: Stored = Stored("resource grant");

/// A relation a principal holds, as the store's checked query reads it.
pub(super) struct GrantRecord {
    pub(super) relation: String,
    pub(super) object_ref: String,
}

impl GrantRecord {
    /// The capability the record holds, through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the relation or the
    /// resource no longer passes its rules.
    pub(super) fn into_capability(self) -> Result<ResourceCapability, DomainError> {
        Ok(ResourceCapability::new(
            GRANT.value("relation", Relation::new(self.relation))?,
            GRANT.value("resource", ResourceRef::new(self.object_ref))?,
        ))
    }
}

/// A principal as its two columns hold it.
pub(super) struct PrincipalColumns {
    pub(super) kind: &'static str,
    pub(super) id: Uuid,
}

impl PrincipalColumns {
    /// The columns `principal` is written to.
    pub(super) fn of(principal: &PrincipalRef) -> Self {
        Self {
            kind: kind_word(principal),
            id: principal.id(),
        }
    }
}

/// Relations on resources, one list per column and one place per
/// capability, as one statement reads them.
pub(super) struct WantedColumns {
    pub(super) relations: Vec<String>,
    pub(super) object_refs: Vec<String>,
}

impl WantedColumns {
    /// The columns `wanted` is asked for in.
    pub(super) fn of(wanted: &[ResourceCapability]) -> Self {
        Self {
            relations: wanted
                .iter()
                .map(|capability| capability.relation().as_str().to_owned())
                .collect(),
            object_refs: wanted
                .iter()
                .map(|capability| capability.resource_ref().as_str().to_owned())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuilding a resource grant with an empty relation returns a corruption
    /// error.
    #[test]
    fn a_row_with_an_empty_relation_is_refused() {
        let record = GrantRecord {
            relation: String::new(),
            object_ref: "calendar:q1".to_owned(),
        };

        let read = record.into_capability();

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
