//! How a delegation gains and loses one resource capability after it was
//! granted, never past the ceiling it was cut from.

use crate::domains::agents::authority::capability::{Relation, ResourceCapability, ResourceRef};
use crate::domains::agents::authority::delegation::ceiling::ensure_within;
use crate::domains::agents::authority::delegation::{
    Delegation, ResourceCeiling, Revoker, recorded,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;

impl<T: TenantScope> Delegation<T> {
    /// Adds a resource within `ceiling`; an existing grant remains unchanged.
    /// Raises `agents.delegation_resource_granted` even for an existing grant.
    ///
    /// # Errors
    /// [`DomainError::InvalidTransition`] if revoked.
    /// [`DomainError::Forbidden`] for token-owned grants, a mismatched delegator or parent,
    /// an actor unable to widen the root or speak for the parent holder, another person's
    /// holdings supplied as the delegator's, or a result exceeding `ceiling`.
    pub fn grant_resource(
        &mut self,
        capability: &ResourceCapability,
        ceiling: &ResourceCeiling<'_, T>,
    ) -> Result<(), DomainError> {
        if self.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "agents-cannot-modify-a-revoked-delegation",
                "cannot modify a revoked delegation"
            )));
        }
        if !self.granted.resources().contains(capability) {
            self.widen(capability, ceiling)?;
        }
        recorded::resource_granted(self, capability.relation(), capability.resource_ref());
        Ok(())
    }

    /// Adds `capability`, which this delegation does not grant yet, as long
    /// as the result stays inside `ceiling`.
    fn widen(
        &mut self,
        capability: &ResourceCapability,
        ceiling: &ResourceCeiling<'_, T>,
    ) -> Result<(), DomainError> {
        let mut resources = self.granted.resources().to_vec();
        resources.push(capability.clone());
        let widened = self.granted.clone().with_resources(resources);
        ensure_within(self, &widened, ceiling)?;
        self.granted = widened;
        self.updated_at = clock::now();
        Ok(())
    }

    /// Removes the resource capability for `relation` on `resource_ref`, and
    /// keeps the rest of what this delegation grants.
    ///
    /// Removing one the delegation does not grant changes nothing. Either
    /// way, the delegation does not grant it afterwards.
    ///
    /// Raises `agents.delegation_resource_revoked`, also when the
    /// delegation did not grant it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a person who neither granted it nor
    ///   has a say over its agent removes it.
    /// - [`DomainError::InvalidTransition`] when this delegation is revoked.
    pub fn revoke_resource(
        &mut self,
        by: Revoker<'_>,
        relation: &Relation,
        resource_ref: &ResourceRef,
    ) -> Result<(), DomainError> {
        by.ensure_may_revoke(&self.delegator)?;
        if self.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "agents-cannot-modify-a-revoked-delegation",
                "cannot modify a revoked delegation"
            )));
        }
        let before = self.granted.resources().len();
        let resources: Vec<ResourceCapability> = self
            .granted
            .resources()
            .iter()
            .filter(|c| c.relation() != relation || c.resource_ref() != resource_ref)
            .cloned()
            .collect();
        if resources.len() != before {
            self.granted = self.granted.clone().with_resources(resources);
            self.updated_at = clock::now();
        }
        recorded::resource_revoked(self, relation, resource_ref);
        Ok(())
    }
}
