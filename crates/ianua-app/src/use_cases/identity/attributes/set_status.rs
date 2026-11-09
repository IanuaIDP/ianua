//! Withdraw a user attribute from use, or bring it back.
//!
//! The reversible half of removing a field. Archiving takes it off every
//! form, listing, filter and sort while keeping every value stored under it,
//! so an archive made in error costs nothing to undo. Discarding the values
//! is [`delete_user_attribute`](crate::use_cases::identity::attributes::delete),
//! which is separate because it cannot be undone.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace, SchemaControlCheck,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserAttributeStore;
use crate::use_case::Command;
use crate::use_cases::identity::lookup::existing_attribute;

/// Whether an attribute should be in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Offered on forms, carried by listings, available to filters.
    InUse,
    /// Hidden everywhere, with its stored values kept.
    Withdrawn,
}

/// The state to put one declared attribute in.
pub struct SetStatusRequest {
    /// Which namespace the attribute is declared in.
    pub namespace: AttributeNamespace,
    /// The attribute's key.
    pub key: AttributeKey,
    /// In use, or withdrawn.
    pub status: Status,
}

/// The ports [`SetStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetStatusPorts {
    /// Reads and saves declarations.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws an attribute of the caller's tenant from use, or brings it
/// back.
pub struct SetStatusUseCase {
    ports: SetStatusPorts,
}

impl SetStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for SetStatusUseCase {
    type Caller = CallerContext;
    type Input = SetStatusRequest;
    type Output = Result<AttributeDefinition<ResolvedTenant>, AppError>;

    /// Puts an attribute into or out of use, for a caller who may change the
    /// schema.
    ///
    /// Asking for the state it is already in changes nothing and is not an
    /// error: the caller wanted it withdrawn, and it is.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the schema.
    /// - `AppError::NotFound` if nothing is declared under that name.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SetStatusRequest,
    ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
        let SetStatusRequest {
            namespace,
            key,
            status,
        } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_change_schema()
            .map_err(AppError::from_domain)?;
        let store = self.ports.attribute_store.as_ref();
        let mut definition = existing_attribute(store, &tenant, namespace, &key).await?;
        if is_already(&definition, status) {
            return Ok(definition);
        }
        set_status(&mut definition, status, &authority).map_err(AppError::from_domain)?;

        store.save(&tenant, &definition).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), definition.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(definition)
    }
}

/// Whether the attribute is already in the requested state.
fn is_already(definition: &AttributeDefinition<ResolvedTenant>, status: Status) -> bool {
    match status {
        Status::Withdrawn => definition.archived(),
        Status::InUse => !definition.archived(),
    }
}

/// Puts the attribute into the requested state, as `by` may.
fn set_status(
    definition: &mut AttributeDefinition<ResolvedTenant>,
    status: Status,
    by: &TenantAuthority,
) -> Result<(), DomainError> {
    match status {
        Status::Withdrawn => definition.archive(by),
        Status::InUse => definition.restore(by),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::AttributeKind;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{FakeUserAttributeStore, declaration, declared};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant declaring `tier`, and what a status change records.
    struct Tier {
        attributes: Arc<FakeUserAttributeStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tier {
        fn new() -> Self {
            let tier = declared(declaration(
                "tier",
                AttributeNamespace::App,
                AttributeKind::Text,
            ));
            Self {
                attributes: Arc::new(FakeUserAttributeStore::holding(vec![tier])),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> SetStatusPorts {
            SetStatusPorts {
                attribute_store: self.attributes.clone(),
                ..SetStatusPorts::fakes()
            }
        }

        fn set(
            &self,
            ports: SetStatusPorts,
            status: Status,
        ) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
            block_on(SetStatusUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                SetStatusRequest {
                    namespace: AttributeNamespace::App,
                    key: AttributeKey::new("tier").unwrap(),
                    status,
                },
            ))
        }
    }

    /// Ann withdraws `tier`. It is archived and the withdrawal recorded.
    #[test]
    fn a_withdrawal_archives_the_attribute() {
        let tier = Tier::new();

        let withdrawn = tier.set(tier.ports(), Status::Withdrawn).unwrap();

        assert!(withdrawn.archived());
        assert_eq!(
            tier.sink.records.lock().unwrap().as_slice(),
            ["identity.attribute_archived"]
        );
    }

    /// Ann brings `tier` back after withdrawing it. It is in use again.
    #[test]
    fn a_withdrawn_attribute_comes_back() {
        let tier = Tier::new();
        tier.set(tier.ports(), Status::Withdrawn).unwrap();

        let restored = tier.set(tier.ports(), Status::InUse).unwrap();

        assert!(!restored.archived());
    }

    /// Ann puts `tier` in use while it is in use. Nothing changes and
    /// nothing is recorded.
    #[test]
    fn asking_for_the_state_it_has_changes_nothing() {
        let tier = Tier::new();

        tier.set(tier.ports(), Status::InUse).unwrap();

        assert!(tier.sink.records.lock().unwrap().is_empty());
    }

    /// User-viewing rights do not permit withdrawing the tier attribute.
    #[test]
    fn a_caller_who_may_not_change_the_schema_is_refused() {
        let tier = Tier::new();
        let ports = SetStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..tier.ports()
        };

        let result = tier.set(ports, Status::Withdrawn);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot withdraw the tier attribute.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tier = Tier::new();
        let ports = SetStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tier.ports()
        };

        let result = tier.set(ports, Status::Withdrawn);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
