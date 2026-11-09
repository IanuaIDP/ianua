//! Delete user metadata: remove every custom attribute value a user holds.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::attribute::metadata_change::MetadataChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::MetadataStore;
use crate::ports::shared::AuditLabelResolver;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::audit_label::resolved_user_label;

/// The ports [`DeleteUserMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteUserMetadataPorts {
    /// Keeps values.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// Names the person in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes every custom attribute value of a user of the caller's tenant.
pub struct DeleteUserMetadataUseCase {
    ports: DeleteUserMetadataPorts,
}

impl DeleteUserMetadataUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeleteUserMetadataPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUserMetadataUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<(), AppError>;

    /// Deletes the values of `user_id` in both namespaces, for a caller who
    /// may edit their profile.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit the user's
    ///   profile, or the user holds more than the caller.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        user_id: UserId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        account_control(
            self.ports.access_records.as_ref(),
            &tenant,
            &authority,
            &user_id,
            AccountAction::EditProfile,
        )
        .await?
        .ensure_allowed(&user_id, AccountAction::EditProfile)
        .map_err(AppError::from_domain)?;

        self.ports
            .metadata_store
            .delete_for_user(&tenant, &user_id)
            .await
            .or_internal()?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let user_label = resolved_user_label(resolver, &tenant, &user_id).await;
        let mut change = MetadataChange::<ResolvedTenant>::every_value(user_id, user_label);
        auditor
            .dispatch_by(&ctx.actor(), change.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::metadata_value::MetadataValue;
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeMetadataStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Bob, holding a theme, and what deleting his values records.
    struct Bob {
        bob: UserId,
        values: Arc<FakeMetadataStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bob {
        fn new() -> Self {
            let bob = UserId::new();
            let values = Arc::new(FakeMetadataStore::empty());
            values.insert_user_value(
                &bob,
                Label::new("attribute_key", "theme").unwrap(),
                MetadataValue::from("dark"),
            );
            Self {
                bob,
                values,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn delete(&self, tenant_authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = DeleteUserMetadataUseCase::new(DeleteUserMetadataPorts {
                metadata_store: self.values.clone(),
                tenant_authorities: Arc::new(tenant_authorities),
                ..DeleteUserMetadataPorts::fakes()
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), self.bob))
        }
    }

    /// Ann deletes Bob's values. They are gone and the deletion is recorded.
    #[test]
    fn a_users_values_are_deleted_and_recorded() {
        let bob = Bob::new();

        bob.delete(FakeTenantAuthorities::holding_everything())
            .unwrap();

        assert!(bob.values.is_empty_for(&bob.bob));
        assert_eq!(
            bob.sink.records.lock().unwrap().as_slice(),
            ["identity.metadata_deleted"]
        );
    }

    /// User-viewing rights do not permit deleting Bob's attribute values.
    /// His values remain after the refusal.
    #[test]
    fn a_caller_who_may_not_edit_the_profile_is_refused() {
        let bob = Bob::new();

        let result = bob.delete(FakeTenantAuthorities::holding(&[SystemPermission::Users(
            UserAction::View,
        )]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!bob.values.is_empty_for(&bob.bob));
    }

    /// A signed-out caller cannot delete Bob's attribute values.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bob = Bob::new();

        let result = bob.delete(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
