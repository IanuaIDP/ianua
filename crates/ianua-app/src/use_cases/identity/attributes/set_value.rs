//! Set a user's value for one custom attribute, or clear it.
//!
//! One use case for both namespaces. A person keeps their own `user`
//! attributes from their own session; everything else, an administrator's
//! own `app` attributes included, is written by someone who may edit the
//! person's profile.
//!
//! Every write goes through the tenant's declared schema. A key nobody
//! declared is refused rather than stored: values under an undeclared name
//! could not be shown, filtered, sorted, reviewed or erased.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::attribute::metadata_change::MetadataChange;
use ianua_domain::domains::identity::attribute::{
    AttributeKey, AttributeNamespace, AttributeWriter, MetadataSchema,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::{MetadataStore, UserAttributeStore};
use crate::ports::shared::AuditLabelResolver;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::attributes::declared_schema::declared_schema;
use crate::use_cases::identity::audit_label::resolved_user_label;
use crate::use_cases::identity::whose::Whose;

/// One attribute value to write or clear.
pub struct SetValueRequest {
    /// Whose value it is.
    pub whose: Whose,
    /// Which namespace the attribute is declared in.
    pub namespace: AttributeNamespace,
    /// The attribute's key.
    pub key: AttributeKey,
    /// The new value, or `None` to clear it.
    pub value: Option<MetadataValue>,
}

/// The ports [`SetValueUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetValuePorts {
    /// Keeps values.
    pub metadata_store: Arc<dyn MetadataStore>,
    /// Reads the declarations a value is checked against.
    pub attribute_store: Arc<dyn UserAttributeStore>,
    /// Names the person in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Writes or clears one custom attribute value.
pub struct SetValueUseCase {
    ports: SetValuePorts,
}

/// Whose attribute changes, which one, and who writes it.
#[derive(Clone, Copy)]
struct ChangedAttribute<'a> {
    user_id: UserId,
    namespace: AttributeNamespace,
    key: &'a AttributeKey,
    writer: AttributeWriter,
}

impl SetValueUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetValuePorts) -> Self {
        Self { ports }
    }

    /// The person whose value it is, and who writes it, once the caller may.
    async fn writer(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<(UserId, AttributeWriter), AppError> {
        match whose {
            Whose::Own => {
                let person = self.ports.tenant_authorities.signed_in(ctx).await?;
                Ok((*person.account.id(), AttributeWriter::Holder))
            }
            Whose::OnBehalfOf(user_id) => {
                let authority = self.ports.tenant_authorities.authority(ctx).await?;
                let records = self.ports.access_records.as_ref();
                let tenant = ctx.tenant();
                let editing = AccountAction::EditProfile;
                account_control(records, &tenant, &authority, &user_id, editing)
                    .await?
                    .ensure_allowed(&user_id, AccountAction::EditProfile)
                    .map_err(AppError::from_domain)?;
                Ok((user_id, AttributeWriter::Administrator))
            }
        }
    }

    /// Writes `value`, or clears the value when there is none.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        changed: &ChangedAttribute<'_>,
        value: Option<&MetadataValue>,
    ) -> Result<(), AppError> {
        let store = self.ports.metadata_store.as_ref();
        let user_id = &changed.user_id;
        let Some(value) = value else {
            return store
                .delete_value(tenant, user_id, changed.namespace, changed.key)
                .await
                .or_internal();
        };
        let label = value_label(changed.key)?;
        match changed.namespace {
            AttributeNamespace::User => store.set_user_value(tenant, user_id, &label, value).await,
            AttributeNamespace::App => store.set_app_value(tenant, user_id, &label, value).await,
        }
        .or_internal()
    }
}

impl Command for SetValueUseCase {
    type Caller = CallerContext;
    type Input = SetValueRequest;
    type Output = Result<(), AppError>;

    /// Sets a value for an attribute, or clears it when `request.value` is
    /// `None`.
    ///
    /// Clearing is refused for an attribute the tenant declared required, so
    /// a field everyone must hold cannot be emptied one person at a time.
    /// The record names who changed which attribute, never the value: it may
    /// be a salary or a health note.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the person writes an `app` attribute of
    ///   their own, or someone else may not edit their profile.
    /// - `AppError::Domain` if no such attribute is declared, or the value
    ///   does not meet the declaration.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SetValueRequest,
    ) -> Result<(), AppError> {
        let SetValueRequest {
            whose,
            namespace,
            key,
            value,
        } = request;
        let tenant = ctx.tenant();
        let (user_id, writer) = self.writer(ctx, whose).await?;
        let changed = ChangedAttribute {
            user_id,
            namespace,
            key: &key,
            writer,
        };
        let schema = declared_schema(self.ports.attribute_store.as_ref(), &tenant).await?;
        ensure_acceptable(&schema, &changed, value.as_ref()).map_err(AppError::from_domain)?;

        self.store(&tenant, &changed, value.as_ref()).await?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let user_label = resolved_user_label(resolver, &tenant, &user_id).await;
        let mut change =
            MetadataChange::<ResolvedTenant>::one_value(user_id, user_label, namespace, key);
        auditor
            .dispatch_by(&ctx.actor(), change.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses a value the declaration does not take from this writer, or
/// emptying a field the tenant said everyone must hold.
fn ensure_acceptable(
    schema: &MetadataSchema<ResolvedTenant>,
    changed: &ChangedAttribute<'_>,
    value: Option<&MetadataValue>,
) -> Result<(), DomainError> {
    if let Some(value) = value {
        return schema.validate_value(changed.namespace, changed.key, value, changed.writer);
    }
    changed.namespace.ensure_writable_by(changed.writer)?;
    let Some(declaration) = schema.find(changed.namespace, changed.key) else {
        return Err(DomainError::invalid(message!(
            "identity-no-attribute-named-has-been-declared-2",
            format!("no attribute named '{}' has been declared", changed.key)
        )));
    };
    if declaration.required() {
        return Err(DomainError::invalid(message!(
            "identity-is-required-and-cannot-be-cleared",
            format!("'{}' is required and cannot be cleared", changed.key)
        )));
    }
    Ok(())
}

/// The label a value is kept under. Every attribute key is also a valid
/// label, so a refusal here is a broken rule rather than bad input.
fn value_label(key: &AttributeKey) -> Result<Label, AppError> {
    Label::new("attribute_key", key.as_str()).or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::identity::attribute::AttributeKind;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::{
        FakeMetadataStore, FakeUserAttributeStore, access_where_holds, declaration, declared,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    fn tier() -> Label {
        Label::new("attribute_key", "tier").unwrap()
    }

    /// Ann, signed in, a `tier` declared in both namespaces, and the values
    /// kept.
    struct Directory {
        ann: UserId,
        values: Arc<FakeMetadataStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Directory {
        fn new() -> Self {
            Self {
                ann: UserId::new(),
                values: Arc::new(FakeMetadataStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> SetValuePorts {
            let declared_tier =
                |namespace| declared(declaration("tier", namespace, AttributeKind::Text));
            SetValuePorts {
                metadata_store: self.values.clone(),
                attribute_store: Arc::new(FakeUserAttributeStore::holding(vec![
                    declared_tier(AttributeNamespace::User),
                    declared_tier(AttributeNamespace::App),
                ])),
                ..SetValuePorts::fakes()
            }
        }

        fn write(
            &self,
            ports: SetValuePorts,
            whose: Whose,
            namespace: AttributeNamespace,
        ) -> Result<(), AppError> {
            let seeded = test_ctx();
            let as_ann = test_ctx_with(seeded.organization_id(), seeded.tenant_id(), self.ann);
            block_on(SetValueUseCase::new(ports).execute(
                &as_ann,
                &test_auditor(self.sink.clone()),
                SetValueRequest {
                    whose,
                    namespace,
                    key: AttributeKey::new("tier").unwrap(),
                    value: Some(MetadataValue::from("gold")),
                },
            ))
        }
    }

    /// Ann sets her own `user` tier. It is kept and the change recorded,
    /// without the value.
    #[test]
    fn a_person_writes_their_own_user_attribute() {
        let directory = Directory::new();

        directory
            .write(directory.ports(), Whose::Own, AttributeNamespace::User)
            .unwrap();

        assert!(directory.values.has_user_value(&directory.ann, &tier()));
        let recorded = format!("{:?}", directory.sink.all_payloads());
        assert!(!recorded.contains("gold"));
    }

    /// Ann sets her own `app` tier, the one billing keeps. It is refused.
    #[test]
    fn a_person_cannot_write_their_own_app_attribute() {
        let directory = Directory::new();

        let result = directory.write(directory.ports(), Whose::Own, AttributeNamespace::App);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!directory.values.has_app_value(&directory.ann, &tier()));
    }

    /// Ann, an admin, sets Bob's `app` tier. It is kept.
    #[test]
    fn an_administrator_writes_someones_app_attribute() {
        let directory = Directory::new();
        let bob = UserId::new();

        directory
            .write(
                directory.ports(),
                Whose::OnBehalfOf(bob),
                AttributeNamespace::App,
            )
            .unwrap();

        assert!(directory.values.has_app_value(&bob, &tier()));
    }

    /// Ann writes an attribute nobody declared. It is refused.
    #[test]
    fn an_undeclared_attribute_is_refused() {
        let directory = Directory::new();
        let ports = SetValuePorts {
            attribute_store: Arc::new(FakeUserAttributeStore::empty()),
            ..directory.ports()
        };

        let result = directory.write(ports, Whose::Own, AttributeNamespace::User);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// User-viewing rights do not permit setting Bob's tier. The refusal
    /// leaves him without the requested value.
    #[test]
    fn someone_who_may_not_edit_the_profile_is_refused() {
        let directory = Directory::new();
        let bob = UserId::new();
        let ports = SetValuePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::View),
            ])),
            ..directory.ports()
        };

        let result = directory.write(ports, Whose::OnBehalfOf(bob), AttributeNamespace::User);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!directory.values.has_user_value(&bob, &tier()));
    }

    /// A user updater cannot set Bob's app tier while Bob holds broader
    /// user-management rights.
    #[test]
    fn a_person_holding_more_than_the_caller_is_refused() {
        let directory = Directory::new();
        let bob = UserId::new();
        let ports = SetValuePorts {
            access_records: access_where_holds(bob, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..directory.ports()
        };

        let result = directory.write(ports, Whose::OnBehalfOf(bob), AttributeNamespace::App);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann cannot set her own user attribute after signing out.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let directory = Directory::new();
        let ports = SetValuePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..directory.ports()
        };

        let result = directory.write(ports, Whose::Own, AttributeNamespace::User);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
