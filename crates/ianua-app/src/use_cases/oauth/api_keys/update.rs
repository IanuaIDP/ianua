//! Renaming an API key or changing what it may do.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::api_key::ApiKeyChange;
use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ApiKeyId, Label, Scope};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::ApiKeyStore;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::{ensure_key_still_kept, existing_api_key};

/// What to change on a key. `None` leaves a field as it is.
pub struct UpdateRequest {
    /// The key to change.
    pub key_id: ApiKeyId,
    /// The new name.
    pub name: Option<Label>,
    /// The new scopes, replacing the old ones.
    pub scopes: Option<Vec<Scope>>,
}

impl UpdateRequest {
    /// The changes the request names, in the order they are made.
    fn changes(self) -> Vec<ApiKeyChange> {
        let renamed = self.name.map(ApiKeyChange::Rename);
        let scoped = self.scopes.map(ApiKeyChange::Scopes);
        renamed.into_iter().chain(scoped).collect()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes an API key's name or scopes.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Changes the fields `req` names on the key. Records `ApiKeyUpdated`
    /// when anything changed; a request naming no field changes and records
    /// nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update keys, or the
    ///   key carries or would carry a permission they do not hold.
    /// - `AppError::NotFound` when the tenant has no such key. A revoked key
    ///   is deleted, so it reads as not found.
    /// - `AppError::Domain` when the new scopes are empty or one names no
    ///   permission.
    /// - `AppError::Internal` when the key cannot be read, saved or audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Update)
            .map_err(AppError::from_domain)?;
        let store = self.ports.key_store.as_ref();
        let tenant = caller.tenant();
        let mut key = existing_api_key(store, &tenant, &req.key_id).await?;
        let changes = req.changes();
        if changes.is_empty() {
            return Ok(());
        }
        key.update(changes, &control)
            .map_err(AppError::from_domain)?;
        ensure_key_still_kept(store.update(&tenant, &key).await)?;
        auditor
            .dispatch_by(&caller.actor(), key.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        ApiKeyAction, RoutingAction, SystemPermission,
    };
    use ianua_domain::domains::oauth::clients::api_key::ApiKey;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    struct Fixture {
        store: Arc<FakeApiKeyStore>,
        key_id: ApiKeyId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            let key = stored_api_key("CI", test_ctx().actor());
            let key_id = *key.id();
            Self {
                store: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
                key_id,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn change(&self) -> UpdateRequest {
            UpdateRequest {
                key_id: self.key_id,
                name: None,
                scopes: None,
            }
        }

        fn update(&self, req: UpdateRequest) -> Result<(), AppError> {
            self.update_as(FakeTenantAuthorities::holding_everything(), req)
        }

        fn update_as(
            &self,
            authorities: FakeTenantAuthorities,
            req: UpdateRequest,
        ) -> Result<(), AppError> {
            let use_case = UpdateUseCase::new(UpdatePorts {
                key_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), req))
        }

        fn saved(&self) -> ApiKey<ResolvedTenant> {
            block_on(self.store.find_by_id(&test_ctx().tenant(), &self.key_id))
                .unwrap()
                .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn scoped_to(&self, scope: &str) -> UpdateRequest {
            UpdateRequest {
                scopes: Some(vec![Scope::new(scope).unwrap()]),
                ..self.change()
            }
        }
    }

    /// Ann renames the CI key to "Deploy". The new name is kept and the
    /// change recorded.
    #[test]
    fn a_rename_is_kept_and_recorded() {
        let fixture = Fixture::new();

        fixture
            .update(UpdateRequest {
                name: Some(Label::new("name", "Deploy").unwrap()),
                ..fixture.change()
            })
            .unwrap();

        assert_eq!(fixture.saved().name().as_str(), "Deploy");
        assert_eq!(fixture.recorded(), ["oauth.api_key_updated"]);
    }

    /// Ann lets the CI key read the audit log instead of routes. The key now
    /// carries only that.
    #[test]
    fn new_scopes_replace_the_old_ones() {
        let fixture = Fixture::new();

        fixture
            .update(fixture.scoped_to("idp:audit_log:view"))
            .unwrap();

        let scopes = fixture.saved().scopes().to_vec();
        assert_eq!(scopes, [Scope::new("idp:audit_log:view").unwrap()]);
    }

    /// A scope naming no permission is refused, preserving the key's
    /// route-view scope.
    #[test]
    fn a_scope_naming_no_permission_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.update(fixture.scoped_to("projects:read"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.saved().scopes()[0].as_str(), "idp:routing:view");
    }

    /// Ann sends a change naming nothing. Nothing is saved or recorded.
    #[test]
    fn a_change_naming_nothing_records_nothing() {
        let fixture = Fixture::new();

        fixture.update(fixture.change()).unwrap();

        assert!(fixture.recorded().is_empty());
    }

    /// Renaming an unknown API key returns not found and records no event.
    #[test]
    fn an_unknown_key_is_not_found() {
        let fixture = Fixture::new();

        let result = fixture.update(UpdateRequest {
            key_id: ApiKeyId::new(),
            name: Some(Label::new("name", "Ghost").unwrap()),
            scopes: None,
        });

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A caller with only API-key view permission cannot rename the CI key.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.update_as(
            FakeTenantAuthorities::holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]),
            UpdateRequest {
                name: Some(Label::new("name", "Sam's").unwrap()),
                ..fixture.change()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An updater lacking user-management permission cannot grant that
    /// scope to the key, which retains its route-view scope.
    #[test]
    fn a_scope_beyond_the_changer_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.update_as(
            FakeTenantAuthorities::holding(&[
                SystemPermission::ApiKeys(ApiKeyAction::Update),
                SystemPermission::Routing(RoutingAction::View),
            ]),
            fixture.scoped_to("idp:users:manage"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.saved().scopes()[0].as_str(), "idp:routing:view");
    }

    /// A signed-out caller receives unauthenticated when changing API-key scopes.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.update_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.scoped_to("idp:users:manage"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A rename that reads a stale key snapshot but writes after deletion
    /// returns not found. The key stays absent and no event is recorded.
    #[test]
    fn a_change_racing_a_revocation_does_not_bring_the_key_back() {
        let fixture = Fixture::new();
        let revoked = Arc::new(FakeApiKeyStore::empty());
        let use_case = UpdateUseCase::new(UpdatePorts {
            key_store: Arc::new(ReadBeforeWrite::new(
                FakeApiKeyStore::holding(&test_ctx().tenant(), fixture.saved()),
                revoked.clone(),
            )),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let rename = UpdateRequest {
            name: Some(Label::new("name", "Deploy").unwrap()),
            ..fixture.change()
        };

        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(fixture.audit.clone()), rename));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(revoked.count(), 0);
        assert!(fixture.recorded().is_empty());
    }
}
