//! Stop mapping groups: a connection's provider groups bring nothing here
//! any more.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConnectionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ConnectionStore;
use crate::use_case::Command;
use crate::use_cases::federation::lookup::existing_connection;

/// The ports [`StopMappingGroupsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StopMappingGroupsPorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Turns a connection's group mapping off.
pub struct StopMappingGroupsUseCase {
    ports: StopMappingGroupsPorts,
}

impl StopMappingGroupsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StopMappingGroupsPorts) -> Self {
        Self { ports }
    }
}

impl Command for StopMappingGroupsUseCase {
    type Caller = CallerContext;
    type Input = ConnectionId;
    type Output = Result<(), AppError>;

    /// Turns the mapping off and records `federation.connection_updated`.
    /// It only stops the provider handing out rights, so the update right
    /// is enough, as in an incident. What people were given through it stays
    /// until their next sign-in takes it back.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not update connections.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        connection_id: ConnectionId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::EditConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.connection_store.as_ref();
        let mut conn = existing_connection(store, &tenant, &connection_id).await?;
        conn.stop_mapping_groups(&control)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &conn).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection::{
        GroupMapping, GroupRule, GroupRules, MappedGrant, ProviderGroupName,
    };
    use ianua_domain::types::{Label, RoleId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{
        FakeConnectionStore, test_saml_connection, test_saml_settings,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Acme's Okta, mapping `engineering` to a role.
    fn mapping() -> (Arc<FakeConnectionStore>, ConnectionId) {
        let id = ConnectionId::new();
        let rules = GroupRules::new(
            Label::new("claim", "groups").unwrap(),
            vec![GroupRule {
                provider_group: ProviderGroupName::new("engineering").unwrap(),
                grant: MappedGrant::Role(RoleId::new()),
            }],
        )
        .unwrap();
        let conn = test_saml_connection(id, test_saml_settings(), GroupMapping::On(rules));
        let store = FakeConnectionStore::holding(&test_ctx().tenant(), [conn]);
        (Arc::new(store), id)
    }

    fn stop(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: ConnectionId,
    ) -> Result<(), AppError> {
        let use_case = StopMappingGroupsUseCase::new(StopMappingGroupsPorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn saved_mapping(store: &FakeConnectionStore, id: &ConnectionId) -> GroupMapping {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .group_mapping()
            .clone()
    }

    /// Okta's groups were mapped by mistake. Sam, who may update
    /// connections, turns the mapping off in the incident, and the change is
    /// recorded.
    #[test]
    fn the_update_right_turns_the_mapping_off() {
        let (store, id) = mapping();
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];

        stop(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(saved_mapping(&store, &id), GroupMapping::Off);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Sam names a connection his tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = stop(
            Arc::new(FakeConnectionStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            ConnectionId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A federation viewer cannot disable group mapping. The refusal leaves
    /// the mapping on and records no update event.
    #[test]
    fn a_viewer_cannot_turn_the_mapping_off() {
        let (store, id) = mapping();
        let audit = Arc::new(FakeEventDispatcher::new());
        let view = [SystemPermission::Federation(FederationAction::View)];

        let result = stop(
            store.clone(),
            FakeTenantAuthorities::holding(&view),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(matches!(saved_mapping(&store, &id), GroupMapping::On(_)));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot disable provider group mapping.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = mapping();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = stop(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
