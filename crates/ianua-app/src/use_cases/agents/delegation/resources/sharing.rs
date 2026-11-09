//! Shared resources between agents: the message board a person must approve.
//!
//! Two agents holding rights on the same object, where either may write, can
//! pass anything through it: one writes, the other reads. That is a channel
//! between them whether anyone meant one or not, so granting it needs a
//! channel a person opened for that object. Two agents that only read may
//! share freely; nothing passes between readers.
//!
//! Checked whenever an agent is granted resource rights. A channel that closes
//! later does not take back rights already granted; revoking the delegation
//! does.

use ianua_domain::domains::agents::authority::capability::{ResourceCapability, ResourceRef};
use ianua_domain::domains::agents::channels::channel::{
    AgentChannel, SharedObject, sharing_needs_channel,
};
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::AgentId;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{DelegationStore, ResourceHolder};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::messaging::AgentChannelStore;
use crate::tenancy::ScopedTenant;

/// Where sharing is checked against: who holds what, the channels people
/// opened, and the tenant's resource types with their data class.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents) struct SharingStores<'a> {
    /// The delegations, for who holds rights on an object.
    pub(in crate::use_cases::agents) delegations: &'a dyn DelegationStore,
    /// The channels people opened between agents.
    pub(in crate::use_cases::agents) channels: &'a dyn AgentChannelStore,
    /// The tenant's resource types, for how sensitive an object is.
    pub(in crate::use_cases::agents) resource_types: &'a dyn ResourceTypeStore,
}

/// The agent being given a resource, and the tenant it lives in.
pub(in crate::use_cases::agents) struct SharingAgent<'a> {
    /// The agent's tenant.
    pub(in crate::use_cases::agents) tenant_id: &'a ScopedTenant,
    /// The identity receiving access to the shared resource.
    pub(in crate::use_cases::agents) agent: &'a AgentId,
}

/// Refuses resource rights that would let `agent` exchange data with another
/// agent through a shared object, unless a person opened a channel for that
/// object between the two.
///
/// # Errors
///
/// - `AppError::Forbidden` naming the object when a channel is missing.
/// - `AppError::Internal` when the holders or channels cannot be read.
pub(in crate::use_cases::agents) async fn refuse_unchanneled_sharing(
    stores: SharingStores<'_>,
    sharing: SharingAgent<'_>,
    wanted: &[ResourceCapability],
) -> Result<(), AppError> {
    for capability in wanted {
        let holders = stores
            .delegations
            .resource_holders(sharing.tenant_id, capability.resource_ref())
            .await
            .or_internal()?;
        for holder in holders
            .iter()
            .filter(|holder| needs_channel(holder, sharing.agent, capability))
        {
            ensure_channel(stores, &sharing, holder, capability).await?;
        }
    }
    Ok(())
}

/// Refuses sharing `wanted` with `holder` over no open channel a person
/// opened for that object.
async fn ensure_channel(
    stores: SharingStores<'_>,
    sharing: &SharingAgent<'_>,
    holder: &ResourceHolder,
    wanted: &ResourceCapability,
) -> Result<(), AppError> {
    let (tenant_id, agent) = (sharing.tenant_id, sharing.agent);
    let now = clock::now();
    let between = channels_between(stores, sharing, holder).await?;
    let object = SharedObject {
        resource: wanted.resource_ref(),
        class: class_of(stores.resource_types, tenant_id, wanted.resource_ref()).await?,
    };
    if between
        .iter()
        .any(|channel| channel.shares(agent, &holder.agent, object, now))
    {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-another-agent-holds-rights-on-sharing",
        format!(
            "another agent holds rights on {}; sharing it needs a channel a person opened",
            wanted.resource_ref().as_str()
        )
    )))
}

/// Every channel still open between the sharing agent and `holder`, sent
/// either way.
async fn channels_between(
    stores: SharingStores<'_>,
    sharing: &SharingAgent<'_>,
    holder: &ResourceHolder,
) -> Result<Vec<AgentChannel<ResolvedTenant>>, AppError> {
    let (tenant_id, agent) = (sharing.tenant_id, sharing.agent);
    let mut between = stores
        .channels
        .unclosed_between(tenant_id, agent, &holder.agent)
        .await
        .or_internal()?;
    between.extend(
        stores
            .channels
            .unclosed_between(tenant_id, &holder.agent, agent)
            .await
            .or_internal()?,
    );
    Ok(between)
}

/// How sensitive `resource`'s data is: its resource type's data class, or
/// restricted when its type is not declared.
async fn class_of(
    resource_types: &dyn ResourceTypeStore,
    tenant: &ScopedTenant,
    resource: &ResourceRef,
) -> Result<DataClassLevel, AppError> {
    let Some(key) = resource
        .type_key()
        .and_then(|kind| PermissionSegment::new("resource_type_key", kind).ok())
    else {
        return Ok(DataClassLevel::Restricted);
    };
    let declared = resource_types
        .find_by_key(tenant, &key)
        .await
        .or_internal()?;
    Ok(declared.map_or(DataClassLevel::Restricted, |kind| kind.data_class()))
}

/// Whether another agent's holding and the wanted relation could pass data
/// between them.
fn needs_channel(holder: &ResourceHolder, agent: &AgentId, wanted: &ResourceCapability) -> bool {
    holder.agent != *agent && sharing_needs_channel(&holder.relation, wanted.relation())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints, ResourceRef,
    };
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::agents::channels::channel::{
        AgentChannel, ChannelScope, OpenChannelParams,
    };
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{PrincipalRef, Seconds, UserId};

    use super::*;
    use crate::test_support::agents::{
        FakeDelegationStore, StoredGrant, caller_person, resource_cap, stored_delegation,
    };
    use crate::test_support::authorization::FakeResourceTypeStore;
    use crate::test_support::messaging::FakeAgentChannelStore;
    use crate::test_support::{block_on, test_ctx};

    fn holding(store: &FakeDelegationStore, agent: AgentId, held: ResourceCapability) {
        let delegation = stored_delegation(StoredGrant {
            delegator: PrincipalRef::User(UserId::new()),
            delegate: agent,
            granted: CapabilitySet::empty().with_resources(vec![held]),
            constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
            lineage: Lineage::Root,
            status: DelegationStatus::Active,
        });
        block_on(store.save(&test_ctx().tenant(), &delegation)).unwrap();
    }

    fn channel_for(
        object: &str,
        (sender, receiver): (AgentId, AgentId),
        max_class: DataClassLevel,
    ) -> FakeAgentChannelStore {
        let owner = caller_person();
        let authority = TenantAuthority::assumed(owner.clone(), test_ctx().tenant_id(), &[], &[]);
        let channel: AgentChannel<ResolvedTenant> = AgentChannel::open(
            &AgentControl::new(&authority),
            &owner,
            OpenChannelParams {
                sender,
                receiver,
                scope: ChannelScope::Resource(ResourceRef::new(object).unwrap()),
                max_class,
                lifetime_seconds: Seconds::new(3600),
            },
        )
        .unwrap();
        let channels = FakeAgentChannelStore::empty();
        block_on(channels.save(&test_ctx().tenant(), &channel)).unwrap();
        channels
    }

    fn check(
        delegations: &FakeDelegationStore,
        channels: &FakeAgentChannelStore,
        agent: AgentId,
        wanted: ResourceCapability,
    ) -> Result<(), AppError> {
        check_with(
            delegations,
            channels,
            &FakeResourceTypeStore::empty(),
            agent,
            wanted,
        )
    }

    fn check_with(
        delegations: &FakeDelegationStore,
        channels: &FakeAgentChannelStore,
        resource_types: &FakeResourceTypeStore,
        agent: AgentId,
        wanted: ResourceCapability,
    ) -> Result<(), AppError> {
        let stores = SharingStores {
            delegations,
            channels,
            resource_types,
        };
        block_on(refuse_unchanneled_sharing(
            stores,
            SharingAgent {
                tenant_id: &test_ctx().tenant(),
                agent: &agent,
            },
            &[wanted],
        ))
    }

    /// Documents are declared as holding internal data. A writer and a
    /// reader share `doc:1` over a channel opened for internal data, which
    /// is enough.
    #[test]
    fn a_declared_types_class_decides_which_channel_shares_it() {
        let (writer, reader) = (AgentId::new(), AgentId::new());
        let delegations = FakeDelegationStore::empty();
        holding(&delegations, writer, resource_cap("editor", "doc:1"));
        let channels = channel_for("doc:1", (writer, reader), DataClassLevel::Internal);
        let documents = FakeResourceTypeStore::declaring(
            test_ctx().tenant_id(),
            "doc",
            DataClassLevel::Internal,
        );

        let result = check_with(
            &delegations,
            &channels,
            &documents,
            reader,
            resource_cap("reader", "doc:1"),
        );

        assert!(result.is_ok());
    }

    /// An internal-data channel cannot authorize sharing a document declared
    /// confidential between a writer and reader.
    #[test]
    fn a_channel_below_the_declared_class_does_not_share_the_object() {
        let (writer, reader) = (AgentId::new(), AgentId::new());
        let delegations = FakeDelegationStore::empty();
        holding(&delegations, writer, resource_cap("editor", "doc:1"));
        let channels = channel_for("doc:1", (writer, reader), DataClassLevel::Internal);
        let documents = FakeResourceTypeStore::declaring(
            test_ctx().tenant_id(),
            "doc",
            DataClassLevel::Confidential,
        );

        let result = check_with(
            &delegations,
            &channels,
            &documents,
            reader,
            resource_cap("reader", "doc:1"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's agent reads a document another agent also reads. Nothing passes
    /// between readers, so no channel is needed.
    #[test]
    fn a_reader_may_join_another_reader() {
        let delegations = FakeDelegationStore::empty();
        holding(
            &delegations,
            AgentId::new(),
            resource_cap("reader", "doc:1"),
        );

        let result = check(
            &delegations,
            &FakeAgentChannelStore::empty(),
            AgentId::new(),
            resource_cap("reader", "doc:1"),
        );

        assert!(result.is_ok());
    }

    /// A reader cannot share another agent's writable document without a
    /// channel between them.
    #[test]
    fn a_reader_cannot_join_a_writer_without_a_channel() {
        let delegations = FakeDelegationStore::empty();
        holding(
            &delegations,
            AgentId::new(),
            resource_cap("editor", "doc:1"),
        );

        let result = check(
            &delegations,
            &FakeAgentChannelStore::empty(),
            AgentId::new(),
            resource_cap("reader", "doc:1"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An owner grant is refused when another agent reads the document and
    /// no channel connects them.
    #[test]
    fn a_writer_cannot_join_a_reader_without_a_channel() {
        let delegations = FakeDelegationStore::empty();
        holding(
            &delegations,
            AgentId::new(),
            resource_cap("reader", "doc:1"),
        );

        let result = check(
            &delegations,
            &FakeAgentChannelStore::empty(),
            AgentId::new(),
            resource_cap("owner", "doc:1"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann opened a channel for the document between the writer and her
    /// reader, cleared for restricted data. The reader may join.
    #[test]
    fn a_channel_for_the_object_lets_them_share() {
        let (writer, reader) = (AgentId::new(), AgentId::new());
        let delegations = FakeDelegationStore::empty();
        holding(&delegations, writer, resource_cap("editor", "doc:1"));
        let channels = channel_for("doc:1", (writer, reader), DataClassLevel::Restricted);

        let result = check(
            &delegations,
            &channels,
            reader,
            resource_cap("reader", "doc:1"),
        );

        assert!(result.is_ok());
    }

    /// An internal-data channel cannot authorize sharing a document whose
    /// resource type has no declared data class.
    #[test]
    fn a_channel_for_less_sensitive_data_does_not_share_the_object() {
        let (writer, reader) = (AgentId::new(), AgentId::new());
        let delegations = FakeDelegationStore::empty();
        holding(&delegations, writer, resource_cap("editor", "doc:1"));
        let channels = channel_for("doc:1", (writer, reader), DataClassLevel::Internal);

        let result = check(
            &delegations,
            &channels,
            reader,
            resource_cap("reader", "doc:1"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's agent already reads its own document and is given edit rights
    /// on it. Nobody else holds it, so nothing is shared.
    #[test]
    fn an_agent_may_hold_more_rights_on_its_own_object() {
        let agent = AgentId::new();
        let delegations = FakeDelegationStore::empty();
        holding(&delegations, agent, resource_cap("reader", "doc:1"));

        let result = check(
            &delegations,
            &FakeAgentChannelStore::empty(),
            agent,
            resource_cap("editor", "doc:1"),
        );

        assert!(result.is_ok());
    }

    /// Another agent writes a different document. It is no concern of a
    /// grant on this one.
    #[test]
    fn another_object_is_no_concern() {
        let delegations = FakeDelegationStore::empty();
        holding(
            &delegations,
            AgentId::new(),
            resource_cap("editor", "doc:2"),
        );

        let result = check(
            &delegations,
            &FakeAgentChannelStore::empty(),
            AgentId::new(),
            resource_cap("reader", "doc:1"),
        );

        assert!(result.is_ok());
    }
}
