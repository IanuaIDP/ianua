//! A tenant's agents, and the model provider they run on.

use ianua_app::listing::{Limit, PageRequest, SortOrder};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::agents::lifecycle::CreateAgentRequest;
use ianua_app::use_cases::agents::model_providers::ConnectRequest;
use ianua_domain::domains::agents::execution::model_provider::{
    ModelEndpoint, ModelName, ModelProviderKind,
};
use ianua_domain::domains::agents::execution::usage::ModelPricing;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Label, ModelProviderId};

use crate::demo::DemoError;
use crate::demo::catalog::{AgentSeed, PROVIDER};
use crate::demo::seeder::{DemoTenant, Seed, Seeder};

/// The most agents one page of the lookup covers.
const PAGE: Limit = Limit::internal(100);

/// The tenant's model provider, found by its name or connected by the
/// owner. The use case seals its key for this provider of this tenant.
///
/// # Errors
///
/// [`DemoError`] when the providers cannot be read or one connected.
pub(super) async fn model_provider(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
) -> Result<Seed<ModelProviderId>, DemoError> {
    let name = Label::new("name", PROVIDER.name)?;
    let store = seeder.adapters.model_provider_store.as_ref();
    let providers = store.list(&tenant.scoped()).await?;
    if let Some(found) = providers.iter().find(|provider| provider.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let request = ConnectRequest {
        name,
        kind: ModelProviderKind::SelfHosted,
        endpoint: ModelEndpoint::new(PROVIDER.endpoint)?,
        model: ModelName::new(PROVIDER.model)?,
        pricing: ModelPricing::Unpriced,
        api_key: Some(Secret::new(PROVIDER.key)),
        clearance: DataClassLevel::Internal,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let connect = seeder.state.agents.model_providers.connect.as_ref();
    let id = seeder
        .kept(
            "a model provider",
            connect.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(id))
}

/// The agent `seed` names, found by its name or created by the owner,
/// who owns it.
///
/// # Errors
///
/// [`DemoError`] when the agents cannot be read or one created.
pub(super) async fn agent(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    seed: &AgentSeed,
) -> Result<Seed<AgentId>, DemoError> {
    let name = Label::new("name", seed.name)?;
    let page = PageRequest::first(PAGE);
    let store = seeder.adapters.agent_store.as_ref();
    let listed = store
        .list_all(&tenant.scoped(), &SortOrder::default(), &page)
        .await?;
    if let Some(found) = listed.items.iter().find(|agent| agent.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let request = CreateAgentRequest {
        name,
        description: Some(Label::new("description", seed.description)?),
        attestation_policy: None,
        key: None,
    };
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.agents.lifecycle.create.as_ref();
    let created = seeder
        .kept(
            "an agent",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(created.agent_id))
}
