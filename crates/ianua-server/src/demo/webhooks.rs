//! A tenant's webhook, telling another system of new people and roles.

use ianua_app::listing::{Limit, PageRequest, SortOrder};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::webhooks::subscriptions::CreateRequest;
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::types::event_type::{AuthorizationEvent, EventType, IdentityEvent};
use ianua_domain::types::{PublicHttpsUrl, Text, WebhookSubscriptionId};

use crate::demo::seeder::{DemoTenant, Seed, Seeder};
use crate::demo::{DemoError, catalog};

/// The most webhooks one page of the lookup covers.
const PAGE: Limit = Limit::internal(100);

/// The tenant's webhook, found by where it posts or subscribed by the
/// owner. The use case makes its signing secret and seals it; the demo
/// never sees it again.
///
/// # Errors
///
/// [`DemoError`] when the webhooks cannot be read or one subscribed.
pub(super) async fn webhook(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
) -> Result<Seed<WebhookSubscriptionId>, DemoError> {
    let url = PublicHttpsUrl::new(format!(
        "{}/{}",
        catalog::WEBHOOK_BASE,
        tenant.slug.as_str()
    ))?;
    let page = PageRequest::first(PAGE);
    let store = seeder.adapters.webhook_store.as_ref();
    let listed = store
        .list_all(&tenant.scoped(), None, &SortOrder::default(), &page)
        .await?;
    if let Some(found) = listed.items.iter().find(|webhook| webhook.url() == &url) {
        return Ok(Seed::Found(*found.id()));
    }
    let request = subscription_request(url)?;
    let acting = seeder.in_tenant(tenant).await?;
    let create = seeder.state.webhooks.create.as_ref();
    let created = seeder
        .kept(
            "a webhook",
            create.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(created.subscription_id))
}

/// Subscribes to the demo's person and role events with its validated description.
fn subscription_request(url: PublicHttpsUrl) -> Result<CreateRequest, DemoError> {
    Ok(CreateRequest {
        url,
        event_types: vec![
            EventType::Identity(IdentityEvent::UserRegistered),
            EventType::Authorization(AuthorizationEvent::RoleCreated),
        ],
        description: Some(Text::new("description", catalog::WEBHOOK_DESCRIPTION)?),
        retry: RetryPreset::Standard,
    })
}
