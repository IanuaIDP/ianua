//! Where the organization's notifications are posted beside the members'
//! inboxes, which the worker fills from the seeded events.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::notifications::destinations::endpoint::{
    DestinationSettings, DestinationTarget,
};
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::types::{Label, NotificationDestinationId, PublicHttpsUrl};

use crate::demo::seeder::{Seed, Seeder};
use crate::demo::{DemoError, catalog};

/// The organization's notification webhook, found by its name or added by
/// the owner. The use case makes its signing secret and seals it.
///
/// # Errors
///
/// [`DemoError`] when the destinations cannot be read or one added.
pub(super) async fn destination(
    seeder: &Seeder<'_>,
) -> Result<Seed<NotificationDestinationId>, DemoError> {
    let name = Label::new("name", catalog::DESTINATION)?;
    let store = seeder.adapters.notification_destination_store.as_ref();
    let destinations = store.list(&seeder.organization.id).await?;
    if let Some(found) = destinations.iter().find(|place| place.name() == &name) {
        return Ok(Seed::Found(*found.id()));
    }
    let settings = DestinationSettings {
        name,
        target: DestinationTarget::Webhook(PublicHttpsUrl::new(catalog::DESTINATION_URL)?),
        categories: vec![
            NotificationCategory::Identity,
            NotificationCategory::Authorization,
            NotificationCategory::Routing,
        ],
        minimum: NotificationSeverity::Warning,
    };
    let acting = seeder.in_organization().await?;
    let add = seeder.state.notifications.destinations.add.as_ref();
    let added = seeder
        .kept(
            "a notification destination",
            add.execute(&acting.caller, &acting.auditor, settings),
        )
        .await?;
    Ok(Seed::Made(added.id))
}
