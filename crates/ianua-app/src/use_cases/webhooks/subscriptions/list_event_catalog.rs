//! List event catalog: the events the caller may subscribe a webhook to,
//! with what each means.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::catalog::{CatalogEntry, subscribable_events};
use ianua_domain::domains::webhooks::control::WebhookControl;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::use_case::Query;

/// The ports [`ListEventCatalogUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListEventCatalogPorts {
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the events a caller may subscribe a webhook to.
pub struct ListEventCatalogUseCase {
    ports: ListEventCatalogPorts,
}

impl ListEventCatalogUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListEventCatalogPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListEventCatalogUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<CatalogEntry>, AppError>;

    /// Every event the caller may subscribe a webhook to, in the order the
    /// contexts list them: only the ones their standing rights let them
    /// see, and never the record of a webhook's own delivery.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view webhooks.
    async fn execute(&self, caller: &CallerContext, (): ()) -> Result<Vec<CatalogEntry>, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = WebhookControl::new(&authority);
        control
            .ensure_may(WebhooksAction::View)
            .map_err(AppError::from_domain)?;
        Ok(subscribable_events(&control.visibility()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::EventType;
    use ianua_domain::types::event_type::{CryptoEvent, IdentityEvent, WebhooksEvent};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::{block_on, test_ctx};

    /// The catalog as a caller holding what `authorities` says reads it.
    fn catalog(authorities: FakeTenantAuthorities) -> Result<Vec<CatalogEntry>, AppError> {
        let use_case = ListEventCatalogUseCase::new(ListEventCatalogPorts {
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// The event types in `entries`.
    fn types_in(entries: &[CatalogEntry]) -> Vec<EventType> {
        entries.iter().map(CatalogEntry::event_type).collect()
    }

    /// Ann may view webhooks and see user events. Her catalog offers user
    /// registrations, described in words, and never the record of a
    /// webhook's own delivery.
    #[test]
    fn the_catalog_offers_what_the_caller_may_see() {
        let entries = catalog(FakeTenantAuthorities::holding(&[
            SystemPermission::Webhooks(WebhooksAction::View),
            SystemPermission::Users(UserAction::View),
        ]))
        .unwrap();

        let registered = entries
            .iter()
            .find(|entry| entry.event_type() == IdentityEvent::UserRegistered.into())
            .unwrap();
        assert!(!registered.description().is_empty());
        assert!(!types_in(&entries).contains(&WebhooksEvent::DeliveryAttempted.into()));
    }

    /// The catalog excludes a signing key event when the caller can view
    /// webhooks and users but lacks access to that event.
    #[test]
    fn the_catalog_leaves_out_events_the_caller_may_not_see() {
        let entries = catalog(FakeTenantAuthorities::holding(&[
            SystemPermission::Webhooks(WebhooksAction::View),
            SystemPermission::Users(UserAction::View),
        ]))
        .unwrap();

        assert!(!types_in(&entries).contains(&CryptoEvent::ALL[0].0.into()));
    }

    /// User viewing rights alone do not permit reading the webhook catalog.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = catalog(FakeTenantAuthorities::holding(&[SystemPermission::Users(
            UserAction::View,
        )]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading the catalog with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = catalog(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
