//! Controls and services the messaging context's tests share.

use crate::domains::authorization::permission::{MessagingAction, SystemPermission};
use crate::domains::consumers::authority::ConsumerAuthority;
use crate::domains::consumers::fixtures::service_holding;
use crate::domains::messaging::control::MessagingControl;
use crate::test_support::authority::anyone_holding;

/// A service whose roles let it create topics, schemas and subscriptions.
pub(crate) fn creating_service() -> ConsumerAuthority {
    service_holding(&[SystemPermission::Messaging(MessagingAction::Create)])
}

/// A service whose roles let it only publish.
pub(crate) fn publishing_service() -> ConsumerAuthority {
    service_holding(&[SystemPermission::Messaging(MessagingAction::Publish)])
}

/// Someone changing messaging who holds `system` and no custom permission.
pub(crate) fn holding(system: &[SystemPermission]) -> MessagingControl<'static> {
    MessagingControl::new(anyone_holding(system))
}

/// Someone who manages messaging.
pub(crate) fn messaging_admin() -> MessagingControl<'static> {
    holding(&[SystemPermission::Messaging(MessagingAction::Manage)])
}

/// Someone who may only view messaging.
pub(crate) fn messaging_viewer() -> MessagingControl<'static> {
    holding(&[SystemPermission::Messaging(MessagingAction::View)])
}
