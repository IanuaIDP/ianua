//! Recording what a member's change raised beside records that carry their
//! own actor, or none: the mail a change sent, the grants it revoked.

use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::ActorRef;

/// `raised`, each as done by `by`, followed by `alongside` as they are, in
/// one list to dispatch together.
pub(in crate::use_cases::organization) fn attributed(
    by: &ActorRef,
    raised: Vec<DomainEvent>,
    alongside: Vec<DomainEvent>,
) -> Vec<DomainEvent> {
    raised
        .into_iter()
        .map(|event| event.with_actor(by.clone()))
        .chain(alongside)
        .collect()
}
