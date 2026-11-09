//! The words a workflow version's choices are stored as.
//!
//! What starts a version and where a workflow came from carry values of
//! their own, a schedule, an event, a service's event or a flow's
//! description, which have
//! columns of their own, so their cases are stored apart, as a
//! [`TriggerKind`] and an [`OriginKind`]. A version's status is stored as
//! the domain names it.

use ianua_domain::domains::workflows::design::workflow::WorkflowOrigin;
use ianua_domain::domains::workflows::triggers::Trigger;

use crate::postgres::foundation::stored::stored_words;

/// Which case of [`Trigger`] starts a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TriggerKind {
    /// A person starts it.
    Manual,
    /// Its schedule starts it.
    Schedule,
    /// A call to its webhook starts it.
    Webhook,
    /// An event in the tenant starts it.
    Event,
    /// An event an integration's service sends starts it.
    Service,
    /// A change about to happen starts it, and it decides the change.
    Before,
}

impl TriggerKind {
    /// The case `trigger` is.
    pub(super) fn of(trigger: &Trigger) -> Self {
        match trigger {
            Trigger::Manual => Self::Manual,
            Trigger::Schedule(_) => Self::Schedule,
            Trigger::Webhook => Self::Webhook,
            Trigger::Event(_) => Self::Event,
            Trigger::Service(_) => Self::Service,
            Trigger::Before(_) => Self::Before,
        }
    }
}

stored_words! {
    TriggerKind as "workflow trigger" {
        Manual => "manual",
        Schedule => "schedule",
        Webhook => "webhook",
        Event => "event",
        Service => "service",
        Before => "before",
    }
}

/// Which case of [`WorkflowOrigin`] a workflow came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OriginKind {
    /// A person designed it, version by version.
    Designed,
    /// A person made it at once as an agent flow.
    Flow,
}

impl OriginKind {
    /// The case `origin` is.
    pub(super) fn of(origin: &WorkflowOrigin) -> Self {
        match origin {
            WorkflowOrigin::Designed => Self::Designed,
            WorkflowOrigin::Flow(_) => Self::Flow,
        }
    }
}

stored_words! {
    OriginKind as "workflow origin" {
        Designed => "designed",
        Flow => "flow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every trigger and origin reads back from the word it is written as.
    #[test]
    fn every_trigger_and_origin_reads_back_from_its_word() {
        for kind in [
            TriggerKind::Manual,
            TriggerKind::Schedule,
            TriggerKind::Webhook,
            TriggerKind::Event,
            TriggerKind::Service,
            TriggerKind::Before,
        ] {
            assert_eq!(TriggerKind::from_word(kind.word()), Some(kind));
        }
        for kind in [OriginKind::Designed, OriginKind::Flow] {
            assert_eq!(OriginKind::from_word(kind.word()), Some(kind));
        }
    }
}
