//! Why an event is told at all: as activity in colleagues' feeds, or as a
//! security alert, of which the throttle lets one a window through.
//!
//! The two are separate answers of the domain. A feed notice goes out on
//! every occurrence, since nobody can repeat it at will. An alert's event
//! fires per request, so whoever sends the requests could fill every inbox:
//! its first occurrence on a plane is told, the next only once its window
//! passed, and that one says how many came in between.

use ianua_domain::domains::notifications::alert::{AlertAudience, AlertRepeats, SecurityAlert};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::types::EventType;

use crate::ports::notifications::{AlertAbout, AlertKey, AlertPlane, AlertTurn};
use crate::use_cases::notifications::delivery::audience::Audience;

/// How one event is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::notifications::delivery) enum Notice {
    /// As activity, to everyone who runs the plane and may see it.
    Feed,
    /// As a security alert, held back to one a window.
    Alert(SecurityAlert),
}

impl Notice {
    /// How an event of `event_type` is told, or `None` when it is told to
    /// no one and only recorded.
    pub(in crate::use_cases::notifications::delivery) fn of(
        event_type: &EventType,
    ) -> Option<Self> {
        if event_type.is_notifiable() {
            return Some(Self::Feed);
        }
        SecurityAlert::of(event_type).map(Self::Alert)
    }

    /// Whether a member of the organization holding `role` is told.
    pub(in crate::use_cases::notifications::delivery) fn reaches(self, role: OrgRole) -> bool {
        match self {
            Self::Feed => true,
            Self::Alert(alert) => alert.reaches(role),
        }
    }

    /// Which of a tenant's users are told: its administrators of activity
    /// and of most alerts, whoever holds the alert's right of the rest.
    pub(in crate::use_cases::notifications::delivery) fn tenant_audience(self) -> AlertAudience {
        match self {
            Self::Feed => AlertAudience::Administrators,
            Self::Alert(alert) => alert.audience(),
        }
    }

    /// The kind of alert this is on the plane `audience` runs, or `None`
    /// when telling holds nothing back: a feed notice, or an alert whose
    /// repeats were held back already where it was recorded.
    pub(in crate::use_cases::notifications::delivery) fn alert_key(
        self,
        audience: &Audience,
    ) -> Option<(AlertKey, time::Duration)> {
        let Self::Alert(alert) = self else {
            return None;
        };
        if alert.repeats() == AlertRepeats::WhenRecorded {
            return None;
        }
        let key = AlertKey {
            plane: plane_of(audience),
            event_type: alert.event_type(),
            about: AlertAbout::Kind,
        };
        Some((key, alert.window()))
    }
}

/// How many times an alert's event happened since the last alert of its
/// kind, as its text says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::notifications) enum Occurrences {
    /// Not counted: a feed notice, or the first alert of its kind.
    NotCounted,
    /// This many, this one included, since the last alert.
    SinceLastAlert(u64),
}

impl Occurrences {
    /// What the throttle's `turn` lets out: `None` when it held the alert
    /// back.
    pub(in crate::use_cases::notifications::delivery) fn admitted(turn: AlertTurn) -> Option<Self> {
        match turn {
            AlertTurn::Raise { since_last: None } => Some(Self::NotCounted),
            AlertTurn::Raise {
                since_last: Some(count),
            } => Some(Self::SinceLastAlert(count)),
            AlertTurn::HeldBack => None,
        }
    }
}

/// The plane alerts told to `audience` are held back on: the tenant an
/// event happened in, whichever plane its people are on, or else the
/// organization's or the platform's own.
fn plane_of(audience: &Audience) -> AlertPlane {
    match *audience {
        Audience::Tenant { tenant_id, .. }
        | Audience::Organization {
            about_tenant: Some(tenant_id),
            ..
        } => AlertPlane::Tenant(tenant_id),
        Audience::Organization {
            organization_id,
            about_tenant: None,
            ..
        } => AlertPlane::Organization(organization_id),
        Audience::Platform { .. } => AlertPlane::Platform,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::event_type::{OAuthEvent, ProxyEvent};
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;

    /// A role change is activity; a canary hit is an alert; a honeypot hit
    /// is only recorded.
    #[test]
    fn events_are_told_as_activity_as_alerts_or_not_at_all() {
        let changed = EventType::from(ProxyEvent::PipelineDisabled);
        let canary = EventType::from(ProxyEvent::CanaryTokenTriggered);
        let honeypot = EventType::from(ProxyEvent::HoneypotHit);

        assert_eq!(Notice::of(&changed), Some(Notice::Feed));
        assert!(matches!(Notice::of(&canary), Some(Notice::Alert(_))));
        assert_eq!(Notice::of(&honeypot), None);
    }

    /// A reused refresh token in Acme, told to the organization because an
    /// org user's client used it, is held back on Acme's plane, beside the
    /// same alert told to Acme's own admins.
    #[test]
    fn an_alert_is_held_back_on_the_tenant_it_happened_in() {
        let acme = TenantId::new();
        let alert = Notice::of(&EventType::from(OAuthEvent::RefreshTokenReused)).unwrap();
        let to_org = Audience::Organization {
            organization_id: OrganizationId::new(),
            about_tenant: Some(acme),
            actor: None,
            subject: None,
        };
        let to_tenant = Audience::Tenant {
            tenant_id: acme,
            actor: None,
            subject: None,
        };

        let (org_key, _) = alert.alert_key(&to_org).unwrap();
        let (tenant_key, _) = alert.alert_key(&to_tenant).unwrap();

        assert_eq!(org_key, tenant_key);
        assert_eq!(org_key.plane, AlertPlane::Tenant(acme));
    }

    /// Mallory forges the billing agent's assertions, then replays the
    /// payroll agent's within the hour. Each record of an agent attack was
    /// held back already where it was written, so telling holds back none,
    /// and the payroll attack is told too.
    #[test]
    fn an_agent_attack_is_not_held_back_again_when_told() {
        let alert = Notice::of(&EventType::from(
            ianua_domain::types::event_type::AgentsEvent::TokenAttackRefused,
        ))
        .unwrap();
        let to_tenant = Audience::Tenant {
            tenant_id: TenantId::new(),
            actor: None,
            subject: None,
        };

        assert!(matches!(alert, Notice::Alert(_)));
        assert!(alert.alert_key(&to_tenant).is_none());
    }
}
