//! Security alerts: the few events a caller can repeat on every request
//! that the people who run a plane must still hear of.
//!
//! A colleague's activity feed leaves out what fires per request, as
//! [`EventType::is_notifiable`] says: Mallory replaying a canary credential
//! a thousand times would fill every feed. Yet a canary presented, a
//! refresh token used twice or a reset link that never went out means
//! someone is attacking the tenant, or a person is locked out, and the
//! audit trail alone tells nobody. So these events are alerts instead: the
//! first one tells the people who run the plane, and after that at most one
//! alert of the same kind goes out on the same plane per
//! [`ALERT_WINDOW`]. Every occurrence is still recorded in the trail.
//!
//! An alert reaches the people a notification of its category reaches,
//! by the right that category needs, and on the organization's plane only
//! its admins and owners: a viewer or a billing contact does not run
//! anything an attack is aimed at.

use time::Duration;

use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
use crate::domains::organization::members::membership::OrgRole;
use crate::types::EventType;
use crate::types::event_type::{
    AgentsEvent, AuthenticationEvent, NotificationsEvent, OAuthEvent, OrganizationEvent, ProxyEvent,
};

/// How long after one alert of a kind the next of the same kind on the
/// same plane is held back. An hour tells the people who run the plane
/// soon enough to act, and an attacker repeating a request all day sends
/// them at most one an hour.
pub const ALERT_WINDOW: Duration = Duration::HOUR;

/// One event that is a security alert, and the rules it is told by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityAlert {
    event_type: EventType,
}

impl SecurityAlert {
    /// The alert `event_type` is, or `None` when it is not one.
    ///
    /// These are a canary credential presented or found leaking, an
    /// automated attack detected, a refresh token used again after it was
    /// spent, an account coming under attack from many networks, an
    /// agent's sign-in refused as an attack, and a mail given up on after
    /// its last try. A honeypot hit is
    /// left to the trail: a decoy path is found by every scanner on the
    /// internet, and alerting on it would teach people to ignore alerts.
    /// So is a purge of old audit records, which the tenant's retention
    /// asked for.
    #[must_use]
    pub fn of(event_type: &EventType) -> Option<Self> {
        let alert = matches!(
            event_type,
            EventType::Proxy(
                ProxyEvent::CanaryTokenTriggered
                    | ProxyEvent::CanaryTokenLeaked
                    | ProxyEvent::AutomatedThreatDetected
            ) | EventType::OAuth(OAuthEvent::RefreshTokenReused)
                | EventType::Agents(AgentsEvent::TokenAttackRefused)
                | EventType::Authentication(AuthenticationEvent::AccountUnderAttack)
                | EventType::Organization(OrganizationEvent::OrgAccountUnderAttack)
                | EventType::Notifications(NotificationsEvent::MailUndelivered)
        );
        alert.then_some(Self {
            event_type: *event_type,
        })
    }

    /// The event this alert is about.
    #[must_use]
    pub fn event_type(self) -> EventType {
        self.event_type
    }

    /// How long after this alert the next of its kind on its plane is held
    /// back.
    #[must_use]
    pub fn window(self) -> Duration {
        ALERT_WINDOW
    }

    /// Where this alert's repeats are held back.
    ///
    /// An agent's sign-in refused as an attack is held back where it is
    /// recorded, per agent and kind of attack, each record saying how many
    /// attempts it stands for: Mallory forging one agent's assertions all
    /// day neither writes a record per try nor hides a replay on another
    /// agent behind the first alert. Every record of it is told. Every
    /// other alert's occurrences are all recorded and held back when told,
    /// one a window per kind on the plane.
    #[must_use]
    pub fn repeats(self) -> AlertRepeats {
        let agent_attack = matches!(
            self.event_type,
            EventType::Agents(AgentsEvent::TokenAttackRefused)
        );
        if agent_attack {
            return AlertRepeats::WhenRecorded;
        }
        AlertRepeats::WhenTold
    }

    /// Whether a member of the organization holding `role` is told.
    #[must_use]
    pub fn reaches(self, role: OrgRole) -> bool {
        matches!(role, OrgRole::Admin | OrgRole::Owner)
    }

    /// Which of a tenant's users are told.
    ///
    /// An attack is for the people who run the whole tenant, its
    /// administrators. A mail given up on is for whoever may manage the
    /// tenant's mail, `branding: update`, administrator or not: Mia runs
    /// Acme's mail provider and nothing else, and she is the one who can
    /// fix it.
    #[must_use]
    pub fn audience(self) -> AlertAudience {
        let lost_mail = matches!(
            self.event_type,
            EventType::Notifications(NotificationsEvent::MailUndelivered)
        );
        if lost_mail {
            return AlertAudience::HoldersOf(SystemPermission::Branding(BrandingAction::Update));
        }
        AlertAudience::Administrators
    }
}

/// Where an alert's repeats are held back to one a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertRepeats {
    /// Every occurrence is recorded, and telling holds back repeats of the
    /// kind on the plane.
    WhenTold,
    /// Occurrences are held back where they are recorded, per what they are
    /// about, each record saying how many it stands for; every record is
    /// told.
    WhenRecorded,
}

/// Which of a tenant's users an alert is told to. Each is still told only
/// while they may sign in and may see the alert's category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertAudience {
    /// The tenant's administrators.
    Administrators,
    /// Everyone whose roles give this right, administrator or not.
    HoldersOf(SystemPermission),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::TenantEvent;

    fn alert_of(event_type: impl Into<EventType>) -> Option<SecurityAlert> {
        SecurityAlert::of(&event_type.into())
    }

    /// Canary use or leakage, automated attacks, token replay, attacks on
    /// accounts or agents, and undelivered mail are classified as alerts.
    #[test]
    fn attacks_and_lost_mail_are_alerts() {
        let alerts: [EventType; 8] = [
            ProxyEvent::CanaryTokenTriggered.into(),
            ProxyEvent::CanaryTokenLeaked.into(),
            ProxyEvent::AutomatedThreatDetected.into(),
            OAuthEvent::RefreshTokenReused.into(),
            AgentsEvent::TokenAttackRefused.into(),
            AuthenticationEvent::AccountUnderAttack.into(),
            OrganizationEvent::OrgAccountUnderAttack.into(),
            NotificationsEvent::MailUndelivered.into(),
        ];

        for event_type in alerts {
            assert!(SecurityAlert::of(&event_type).is_some(), "{event_type:?}");
        }
    }

    /// Agent attack alerts suppress repeats when recorded and target
    /// administrators; canary alerts suppress repeats when told.
    #[test]
    fn an_agent_attack_is_held_back_where_it_is_recorded() {
        let agent_attack = alert_of(AgentsEvent::TokenAttackRefused).unwrap();
        let canary = alert_of(ProxyEvent::CanaryTokenTriggered).unwrap();

        assert_eq!(agent_attack.repeats(), AlertRepeats::WhenRecorded);
        assert_eq!(canary.repeats(), AlertRepeats::WhenTold);
        assert_eq!(agent_attack.audience(), AlertAudience::Administrators);
    }

    /// A purge the tenant's retention asked for, and a decoy path any
    /// scanner finds, stay in the trail only.
    #[test]
    fn a_purge_and_a_honeypot_hit_are_not_alerts() {
        assert!(alert_of(TenantEvent::AuditRecordsPurged).is_none());
        assert!(alert_of(ProxyEvent::HoneypotHit).is_none());
    }

    /// An alert is never a feed notification too, so the rule keeping
    /// per-request events out of colleagues' feeds still holds.
    #[test]
    fn no_alert_is_also_a_feed_notification() {
        for event_type in EventType::all() {
            let both = event_type.is_notifiable() && SecurityAlert::of(&event_type).is_some();

            assert!(!both, "{event_type:?}");
        }
    }

    /// The next alert of a kind is held back for an hour.
    #[test]
    fn an_alert_holds_back_the_next_for_an_hour() {
        let alert = alert_of(ProxyEvent::CanaryTokenTriggered).unwrap();

        assert_eq!(alert.window(), Duration::HOUR);
    }

    /// Undelivered mail targets holders of branding update permission,
    /// while canary alerts target administrators.
    #[test]
    fn a_lost_mail_is_told_to_whoever_manages_mail() {
        let mail = alert_of(NotificationsEvent::MailUndelivered).unwrap();
        let canary = alert_of(ProxyEvent::CanaryTokenTriggered).unwrap();

        assert_eq!(
            mail.audience(),
            AlertAudience::HoldersOf(SystemPermission::Branding(BrandingAction::Update))
        );
        assert_eq!(canary.audience(), AlertAudience::Administrators);
    }

    /// A refresh-token replay alert reaches organization owners and admins,
    /// excluding members, billing contacts and viewers.
    #[test]
    fn only_admins_and_owners_of_the_organization_are_told() {
        let alert = alert_of(OAuthEvent::RefreshTokenReused).unwrap();

        assert!(alert.reaches(OrgRole::Owner));
        assert!(alert.reaches(OrgRole::Admin));
        assert!(!alert.reaches(OrgRole::Member));
        assert!(!alert.reaches(OrgRole::Billing));
        assert!(!alert.reaches(OrgRole::Viewer));
    }
}
