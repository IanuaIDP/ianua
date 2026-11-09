//! The throttle on security alerts: the first occurrence of a kind on a
//! plane, about one thing (the whole kind, or one agent attacked one way),
//! is let through, then at most one a window, and every occurrence is
//! counted so the next says how many came since the last.
//!
//! The window is a claim on the shared state that lapses with it. The
//! occurrences are one counter per kind and plane; at each alert the count
//! it reached is swapped into a second entry, so the next alert reads how
//! far the counter moved since. Both entries are kept for
//! [`COUNTED_FOR`], far longer than any window: past it the counter starts
//! over and the next alert counts from there.
//!
//! When the shared state cannot answer, the same steps run on state held
//! in this process. An attack that takes the cache server down, or happens
//! while it is down, is still told, once per window on each node, never
//! once per request. Should that state be full too, the alert is held
//! back: the full state empties as its windows lapse, so no alert is held
//! back for longer than one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::notifications::{AlertAbout, AlertKey, AlertPlane, AlertThrottle, AlertTurn};

use crate::cache::MemoryState;
use crate::cache::state::{CacheError, SharedState, key};

/// How long the occurrences of one kind of alert are counted for.
const COUNTED_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How many kinds of alert on how many planes the state held in this
/// process tracks while the shared state is down.
const FALLBACK_ENTRIES: usize = 30_000;

/// The throttle on security alerts, on shared state, with state held in
/// this process to fall back on.
pub struct CacheAlertThrottle {
    state: Arc<dyn SharedState>,
    fallback: MemoryState,
}

impl CacheAlertThrottle {
    /// A throttle on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self {
            state,
            fallback: MemoryState::new(FALLBACK_ENTRIES),
        }
    }

    /// The turn the state held in this process gives, holding the alert
    /// back when that cannot answer either.
    async fn turn_in_process(&self, keys: &Keys, window: Duration) -> AlertTurn {
        turn_on(&self.fallback, keys, window)
            .await
            .inspect_err(|error| tracing::warn!(%error, "the alert throttle held an alert back"))
            .unwrap_or(AlertTurn::HeldBack)
    }
}

#[async_trait]
impl AlertThrottle for CacheAlertThrottle {
    async fn admit(&self, alert: &AlertKey, window: time::Duration) -> AlertTurn {
        let window = Duration::try_from(window).unwrap_or(Duration::ZERO);
        let keys = Keys::of(alert);
        match turn_on(self.state.as_ref(), &keys, window).await {
            Ok(turn) => turn,
            Err(error) => {
                tracing::warn!(%error, "the alert throttle fell back to this process");
                self.turn_in_process(&keys, window).await
            }
        }
    }
}

/// The entries one kind of alert on one plane is kept under.
struct Keys {
    window: String,
    occurrences: String,
    at_last_alert: String,
}

impl Keys {
    /// The entries of `alert`.
    fn of(alert: &AlertKey) -> Self {
        let plane = plane_part(alert.plane);
        let kind = alert.event_type.as_str();
        let about = about_part(alert.about);
        Self {
            window: key(&["alert", &plane, kind, &about, "window"]),
            occurrences: key(&["alert", &plane, kind, &about, "seen"]),
            at_last_alert: key(&["alert", &plane, kind, &about, "told"]),
        }
    }
}

/// The part of a key that names what within its kind an alert is about.
fn about_part(about: AlertAbout) -> String {
    match about {
        AlertAbout::Kind => "kind".to_owned(),
        AlertAbout::AgentAttack { agent_id, attack } => {
            format!("agent:{agent_id}:{}", attack.as_str())
        }
    }
}

/// The part of a key that names `plane`.
fn plane_part(plane: AlertPlane) -> String {
    match plane {
        AlertPlane::Tenant(tenant_id) => format!("tenant:{tenant_id}"),
        AlertPlane::Organization(organization_id) => format!("organization:{organization_id}"),
        AlertPlane::Platform => "platform".to_owned(),
    }
}

/// Counts one occurrence on `state` and answers whether its alert goes out
/// now, with how many came since the last.
async fn turn_on(
    state: &dyn SharedState,
    keys: &Keys,
    window: Duration,
) -> Result<AlertTurn, CacheError> {
    let seen = state.count(&keys.occurrences, 1, COUNTED_FOR).await?;
    if !state.claim_once(&keys.window, window).await? {
        return Ok(AlertTurn::HeldBack);
    }
    let before = state
        .swap(&keys.at_last_alert, &seen.to_string(), COUNTED_FOR)
        .await?;
    Ok(AlertTurn::Raise {
        since_last: since_last(before.as_deref(), seen),
    })
}

/// How many occurrences came since the last alert, the counter standing at
/// `seen` now and at `before` then, or `None` when no alert came before.
/// A counter that started over since is read from where it started.
fn since_last(before: Option<&str>, seen: u64) -> Option<u64> {
    let before = before?.parse::<u64>().ok()?;
    Some(
        seen.checked_sub(before)
            .filter(|moved| *moved > 0)
            .unwrap_or(seen),
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::token_attack::TokenAttack;
    use ianua_domain::types::event_type::{AgentsEvent, OAuthEvent, ProxyEvent};
    use ianua_domain::types::{AgentId, EventType, TenantId};

    use super::*;
    use crate::cache::stores::RefusingState;

    const SHORT: time::Duration = time::Duration::milliseconds(50);

    fn throttle() -> CacheAlertThrottle {
        CacheAlertThrottle::new(Arc::new(MemoryState::new(1_000)))
    }

    fn canary_in(tenant_id: TenantId) -> AlertKey {
        AlertKey {
            plane: AlertPlane::Tenant(tenant_id),
            event_type: EventType::from(ProxyEvent::CanaryTokenTriggered),
            about: AlertAbout::Kind,
        }
    }

    /// Attempts at `agent_id` in `tenant_id` looking like `attack`.
    fn agent_attack(tenant_id: TenantId, agent_id: AgentId, attack: TokenAttack) -> AlertKey {
        AlertKey {
            plane: AlertPlane::Tenant(tenant_id),
            event_type: EventType::from(AgentsEvent::TokenAttackRefused),
            about: AlertAbout::AgentAttack { agent_id, attack },
        }
    }

    /// Repeating one agent's alert is held back, while another agent or attack kind
    /// gets its own alert window.
    #[tokio::test]
    async fn each_agent_and_attack_has_its_own_window() {
        let throttle = throttle();
        let acme = TenantId::new();
        let billing = AgentId::new();
        let forged = agent_attack(acme, billing, TokenAttack::Forged);
        throttle.admit(&forged, time::Duration::HOUR).await;

        let again = throttle.admit(&forged, time::Duration::HOUR).await;
        let payroll = throttle
            .admit(
                &agent_attack(acme, AgentId::new(), TokenAttack::Replayed),
                time::Duration::HOUR,
            )
            .await;
        let replayed = throttle
            .admit(
                &agent_attack(acme, billing, TokenAttack::Replayed),
                time::Duration::HOUR,
            )
            .await;

        assert_eq!(again, AlertTurn::HeldBack);
        assert_eq!(payroll, AlertTurn::Raise { since_last: None });
        assert_eq!(replayed, AlertTurn::Raise { since_last: None });
    }

    /// The first canary hit in Acme is told, as the first alert of its kind.
    #[tokio::test]
    async fn the_first_occurrence_is_told() {
        let throttle = throttle();

        let turn = throttle.admit(&canary_in(TenantId::new()), SHORT).await;

        assert_eq!(turn, AlertTurn::Raise { since_last: None });
    }

    /// A canary hit raises an alert once; a second hit within its window is held back.
    #[tokio::test]
    async fn a_repeat_within_the_window_is_held_back() {
        let throttle = throttle();
        let acme = canary_in(TenantId::new());
        throttle.admit(&acme, time::Duration::HOUR).await;

        let again = throttle.admit(&acme, time::Duration::HOUR).await;

        assert_eq!(again, AlertTurn::HeldBack);
    }

    /// Once the window passed, the next hit is told again, counting the
    /// hits since the last alert, the held-back one included.
    #[tokio::test]
    async fn after_the_window_the_next_is_told_with_the_count() {
        let throttle = throttle();
        let acme = canary_in(TenantId::new());
        throttle.admit(&acme, SHORT).await;
        throttle.admit(&acme, SHORT).await;
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let later = throttle.admit(&acme, SHORT).await;

        assert_eq!(
            later,
            AlertTurn::Raise {
                since_last: Some(2)
            }
        );
    }

    /// Alert throttling keeps separate windows for different event kinds and tenant or platform scopes.
    #[tokio::test]
    async fn each_kind_on_each_plane_has_its_own_window() {
        let throttle = throttle();
        let acme = TenantId::new();
        throttle.admit(&canary_in(acme), time::Duration::HOUR).await;
        let reused = AlertKey {
            plane: AlertPlane::Tenant(acme),
            event_type: EventType::from(OAuthEvent::RefreshTokenReused),
            about: AlertAbout::Kind,
        };

        let in_globex = throttle
            .admit(&canary_in(TenantId::new()), time::Duration::HOUR)
            .await;
        let other_kind = throttle.admit(&reused, time::Duration::HOUR).await;

        assert_eq!(in_globex, AlertTurn::Raise { since_last: None });
        assert_eq!(other_kind, AlertTurn::Raise { since_last: None });
    }

    /// During a shared-state outage, the process-local fallback raises the first alert
    /// and holds back its repeat.
    #[tokio::test]
    async fn a_state_that_is_down_tells_once_per_window_from_this_process() {
        let throttle = CacheAlertThrottle::new(Arc::new(RefusingState));
        let acme = canary_in(TenantId::new());

        let first = throttle.admit(&acme, time::Duration::HOUR).await;
        let again = throttle.admit(&acme, time::Duration::HOUR).await;

        assert_eq!(first, AlertTurn::Raise { since_last: None });
        assert_eq!(again, AlertTurn::HeldBack);
    }

    /// A counter that started over since the last alert counts from where
    /// it started, rather than answering nothing.
    #[test]
    fn a_counter_that_started_over_counts_from_its_start() {
        assert_eq!(since_last(Some("7"), 3), Some(3));
        assert_eq!(since_last(Some("3"), 7), Some(4));
        assert_eq!(since_last(None, 1), None);
    }
}
