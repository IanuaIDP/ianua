//! Holding each use of a session against where it was last used, so a
//! session that suddenly stops looking like its holder stops working.
//!
//! Mallory copies Pat's session cookie and uses it from Poznań twenty
//! minutes after Pat used it in Berlin. The API and the gateway ask this on
//! every request a session carried: the session freezes, Mallory is
//! refused, and Pat lifts it with her own second factor.
//!
//! The question costs nothing most of the time. The same session from the
//! same network was looked at a moment ago, so no store is read and nothing
//! is written. A network this node has not seen for the session in a few
//! minutes costs one read, and the write of where it now is.
//!
//! The answer is the domain's, in [`Session::note_use`]. This case only
//! reads what it needs and carries out what the domain decided. Which
//! session gets to freeze is settled in the store, so two requests racing
//! to freeze one session record one event.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::sessions::last_use::{
    CallerNetwork, ObservedUse, UseNoted, WayBack,
};
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Fact, IpAddress, SessionId, UserId};
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{FactorStanding, Geolocator};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::holder::account_label;

/// How long one network of one session counts as already looked at. A busy
/// session on one network costs at most one read and one write this often,
/// and the last use's time is off by at most this much.
const RECENT_FOR: Duration = Duration::minutes(5);

/// How many sessions a node remembers having seen, each with one network.
const REMEMBERED: usize = 200_000;

/// The ports [`WatchUseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct WatchUsePorts {
    /// Where the session is kept.
    pub session_store: Arc<dyn SessionStore>,
    /// Places the request's address.
    pub geolocator: Arc<dyn Geolocator>,
    /// Whether the holder has a second factor that could lift a freeze.
    pub factors: Arc<dyn FactorStanding>,
    /// The session's account, for how the record names it.
    pub users: Arc<dyn UserStore>,
}

/// One use of a session to hold against where it was last used.
pub struct WatchUseRequest {
    /// The session the request came with.
    pub session_id: SessionId,
    /// The address it came from.
    pub ip_address: Fact<IpAddress>,
}

/// What became of the session a request came with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStanding {
    /// It still counts: the rest of the request goes ahead, and whatever
    /// else it is held to is checked as usual.
    Stands,
    /// It was stopped because its use stopped looking like its holder. The
    /// request is refused as if the session were not there.
    Stopped,
}

/// Holds one use of a session against where it was last used.
pub struct WatchUseUseCase {
    ports: WatchUsePorts,
    recent: RecentUses,
}

impl WatchUseUseCase {
    /// A use case working through `ports`, remembering what this node saw
    /// lately to keep the cost bounded.
    #[must_use]
    pub fn new(ports: WatchUsePorts) -> Self {
        Self {
            ports,
            recent: RecentUses::new(RECENT_FOR, REMEMBERED),
        }
    }

    /// The use of the session named in `request` from `network`, once this
    /// node has not just looked at it.
    async fn judged(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: &WatchUseRequest,
        network: CallerNetwork,
    ) -> Result<SessionStanding, AppError> {
        let store = self.ports.session_store.as_ref();
        let now = clock::now();
        let Some(mut session) = store
            .find_by_id(tenant, &request.session_id)
            .await
            .or_internal()?
        else {
            return Ok(SessionStanding::Stands);
        };
        if !session.is_usable(now) {
            return Ok(SessionStanding::Stands);
        }
        let observed = ObservedUse {
            network,
            place: self.place_of(&request.ip_address).await,
        };
        let noted = session.note_use(observed, now);
        self.apply(tenant, auditor, &mut session, noted).await
    }

    /// Writes down what `noted` came to for `session`.
    async fn apply(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        session: &mut Session<ResolvedTenant>,
        noted: UseNoted,
    ) -> Result<SessionStanding, AppError> {
        match noted {
            UseNoted::Unchanged => Ok(SessionStanding::Stands),
            UseNoted::Moved => {
                self.ports
                    .session_store
                    .keep_last_use(tenant, session)
                    .await
                    .or_internal()?;
                Ok(SessionStanding::Stands)
            }
            UseNoted::LooksTakenOver => {
                self.stop(tenant, auditor, session).await?;
                Ok(SessionStanding::Stopped)
            }
        }
    }

    /// Where `ip` is, when it can be told. A lookup that fails is a place
    /// nobody knows, which never freezes anything.
    async fn place_of(&self, ip: &Fact<IpAddress>) -> Fact<IpGeolocation> {
        let Fact::Known(ip) = ip else {
            return Fact::Unknown;
        };
        match self.ports.geolocator.locate(ip).await {
            Ok(place) => Fact::from_option(place),
            Err(error) => {
                tracing::warn!(%error, "a session's use could not be placed");
                Fact::Unknown
            }
        }
    }

    /// Stops `session` as the domain says it should stop for its holder,
    /// and records it, if this request won the race to stop it. A loser
    /// is refused all the same.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the holder or the store cannot answer,
    ///   so nothing is decided and the request is refused.
    async fn stop(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        session: &mut Session<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let holder = *session.user_id();
        let way_back = self.way_back(tenant, &holder).await?;
        let account = self
            .ports
            .users
            .find_by_id(tenant, &holder)
            .await
            .or_internal()?;
        session
            .stop_taken_over(way_back, account_label(account.as_ref(), &holder))
            .map_err(|refused| AppError::from_domain(refused.into()))?;
        let stopped = self
            .ports
            .session_store
            .stop_if_active(tenant, session)
            .await
            .or_internal()?;
        if !stopped {
            return Ok(());
        }
        auditor
            .dispatch_by(&ActorRef::System, session.take_events(tenant))
            .await
            .or_internal()
    }

    /// How the holder gets back in: their own factor, or a fresh sign-in.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the standing cannot be read.
    async fn way_back(&self, tenant: &ScopedTenant, holder: &UserId) -> Result<WayBack, AppError> {
        let holds = self
            .ports
            .factors
            .holds_active_factor(tenant, holder)
            .await
            .or_internal()?;
        Ok(match holds {
            true => WayBack::OwnFactor,
            false => WayBack::FreshSignIn,
        })
    }
}

impl Command for WatchUseUseCase {
    type Caller = ScopedTenant;
    type Input = WatchUseRequest;
    type Output = Result<SessionStanding, AppError>;

    /// Holds a use of the session against where it was last used, and
    /// stops the session if that makes it look taken over. A session not
    /// found or not usable stands: it is refused elsewhere, and a frozen
    /// one must still reach the step that lifts it.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a store cannot be read or written. The
    ///   request is refused, not waved through; the next one asks again,
    ///   since nothing is remembered from a failed look.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: WatchUseRequest,
    ) -> Result<SessionStanding, AppError> {
        let Fact::Known(network) = CallerNetwork::of(request.ip_address.as_ref()) else {
            return Ok(SessionStanding::Stands);
        };
        let now = clock::now();
        if self.recent.was_seen(&request.session_id, &network, now) {
            return Ok(SessionStanding::Stands);
        }
        let standing = self
            .judged(tenant, auditor, &request, network.clone())
            .await?;
        self.recent.mark_seen(request.session_id, network, now);
        Ok(standing)
    }
}

/// What this node saw lately: which network of which session was held
/// against the store, and when.
///
/// The lock is held only to read and write one entry, never across an
/// await, so a plain mutex is the right tool.
struct RecentUses {
    seen: Mutex<HashMap<(SessionId, CallerNetwork), OffsetDateTime>>,
    interval: Duration,
    capacity: usize,
}

impl RecentUses {
    fn new(interval: Duration, capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            interval,
            capacity,
        }
    }

    /// Whether `session` from `network` was looked at within the interval.
    /// A poisoned lock reads as not seen: forgetting only costs a read.
    fn was_seen(&self, session: &SessionId, network: &CallerNetwork, now: OffsetDateTime) -> bool {
        let Ok(seen) = self.seen.lock() else {
            return false;
        };
        seen.get(&(*session, network.clone()))
            .is_some_and(|at| clock::between(*at, now) < self.interval)
    }

    /// Remembers `session` from `network` as looked at now. A full memory
    /// forgets what is past the interval first, and everything when that
    /// is not enough: forgetting only costs a read.
    fn mark_seen(&self, session: SessionId, network: CallerNetwork, now: OffsetDateTime) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        if seen.len() >= self.capacity {
            seen.retain(|_, at| clock::between(*at, now) < self.interval);
        }
        if seen.len() >= self.capacity {
            seen.clear();
        }
        seen.insert((session, network), now);
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::events::session::SuspensionReason;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::types::{CountryCode, EventLabel};

    use super::*;
    use crate::test_support::authentication::{
        FakeFactorStanding, FakeGeolocator, FakeSessionStore, session_signed_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx,
    };

    const BERLIN: (f64, f64, &str) = (52.52, 13.405, "DE");
    const MUNICH: (f64, f64, &str) = (48.14, 11.58, "DE");
    const POZNAN: (f64, f64, &str) = (52.40, 16.92, "PL");

    const BERLIN_ADDRESS: &str = "198.18.0.7";
    const POZNAN_ADDRESS: &str = "198.18.1.7";

    const SUSPENDED: &str = "authentication.session_suspended";
    const REVOKED: &str = "authentication.session_revoked";

    fn place_at(place: (f64, f64, &str)) -> IpGeolocation {
        IpGeolocation::new(place.0, place.1, CountryCode::new(place.2).unwrap(), None).unwrap()
    }

    fn network(ip: &str) -> CallerNetwork {
        CallerNetwork::of(Fact::Known(&IpAddress::new(ip).unwrap()))
            .known()
            .cloned()
            .unwrap()
    }

    fn proved_by_code() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::Proved(MfaFactor::Totp),
            owed: SecondFactor::NotOwed,
        }
    }

    struct Fixture {
        pat: UserId,
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        users: Arc<FakeUserStore>,
        events: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn signed_in() -> Self {
            let pat = UserId::new();
            let session = session_signed_in(pat, proved_by_code());
            Self {
                pat,
                session_id: *session.id(),
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                users: Arc::new(FakeUserStore::with_user(pat, "pat@acme.test")),
                events: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn use_case(
            &self,
            standing: FakeFactorStanding,
            place: Option<(f64, f64, &str)>,
        ) -> WatchUseUseCase {
            WatchUseUseCase::new(WatchUsePorts {
                session_store: self.sessions.clone(),
                geolocator: Arc::new(FakeGeolocator {
                    location: place.map(place_at),
                }),
                factors: Arc::new(standing),
                users: self.users.clone(),
            })
        }

        fn standing_on(&self, use_case: &WatchUseUseCase, ip: &str) -> SessionStanding {
            let auditor = test_auditor(self.events.clone());
            let request = WatchUseRequest {
                session_id: self.session_id,
                ip_address: Fact::Known(IpAddress::new(ip).unwrap()),
            };
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, request)).unwrap()
        }

        fn status(&self) -> Option<SessionStatus> {
            self.sessions.get_status(&self.session_id)
        }

        fn events_named(&self, name: &str) -> usize {
            self.events
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|recorded| recorded.as_str() == name)
                .count()
        }

        fn holding_a_factor(&self) -> FakeFactorStanding {
            FakeFactorStanding::holding(self.pat)
        }
    }

    /// Pat's use in Berlin is held against nothing; her session is on
    /// record as being in Germany, and nothing is frozen.
    #[test]
    fn a_first_placed_use_only_records_the_place() {
        let fixture = Fixture::signed_in();
        let use_case = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));

        let standing = fixture.standing_on(&use_case, BERLIN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stands);
        assert_eq!(fixture.status(), Some(SessionStatus::Active));
    }

    /// Mallory uses Pat's session from Poznań just after Pat used it in
    /// Berlin. Pat has a factor, so it freezes, Mallory is refused and the
    /// freeze is recorded once with the reason and no token.
    #[test]
    fn fast_travel_freezes_a_session_that_has_a_factor_to_lift_it() {
        let fixture = Fixture::signed_in();
        let in_berlin = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let in_poznan = fixture.use_case(fixture.holding_a_factor(), Some(POZNAN));

        let standing = fixture.standing_on(&in_poznan, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stopped);
        assert_eq!(fixture.status(), Some(SessionStatus::Suspended));
        assert_eq!(fixture.events_named(SUSPENDED), 1);
        let payloads = fixture.events.all_payloads();
        assert_eq!(payloads[0].get("reason"), Some("fast travel"));
    }

    /// Lou has only a password, so a freeze nothing could lift would lock
    /// him out. The session ends instead and he signs in again.
    #[test]
    fn fast_travel_ends_a_session_whose_holder_has_no_factor() {
        let fixture = Fixture::signed_in();
        let in_berlin = fixture.use_case(FakeFactorStanding::default(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let in_poznan = fixture.use_case(FakeFactorStanding::default(), Some(POZNAN));

        let standing = fixture.standing_on(&in_poznan, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stopped);
        assert_eq!(fixture.status(), Some(SessionStatus::Revoked));
        assert_eq!(fixture.events_named(REVOKED), 1);
    }

    /// Pat goes from a cafe's Wi-Fi in Berlin to her carrier's Munich
    /// gateway. A new network in the same country does not freeze her.
    #[test]
    fn a_new_network_in_the_same_country_does_not_freeze() {
        let fixture = Fixture::signed_in();
        let in_berlin = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let in_munich = fixture.use_case(fixture.holding_a_factor(), Some(MUNICH));

        let standing = fixture.standing_on(&in_munich, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stands);
        assert_eq!(fixture.status(), Some(SessionStatus::Active));
    }

    /// A geolocator with no answer never freezes anything.
    #[test]
    fn an_address_that_cannot_be_placed_never_freezes() {
        let fixture = Fixture::signed_in();
        let in_berlin = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let unplaced = fixture.use_case(fixture.holding_a_factor(), None);

        let standing = fixture.standing_on(&unplaced, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stands);
        assert_eq!(fixture.status(), Some(SessionStatus::Active));
    }

    /// An address nobody saw has nothing to compare.
    #[test]
    fn an_unobserved_address_is_not_held_against_anything() {
        let fixture = Fixture::signed_in();
        let use_case = fixture.use_case(fixture.holding_a_factor(), Some(POZNAN));
        let auditor = test_auditor(fixture.events.clone());
        let request = WatchUseRequest {
            session_id: fixture.session_id,
            ip_address: Fact::Unknown,
        };

        let standing = block_on(use_case.execute(&test_ctx().tenant(), &auditor, request)).unwrap();

        assert_eq!(standing, SessionStanding::Stands);
    }

    /// A busy session on one network is looked at once, then not for the
    /// rest of the interval: Pat's page-loads cost no read and no write.
    #[test]
    fn one_look_per_network_per_interval() {
        let recent = RecentUses::new(Duration::minutes(5), 10);
        let (session, network, now) = (SessionId::new(), network(BERLIN_ADDRESS), clock::now());

        assert!(!recent.was_seen(&session, &network, now));
        recent.mark_seen(session, network.clone(), now);

        assert!(recent.was_seen(&session, &network, now + Duration::minutes(4)));
        assert!(!recent.was_seen(&session, &network, now + Duration::minutes(5)));
    }

    /// A different network of the same session is a new look at once, so
    /// a stolen cookie is checked on its very first request.
    #[test]
    fn another_network_is_a_new_look() {
        let recent = RecentUses::new(Duration::minutes(5), 10);
        let (session, now) = (SessionId::new(), clock::now());
        recent.mark_seen(session, network(BERLIN_ADDRESS), now);

        assert!(!recent.was_seen(&session, &network(POZNAN_ADDRESS), now));
    }

    /// Past its capacity the memory keeps no more than it may, forgetting
    /// what is past the interval first and everything else if it must: a
    /// forgotten entry costs a read, never a wrong answer.
    #[test]
    fn a_full_memory_forgets_without_error() {
        let recent = RecentUses::new(Duration::minutes(5), 1);
        let now = clock::now();
        let first = SessionId::new();
        recent.mark_seen(first, network(BERLIN_ADDRESS), now);

        recent.mark_seen(SessionId::new(), network(POZNAN_ADDRESS), now);

        assert!(!recent.was_seen(&first, &network(BERLIN_ADDRESS), now));
    }

    /// Two of Mallory's requests from Poznań race: both saw the session
    /// active in Berlin, but one freezes it first. The late one writes
    /// nothing, records nothing and is still refused.
    #[test]
    fn two_requests_racing_to_freeze_record_one_event() {
        let fixture = Fixture::signed_in();
        let in_berlin = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let as_both_saw = FakeSessionStore::with_session(session_copy(&fixture));
        block_on(
            fixture
                .sessions
                .save(&test_ctx().tenant(), &frozen_copy(&fixture)),
        )
        .unwrap();
        let in_poznan = WatchUseUseCase::new(WatchUsePorts {
            session_store: Arc::new(ReadBeforeWrite::new(as_both_saw, fixture.sessions.clone())),
            geolocator: Arc::new(FakeGeolocator {
                location: Some(place_at(POZNAN)),
            }),
            factors: Arc::new(fixture.holding_a_factor()),
            users: fixture.users.clone(),
        });

        let standing = fixture.standing_on(&in_poznan, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stopped);
        assert_eq!(fixture.events_named(SUSPENDED), 0);
    }

    fn session_copy(fixture: &Fixture) -> Session<ResolvedTenant> {
        block_on(
            fixture
                .sessions
                .find_by_id(&test_ctx().tenant(), &fixture.session_id),
        )
        .unwrap()
        .unwrap()
    }

    fn frozen_copy(fixture: &Fixture) -> Session<ResolvedTenant> {
        let mut session = session_copy(fixture);
        session
            .suspend(SuspensionReason::FastTravel, EventLabel::of("Pat"))
            .unwrap();
        session
    }

    /// Pat's session is frozen and her code lifts it from a request that
    /// passes through here too: a stopped session stands.
    #[test]
    fn a_frozen_session_stands_so_its_holder_can_lift_it() {
        let fixture = Fixture::signed_in();
        block_on(
            fixture
                .sessions
                .save(&test_ctx().tenant(), &frozen_copy(&fixture)),
        )
        .unwrap();
        let use_case = fixture.use_case(fixture.holding_a_factor(), Some(POZNAN));

        let standing = fixture.standing_on(&use_case, POZNAN_ADDRESS);

        assert_eq!(standing, SessionStanding::Stands);
        assert_eq!(fixture.status(), Some(SessionStatus::Suspended));
    }

    /// Nothing can be told about a session the store cannot read: the
    /// request is refused and the next one asks again.
    #[test]
    fn a_store_that_cannot_answer_fails_closed() {
        let fixture = Fixture::signed_in();
        let standing = FakeFactorStanding::holding(fixture.pat);
        *standing.fails.lock().unwrap() = true;
        let in_berlin = fixture.use_case(fixture.holding_a_factor(), Some(BERLIN));
        fixture.standing_on(&in_berlin, BERLIN_ADDRESS);
        let in_poznan = fixture.use_case(standing, Some(POZNAN));
        let auditor = test_auditor(fixture.events.clone());
        let request = WatchUseRequest {
            session_id: fixture.session_id,
            ip_address: Fact::Known(IpAddress::new(POZNAN_ADDRESS).unwrap()),
        };

        let refused = block_on(in_poznan.execute(&test_ctx().tenant(), &auditor, request));

        assert!(matches!(refused, Err(AppError::Internal(_))));
        assert_eq!(fixture.status(), Some(SessionStatus::Active));
    }
}
