//! Handing a session from the host it was opened on to a host of another
//! service that accepts it with a cookie of its own.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::events::app_session::AppSessionHandedOver;
use crate::domains::authentication::sessions::session::Session;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{DomainName, Label, Lifetime, ServiceId, SessionId, TokenHash, Usage};

/// The longest a handoff code may live. It covers one redirect.
pub(crate) const HANDOFF_LONGEST: Duration = Duration::minutes(5);

/// A one-time pass that lets one host set its own cookie for a session
/// opened on another.
///
/// The browser landing on a host of a service that accepts the sign-in with
/// its own cookie first keeps a random value in a cookie of that host, then
/// asks the owner's host, where its session is, for a code. The code is
/// random and good for that one host and service; only its hash is kept
/// here, with the hash of the browser's value. It lapses at the end of the
/// short lifetime it was issued with, and works once, and only in the
/// browser holding that value.
///
/// The code travels in a redirect, so it can turn up in a browser history,
/// a proxy log or a referrer. Mallory finds Ann's spent code there. Without
/// the one use, she sets the files app's cookie for Ann's session in her own
/// browser while the code is still in date.
///
/// Without the browser's value, a code is a link anyone can be sent. Eve
/// signs in on the shop and sends Ann the link carrying her own code; Ann
/// opens it and is signed in on the files app as Eve, and what she types
/// there is Eve's to read. Ann's browser does not hold the value Eve's code
/// was bound to, so the link sets nothing.
#[derive(Debug)]
pub struct SessionHandoff<T: TenantScope> {
    token_hash: TokenHash,
    browser_hash: TokenHash,
    session_id: SessionId,
    service_id: ServiceId,
    host: DomainName,
    expires_at: OffsetDateTime,
    usage: Usage,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Persisted state for repository hydration.
pub struct SessionHandoffRow {
    /// One-way hash of the code the browser carries.
    pub token_hash: TokenHash,
    /// One-way hash of the value the browser that asked for the code keeps.
    pub browser_hash: TokenHash,
    /// The session being handed on.
    pub session_id: SessionId,
    /// The service whose cookie the code may set.
    pub service_id: ServiceId,
    /// The host the code may be used on.
    pub host: DomainName,
    /// When the code lapses.
    pub expires_at: OffsetDateTime,
    /// Whether the code was used, and when. A use comes before the code
    /// lapses.
    pub usage: Usage,
}

/// What a handoff is for.
pub struct HandoffTarget {
    /// The service whose cookie it may set.
    pub service_id: ServiceId,
    /// The host it may be used on.
    pub host: DomainName,
}

/// The two hashes a handoff is found and checked by. Neither is ever shown,
/// so this has no `Debug`.
pub struct HandoffKeys {
    /// One-way hash of the code the browser carries.
    pub code: TokenHash,
    /// One-way hash of the value the browser asking for the code keeps.
    pub browser: TokenHash,
}

/// Where a code was brought, and by which browser.
pub struct HandoffLanding<'a> {
    /// The service whose cookie it is to set.
    pub service: &'a ServiceId,
    /// That service's name, for the record of the hand-over.
    pub service_name: &'a Label,
    /// The host it arrived on.
    pub host: &'a DomainName,
    /// One-way hash of the value the arriving browser holds.
    pub browser: &'a TokenHash,
}

impl<T: TenantScope> SessionHandoff<T> {
    /// Hands `session` to `target`, for whoever holds the code hashing to
    /// `keys.code` in the browser whose value hashes to `keys.browser`.
    ///
    /// Only a finished, live session is handed on. One that is suspended,
    /// revoked, expired or still owes a factor would reach the other host
    /// with a cookie of its own, past what it was waiting for.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the session cannot accept requests.
    /// - [`DomainError::Validation`] when `lifetime` is longer than
    ///   `HANDOFF_LONGEST`.
    pub fn issue(
        session: &Session<T>,
        target: HandoffTarget,
        keys: HandoffKeys,
        lifetime: Lifetime,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        if !session.is_usable(now) {
            return Err(DomainError::forbidden(message!(
                "authentication-only-a-finished-live-session-is",
                "only a finished, live session is handed to another host"
            )));
        }
        lifetime.ensure_at_most(HANDOFF_LONGEST, "a handoff code")?;
        Ok(Self {
            token_hash: keys.code,
            browser_hash: keys.browser,
            session_id: *session.id(),
            service_id: target.service_id,
            host: target.host,
            expires_at: now.saturating_add(lifetime.duration()),
            usage: Usage::Unused,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds a handoff from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the code was used
    ///   once it had lapsed.
    pub fn reconstitute(row: SessionHandoffRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            browser_hash: row.browser_hash,
            session_id: row.session_id,
            service_id: row.service_id,
            host: row.host,
            expires_at: row.expires_at,
            usage: row.usage,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SessionHandoffRow) -> Result<(), DomainError> {
        RowCheck::of("session handoff")
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "used after it lapsed",
            )
            .finish()
    }

    /// One-way hash of the code the browser carries.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// One-way hash of the value the browser that asked for the code keeps.
    #[must_use]
    pub fn browser_hash(&self) -> &TokenHash {
        &self.browser_hash
    }

    /// The session being handed on.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The service whose cookie the code may set.
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// The host the code may be used on.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }

    /// When the code lapses.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the code was used, if it was.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// Whether the code, still unused, may set the landing service's cookie
    /// on the landing host at `now`, in the landing browser.
    #[must_use]
    pub fn admits(&self, landing: &HandoffLanding<'_>, now: OffsetDateTime) -> bool {
        !self.usage.is_used()
            && now < self.expires_at
            && self.service_id == *landing.service
            && self
                .host
                .as_str()
                .eq_ignore_ascii_case(landing.host.as_str())
            && self.browser_hash == *landing.browser
    }

    /// Spends the code to set the landing service's cookie on the landing
    /// host at `now`, and gives back the session it hands on. This is the
    /// only way it is used.
    ///
    /// Raises `authentication.app_session_handed_over`, naming the service
    /// and the host.
    ///
    /// A refused code is left as it was.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the code was used already, has
    ///   lapsed, was issued for another service or host, or arrived in a
    ///   browser other than the one that asked for it.
    pub fn redeem(
        &mut self,
        landing: &HandoffLanding<'_>,
        now: OffsetDateTime,
    ) -> Result<SessionId, DomainError> {
        if !self.admits(landing, now) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-handoff-code-is-spent-lapsed",
                "the handoff code is spent, lapsed, or meant for another host or browser"
            )));
        }
        self.usage = Usage::Used { at: now };
        self.raised.raise(AppSessionHandedOver {
            session_id: self.session_id,
            service_id: self.service_id,
            service_name: landing.service_name.clone(),
            host: landing.host.clone(),
            occurred_at: now,
        });
        Ok(self.session_id)
    }
}

impl<T: TenantScope> Raises for SessionHandoff<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::session::tests::{
        signed_in_session, test_session,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    /// The name of the files service the codes hand sessions to.
    fn files() -> Label {
        Label::new("name", "files-api").unwrap()
    }

    /// The hash of the value the browser kept when it asked for the code.
    fn asking_browser() -> TokenHash {
        TokenHash::from_stored("asking-browser".to_owned())
    }

    /// The hash of the value another browser holds.
    fn other_browser() -> TokenHash {
        TokenHash::from_stored("other-browser".to_owned())
    }

    fn handing(
        session: &Session<ResolvedTenant>,
        service_id: ServiceId,
        lifetime: Duration,
    ) -> Result<SessionHandoff<ResolvedTenant>, DomainError> {
        SessionHandoff::issue(
            session,
            HandoffTarget {
                service_id,
                host: DomainName::new("api.example.com").unwrap(),
            },
            HandoffKeys {
                code: TokenHash::from_stored("hash".to_owned()),
                browser: asking_browser(),
            },
            Lifetime::new(lifetime).unwrap(),
        )
    }

    fn handoff(service_id: ServiceId) -> SessionHandoff<ResolvedTenant> {
        handing(&signed_in_session(), service_id, Duration::seconds(60)).unwrap()
    }

    /// Where a code is brought: a service on a host, in the browser whose
    /// value hashes to `browser`.
    struct Arrival {
        service: ServiceId,
        name: Label,
        host: DomainName,
        browser: TokenHash,
    }

    impl Arrival {
        fn landing(&self) -> HandoffLanding<'_> {
            HandoffLanding {
                service: &self.service,
                service_name: &self.name,
                host: &self.host,
                browser: &self.browser,
            }
        }
    }

    /// The files service arriving on `on`, in the browser that asked for the
    /// code.
    fn arriving(service: ServiceId, on: &str) -> Arrival {
        Arrival {
            service,
            name: files(),
            host: host(on),
            browser: asking_browser(),
        }
    }

    fn redeemed(
        code: &mut SessionHandoff<ResolvedTenant>,
        arrival: &Arrival,
        now: OffsetDateTime,
    ) -> Result<SessionId, DomainError> {
        code.redeem(&arrival.landing(), now)
    }

    /// A session still owing its second factor cannot issue a handoff code.
    #[test]
    fn a_session_still_owing_a_factor_is_not_handed_on() {
        let refused = handing(&test_session(), ServiceId::new(), Duration::seconds(60));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A handoff code asked to live for a day is refused. Five minutes is
    /// the most, enough for one redirect.
    #[test]
    fn a_handoff_code_lives_at_most_five_minutes() {
        let session = signed_in_session();

        let refused = handing(&session, ServiceId::new(), Duration::days(1));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// A fresh code for the files service on `api.example.com` admits that
    /// service there, in the browser that asked for it. The host is matched
    /// without regard to case.
    #[test]
    fn a_fresh_code_admits_its_service_on_its_host() {
        let service = ServiceId::new();

        assert!(handoff(service).admits(
            &arriving(service, "API.example.com").landing(),
            crate::shared::clock::now()
        ));
    }

    /// A handoff code admits neither another service nor another host.
    #[test]
    fn a_code_admits_no_other_service_or_host() {
        let service = ServiceId::new();
        let code = handoff(service);
        let now = crate::shared::clock::now();

        assert!(!code.admits(
            &arriving(ServiceId::new(), "api.example.com").landing(),
            now
        ));
        assert!(!code.admits(&arriving(service, "other.example.com").landing(), now));
    }

    /// A different browser binding prevents redemption. The code remains
    /// unspent and raises no event.
    #[test]
    fn a_code_opened_in_another_browser_is_refused() {
        let service = ServiceId::new();
        let mut code = handoff(service);
        let in_anns_browser = Arrival {
            browser: other_browser(),
            ..arriving(service, "api.example.com")
        };

        let refused = redeemed(&mut code, &in_anns_browser, crate::shared::clock::now());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), None);
        assert!(raised_names(&mut code).is_empty());
    }

    /// A code issued for 60 seconds admits nothing 61 seconds later.
    #[test]
    fn a_code_lapses_after_a_minute() {
        let service = ServiceId::new();
        let code = handoff(service);

        let later = crate::shared::clock::now() + Duration::seconds(61);

        assert!(!code.admits(&arriving(service, "api.example.com").landing(), later));
    }

    /// The first redemption returns the issuing session's id and records its
    /// use time. Replaying the code is refused and it admits no further arrival.
    #[test]
    fn a_handoff_code_works_once() {
        let service = ServiceId::new();
        let session = signed_in_session();
        let mut code = handing(&session, service, Duration::seconds(60)).unwrap();
        let now = crate::shared::clock::now();
        let on_api = arriving(service, "api.example.com");

        let handed = redeemed(&mut code, &on_api, now).unwrap();
        let replayed = redeemed(&mut code, &on_api, now);

        assert_eq!(handed, *session.id());
        assert!(matches!(replayed, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), Some(now));
        assert!(!code.admits(&on_api.landing(), now));
    }

    /// Redemption at the wrong host leaves the code unspent, so the intended
    /// host can still redeem it.
    #[test]
    fn a_refused_code_is_left_unspent() {
        let service = ServiceId::new();
        let mut code = handoff(service);
        let now = crate::shared::clock::now();

        let refused = redeemed(&mut code, &arriving(service, "other.example.com"), now);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), None);
        assert!(redeemed(&mut code, &arriving(service, "api.example.com"), now).is_ok());
    }

    fn stored(usage: Usage) -> SessionHandoffRow {
        SessionHandoffRow {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            browser_hash: asking_browser(),
            session_id: SessionId::new(),
            service_id: ServiceId::new(),
            host: DomainName::new("api.example.com").unwrap(),
            expires_at: crate::shared::clock::now() + Duration::seconds(60),
            usage,
        }
    }

    /// Loading a used handoff code preserves its use time and rejects replay.
    #[test]
    fn a_stored_spent_code_stays_spent() {
        let used_at = crate::shared::clock::now();
        let row = stored(Usage::Used { at: used_at });
        let service = row.service_id;
        let mut code = SessionHandoff::<ResolvedTenant>::reconstitute(row).unwrap();

        let replayed = redeemed(&mut code, &arriving(service, "api.example.com"), used_at);

        assert!(matches!(replayed, Err(DomainError::Forbidden(_))));
        assert_eq!(code.consumed_at(), Some(used_at));
    }

    /// A stored code says it was used a second after it lapsed. No use is
    /// let through once a code lapses, so loading it is refused as corrupt.
    #[test]
    fn a_stored_code_used_after_it_lapsed_is_refused() {
        let mut row = stored(Usage::Unused);
        row.usage = Usage::Used {
            at: row.expires_at + Duration::SECOND,
        };

        assert!(refused_as_corrupt(
            &SessionHandoff::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann's code sets the files app's cookie on `api.example.com`. The
    /// handoff raises `authentication.app_session_handed_over`, naming the
    /// service and the host.
    #[test]
    fn spending_a_code_raises_the_handover() {
        let service = ServiceId::new();
        let mut code = handoff(service);

        redeemed(
            &mut code,
            &arriving(service, "api.example.com"),
            crate::shared::clock::now(),
        )
        .unwrap();

        let events = raised(&mut code);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.app_session_handed_over"
        );
        assert_eq!(events[0].payload().get("host"), Some("api.example.com"));
    }

    /// A wrong-host redemption raises no event. Loading an unused code also
    /// starts with an empty event queue.
    #[test]
    fn a_refused_issued_or_stored_code_raises_nothing() {
        let service = ServiceId::new();
        let mut code = handoff(service);
        let mut stored =
            SessionHandoff::<ResolvedTenant>::reconstitute(stored(Usage::Unused)).unwrap();

        let refused = redeemed(
            &mut code,
            &arriving(service, "other.example.com"),
            crate::shared::clock::now(),
        );

        assert!(refused.is_err());
        assert!(raised_names(&mut code).is_empty());
        assert!(raised_names(&mut stored).is_empty());
    }
}
