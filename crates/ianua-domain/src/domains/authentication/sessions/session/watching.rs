//! Holding each use of a session against where it was last used, and
//! stopping a session whose use stopped looking like the person who signed
//! in.
//!
//! Mallory copies Pat's session cookie and uses it from Poznań twenty
//! minutes after Pat used it in Berlin. Pat's factor, or a fresh sign-in
//! when she has none, is the only way back.

use time::OffsetDateTime;

use crate::domains::authentication::events::session::{
    RevocationReason, SessionRevoked, SuspensionReason,
};
use crate::domains::authentication::sessions::last_use::{LastUse, ObservedUse, UseNoted, WayBack};
use crate::domains::authentication::sessions::session::Session;
use crate::domains::authentication::sessions::status::InvalidSessionTransition;
use crate::isolation::scope::TenantScope;
use crate::types::{EventLabel, Fact};

impl<T: TenantScope> Session<T> {
    /// Where this session was last used, when any use could be placed.
    #[must_use]
    pub fn last_use(&self) -> Fact<&LastUse> {
        self.last_use.as_ref()
    }

    /// What one use of this session, seen at `now`, comes to. Nothing is
    /// recorded but `last_use`, so the caller knows what to write.
    ///
    /// A use from the same network only stamps when it was last seen. A
    /// use from an address that cannot be placed changes nothing and never
    /// freezes anything: a VPN or a lookup that fails must not lock Pat
    /// out, and Mallory hiding behind one goes unmeasured until she
    /// comes from an address that can be. Any other new network moves the
    /// last use, unless the move is
    /// [fast travel](LastUse::is_fast_travel_to).
    pub fn note_use(&mut self, observed: ObservedUse, now: OffsetDateTime) -> UseNoted {
        let ObservedUse { network, place } = observed;
        let last = self.last_use.known();
        match (last, place) {
            (Some(last), place) if last.network() == &network => {
                self.last_use = Fact::Known(last.stamped(place, now));
                UseNoted::Moved
            }
            (Some(last), Fact::Known(place)) if last.is_fast_travel_to(&place, now) => {
                UseNoted::LooksTakenOver
            }
            (_, Fact::Known(place)) => {
                self.last_use = Fact::Known(LastUse::new(network, place, now));
                UseNoted::Moved
            }
            (_, Fact::Unknown) => UseNoted::Unchanged,
        }
    }

    /// Stops this session because its use stopped looking like the person
    /// who signed in, as `way_back` says they get back in. Holds
    /// `last_use` as it was, since who proves themselves next says where
    /// the session is. Raises `authentication.session_suspended`, or
    /// `authentication.session_revoked` when the holder has no factor to
    /// lift a freeze, naming the holder as `holder_label`.
    ///
    /// # Errors
    ///
    /// - [`InvalidSessionTransition`] when the session is not active.
    pub fn stop_taken_over(
        &mut self,
        way_back: WayBack,
        holder_label: EventLabel,
    ) -> Result<(), InvalidSessionTransition> {
        match way_back {
            WayBack::OwnFactor => self.suspend(SuspensionReason::FastTravel, holder_label),
            WayBack::FreshSignIn => self.end_as_taken_over(holder_label),
        }
    }

    /// Ends this session on suspicion of takeover and raises its
    /// revocation, naming the holder as `holder_label`.
    fn end_as_taken_over(
        &mut self,
        holder_label: EventLabel,
    ) -> Result<(), InvalidSessionTransition> {
        self.retire()?;
        self.raised.raise(SessionRevoked {
            session_id: self.id,
            user_id: self.user_id,
            user_label: Some(holder_label),
            reason: RevocationReason::SuspectedTakeover,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authentication::risk_engine::assessment::IpGeolocation;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::last_use::CallerNetwork;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::session::tests::{
        holders, rotated, signed_in_session,
    };
    use crate::domains::authentication::sessions::status::SessionStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised_names;
    use crate::types::{CountryCode, EventLabel, IpAddress};

    fn network(ip: &str) -> CallerNetwork {
        CallerNetwork::of(Fact::Known(&IpAddress::new(ip).unwrap()))
            .known()
            .cloned()
            .unwrap()
    }

    fn place(latitude: f64, longitude: f64, country: &str) -> IpGeolocation {
        IpGeolocation::new(
            latitude,
            longitude,
            CountryCode::new(country).unwrap(),
            None,
        )
        .unwrap()
    }

    fn berlin() -> Fact<IpGeolocation> {
        Fact::Known(place(52.52, 13.405, "DE"))
    }

    fn poznan() -> Fact<IpGeolocation> {
        Fact::Known(place(52.40, 16.92, "PL"))
    }

    fn observed(ip: &str, at: Fact<IpGeolocation>) -> ObservedUse {
        ObservedUse {
            network: network(ip),
            place: at,
        }
    }

    fn used_in_berlin() -> (Session<ResolvedTenant>, OffsetDateTime) {
        let mut session = signed_in_session();
        let at = crate::shared::clock::now();
        session.note_use(observed("198.18.0.7", berlin()), at);
        (session, at)
    }

    /// Pat's first placed use only records where they are; nothing to hold
    /// it against, so it never freezes.
    #[test]
    fn a_first_use_is_recorded_and_not_held_against_anything() {
        let mut session = signed_in_session();

        let noted = session.note_use(
            observed("198.18.0.7", berlin()),
            crate::shared::clock::now(),
        );

        assert_eq!(noted, UseNoted::Moved);
        assert!(session.last_use().known().is_some());
    }

    /// An address that cannot be placed leaves nothing behind.
    #[test]
    fn a_first_use_that_cannot_be_placed_records_nothing() {
        let mut session = signed_in_session();

        let noted = session.note_use(
            observed("198.18.0.7", Fact::Unknown),
            crate::shared::clock::now(),
        );

        assert_eq!(noted, UseNoted::Unchanged);
        assert!(session.last_use().known().is_none());
    }

    /// Pat keeps using the same network. Each use only stamps it, however
    /// far Berlin says the database has moved her network, because the
    /// network is what's compared.
    #[test]
    fn the_same_network_is_stamped_and_never_frozen() {
        let (mut session, at) = used_in_berlin();

        let noted = session.note_use(observed("198.18.0.7", poznan()), at + Duration::minutes(1));

        assert_eq!(noted, UseNoted::Moved);
        assert_eq!(
            session.last_use().known().unwrap().at(),
            at + Duration::minutes(1)
        );
    }

    /// Pat's use from Berlin is followed twenty minutes later by one from
    /// Poznań. It looks like someone else has her session.
    #[test]
    fn fast_travel_between_uses_looks_taken_over() {
        let (mut session, at) = used_in_berlin();

        let noted = session.note_use(observed("198.18.1.7", poznan()), at + Duration::minutes(20));

        assert_eq!(noted, UseNoted::LooksTakenOver);
        assert_eq!(
            session
                .last_use()
                .known()
                .unwrap()
                .place()
                .country_code()
                .as_str(),
            "DE",
            "where she was stays recorded, so whoever proves themselves next decides"
        );
    }

    /// Pat flies home a week later; that trip is unhurried, so the session
    /// just moves with her.
    #[test]
    fn an_unhurried_move_to_another_country_only_moves() {
        let (mut session, at) = used_in_berlin();

        let noted = session.note_use(observed("198.18.1.7", poznan()), at + Duration::days(7));

        assert_eq!(noted, UseNoted::Moved);
    }

    /// A network nobody can place tells nothing: never frozen, never
    /// overwriting where she was.
    #[test]
    fn an_address_that_cannot_be_placed_never_freezes_or_moves() {
        let (mut session, at) = used_in_berlin();

        let noted = session.note_use(
            observed("198.18.1.7", Fact::Unknown),
            at + Duration::minutes(1),
        );

        assert_eq!(noted, UseNoted::Unchanged);
        assert_eq!(
            session.last_use().known().unwrap().network(),
            &network("198.18.0.7")
        );
    }

    /// Pat has an authenticator app, so the session freezes and her code
    /// lifts it.
    #[test]
    fn a_session_whose_holder_has_a_factor_freezes() {
        let (mut session, _) = used_in_berlin();

        session
            .stop_taken_over(WayBack::OwnFactor, EventLabel::of("Pat"))
            .unwrap();

        assert_eq!(session.status(), SessionStatus::Suspended);
        assert_eq!(
            raised_names(&mut session),
            ["authentication.session_suspended"]
        );
    }

    /// Lou has only a password. A freeze nothing could lift would lock him
    /// out, so the session ends and he signs in again.
    #[test]
    fn a_session_whose_holder_has_no_factor_ends_instead() {
        let (mut session, _) = used_in_berlin();

        session
            .stop_taken_over(WayBack::FreshSignIn, EventLabel::of("Lou"))
            .unwrap();

        assert_eq!(session.status(), SessionStatus::Revoked);
        assert_eq!(
            raised_names(&mut session),
            ["authentication.session_revoked"]
        );
    }

    /// Pat lifts the freeze with her own code. Who proved themselves here
    /// decides where the session is, so the Poznań use that froze it is
    /// forgotten and her next use is not held against it.
    #[test]
    fn lifting_a_freeze_forgets_where_the_session_was() {
        let (mut session, _) = used_in_berlin();
        session
            .stop_taken_over(WayBack::OwnFactor, EventLabel::of("Pat"))
            .unwrap();
        let code = holders(&session, MfaFactor::Totp);

        session.resume(code, &StepUpPolicy::relaxed()).unwrap();

        assert!(session.last_use().known().is_none());
    }

    /// Pat refreshes in Berlin: the new session remembers where the old one
    /// was, so a stolen refresh token used from Poznań is still held against
    /// Berlin.
    #[test]
    fn a_refresh_keeps_where_the_session_was() {
        let (mut parent, _) = used_in_berlin();

        let child = rotated(&mut parent).unwrap();

        assert!(child.last_use().known().is_some());
    }

    /// A session already stopped cannot be stopped twice: it was recorded
    /// already.
    #[test]
    fn a_stopped_session_cannot_be_stopped_again() {
        let (mut session, _) = used_in_berlin();
        session
            .stop_taken_over(WayBack::OwnFactor, EventLabel::of("Pat"))
            .unwrap();

        let again = session.stop_taken_over(WayBack::OwnFactor, EventLabel::of("Pat"));

        assert!(again.is_err());
    }
}
