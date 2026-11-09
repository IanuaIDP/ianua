//! Whether an account is under attack, and what a password sign-in to it
//! must prove while it is.
//!
//! The lockout stops one network guessing at one account, and the account's
//! pace slows guesses spread over many. Neither caps a botnet: each of its
//! networks stays under its own lockout, and the pace never grows into a
//! lock, which would keep the owner out too. So once failures against one
//! account come from many networks within the lockout's window, the account
//! counts as under attack for a while. Meanwhile a right password from a
//! device the account does not know proves nothing by itself: it is a risk
//! signal, answered the way [`FactorOwed::under`] answers every other one,
//! with the person's second factor, a link mailed to their address, or a
//! refusal when they have neither. A guessed password alone gains a botnet
//! nothing, and the owner gets in with her phone or her mail. A device the
//! person trusted is never asked for more.
//!
//! A directory bind has no second step to ask for. While the account is
//! under attack, a bind from a network that has failed on it is refused,
//! and one from a network that has not still binds.
//!
//! [`FactorOwed::under`]: crate::domains::authentication::mfa::owed::FactorOwed::under

use time::OffsetDateTime;

use crate::domains::authentication::mfa::owed::Demand;
use crate::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
use crate::domains::authentication::risk_engine::step_up::Familiarity;
use crate::types::Lifetime;

/// How many networks must fail on one account within the window, for each
/// failure one network may make before it is locked out, for the account to
/// count as under attack.
///
/// The owner mistyping from her phone, her laptop at home and the office
/// fails from a few networks at most. A botnet keeping every network under
/// its lockout has to spread its guesses over many. Twice the limit leaves
/// the owner far below it, and ties it to the limit, so a tenant that locks
/// a network out sooner also calls an attack sooner: ten networks under the
/// default limit of five, six under the strict limit of three.
pub(crate) const NETWORKS_PER_ALLOWED_FAILURE: u64 = 2;

/// How many of the lockout's windows an account stays under attack once it
/// is.
///
/// The count of failing networks starts again with every window. Held for
/// one window only, a botnet pausing for a window would find the account
/// quiet each time it came back. Held for four, pausing buys it nothing,
/// while the owner on a trusted device never notices, and on a new device
/// proves herself once more: for an hour under the default window of
/// fifteen minutes.
pub(crate) const WINDOWS_UNDER_ATTACK: i32 = 4;

/// How many networks failed on an account within the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailingNetworks(u64);

impl FailingNetworks {
    /// The count.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for FailingNetworks {
    fn from(networks: u64) -> Self {
        Self(networks)
    }
}

/// Whether an account was marked under attack, and the mark has not
/// lapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMark {
    /// No mark: the account is quiet unless its counts say otherwise.
    Unmarked,
    /// Marked, until the mark lapses.
    Marked,
}

/// What the counts kept on an account say about an attack on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackSigns {
    networks: FailingNetworks,
    mark: AttackMark,
}

impl AttackSigns {
    /// `networks` failed on the account in the window, and its mark stands
    /// as `mark` says.
    #[must_use]
    pub fn new(networks: FailingNetworks, mark: AttackMark) -> Self {
        Self { networks, mark }
    }
}

/// An attack the counts just showed on an account that was not marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackBegun {
    networks: FailingNetworks,
    until: OffsetDateTime,
}

impl AttackBegun {
    /// How many networks had failed on the account when it was found.
    #[must_use]
    pub fn networks(self) -> FailingNetworks {
        self.networks
    }

    /// Until when the account counts as under attack.
    #[must_use]
    pub fn until(self) -> OffsetDateTime {
        self.until
    }
}

/// Whether an account is under attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAttack {
    /// Not under attack.
    Quiet,
    /// The counts show an attack the account was not yet marked for. The
    /// caller marks it, for [`attack_held_for`], and records it once.
    Begun(AttackBegun),
    /// Marked under attack earlier, and still.
    Ongoing,
}

impl AccountAttack {
    /// Whether an account with `signs` is under attack at `now`, under the
    /// lockout `policy`.
    ///
    /// A mark that stands says so, whatever the counts. Without one, the
    /// account is under attack once `attacking_networks` networks failed
    /// on it within the window.
    #[must_use]
    pub fn of(signs: AttackSigns, policy: &RateLimitPolicy, now: OffsetDateTime) -> Self {
        let reached = signs.networks >= attacking_networks(policy);
        match (signs.mark, reached) {
            (AttackMark::Marked, true | false) => Self::Ongoing,
            (AttackMark::Unmarked, false) => Self::Quiet,
            (AttackMark::Unmarked, true) => Self::Begun(AttackBegun {
                networks: signs.networks,
                until: attack_held_for(policy).ends_after(now),
            }),
        }
    }

    /// Whether the account is under attack.
    #[must_use]
    pub fn is_under_attack(self) -> bool {
        !matches!(self, Self::Quiet)
    }

    /// The attack the counts just showed, when this sign-in found it.
    #[must_use]
    pub fn begun(self) -> Option<AttackBegun> {
        let Self::Begun(begun) = self else {
            return None;
        };
        Some(begun)
    }

    /// What a password sign-in from `device` is asked, where the tenant's
    /// or organization's rules alone ask `demand`.
    ///
    /// Under attack, a device the person did not trust adds a risk signal,
    /// so a right password alone does not finish the sign-in. A trusted
    /// device is asked no more than it would be anyway.
    #[must_use]
    pub fn demand(self, demand: Demand, device: Familiarity) -> Demand {
        match (self, device) {
            (Self::Quiet, Familiarity::Known | Familiarity::New)
            | (Self::Begun(_) | Self::Ongoing, Familiarity::Known) => demand,
            (Self::Begun(_) | Self::Ongoing, Familiarity::New) => demand.with_signal(),
        }
    }

    /// Whether a directory bind from a network standing at `origin` may go
    /// on to its password. While the account is under attack, a network
    /// that failed on it is refused.
    #[must_use]
    pub fn admits_bind(self, origin: OriginRecord) -> bool {
        match (self, origin) {
            (Self::Quiet, OriginRecord::Clean | OriginRecord::Failed)
            | (Self::Begun(_) | Self::Ongoing, OriginRecord::Clean) => true,
            (Self::Begun(_) | Self::Ongoing, OriginRecord::Failed) => false,
        }
    }
}

/// Whether a network failed on an account within the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRecord {
    /// No failure from it is counted.
    Clean,
    /// At least one is.
    Failed,
}

impl OriginRecord {
    /// The record of a network with `failures` counted on the account.
    #[must_use]
    pub fn of(failures: u32) -> Self {
        match failures {
            0 => Self::Clean,
            _ => Self::Failed,
        }
    }
}

/// How many networks must fail on one account within the window, under the
/// lockout `policy`, for it to count as under attack. See
/// `NETWORKS_PER_ALLOWED_FAILURE`.
#[must_use]
pub(crate) fn attacking_networks(policy: &RateLimitPolicy) -> FailingNetworks {
    let limit = u64::from(policy.max_failed_attempts());
    FailingNetworks(limit.saturating_mul(NETWORKS_PER_ALLOWED_FAILURE))
}

/// How long an account stays under attack once it is, under the lockout
/// `policy`. See `WINDOWS_UNDER_ATTACK`.
#[must_use]
pub fn attack_held_for(policy: &RateLimitPolicy) -> Lifetime {
    let held = policy
        .window()
        .duration()
        .saturating_mul(WINDOWS_UNDER_ATTACK);
    Lifetime::new(held).unwrap_or(Lifetime::MAX)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use proptest::prelude::*;
    use proptest::sample::select;
    use time::Duration;

    use super::*;
    use crate::domains::authentication::methods::MfaPolicy;
    use crate::domains::authentication::mfa::owed::{Enrolment, FactorOwed};
    use crate::domains::identity::account::address::MailReach;
    use crate::domains::identity::account::vouching::Vouching;
    use crate::types::PersonProof;

    const DEMANDS: [Demand; 5] = [
        Demand::Policy,
        Demand::Signal,
        Demand::SignalAndPolicy,
        Demand::OwnFactor,
        Demand::NotAsked,
    ];

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn signs(networks: u64, mark: AttackMark) -> AttackSigns {
        AttackSigns::new(FailingNetworks::from(networks), mark)
    }

    fn limit(attempts: u32) -> RateLimitPolicy {
        RateLimitPolicy::new(
            NonZeroU32::new(attempts).unwrap(),
            RateLimitPolicy::DEFAULT.lockout(),
            RateLimitPolicy::DEFAULT.window(),
        )
    }

    /// Under the default limit of five failures a network, ten networks
    /// make an attack; under the strict limit of three, six do.
    #[test]
    fn many_is_twice_the_limit() {
        assert_eq!(attacking_networks(&RateLimitPolicy::DEFAULT).get(), 10);
        assert_eq!(attacking_networks(&RateLimitPolicy::STRICT).get(), 6);
    }

    /// Under the default window of fifteen minutes an attack is held for an
    /// hour; under the strict window of five, for twenty minutes.
    #[test]
    fn a_while_is_four_windows() {
        assert_eq!(
            attack_held_for(&RateLimitPolicy::DEFAULT).duration(),
            Duration::HOUR
        );
        assert_eq!(
            attack_held_for(&RateLimitPolicy::STRICT).duration(),
            Duration::minutes(20)
        );
    }

    /// A botnet's failures reach the tenth network on Ann's account. The
    /// attack begins now and holds for an hour, naming the ten networks.
    #[test]
    fn the_tenth_network_begins_an_attack() {
        let t = now();

        let attack = AccountAttack::of(
            signs(10, AttackMark::Unmarked),
            &RateLimitPolicy::DEFAULT,
            t,
        );

        let begun = attack.begun().unwrap();
        assert_eq!(begun.networks().get(), 10);
        assert_eq!(begun.until(), t + Duration::HOUR);
        assert!(attack.is_under_attack());
    }

    /// Ann mistypes from three networks. Her account stays quiet.
    #[test]
    fn a_few_networks_leave_the_account_quiet() {
        let attack = AccountAttack::of(
            signs(3, AttackMark::Unmarked),
            &RateLimitPolicy::DEFAULT,
            now(),
        );

        assert_eq!(attack, AccountAttack::Quiet);
    }

    /// The window's count of networks lapsed, but the account was marked
    /// under attack within the hour. It still is, and nothing is begun
    /// again.
    #[test]
    fn a_mark_holds_after_the_counts_lapse() {
        let attack = AccountAttack::of(
            signs(0, AttackMark::Marked),
            &RateLimitPolicy::DEFAULT,
            now(),
        );

        assert_eq!(attack, AccountAttack::Ongoing);
        assert_eq!(attack.begun(), None);
    }

    /// An account under attack requires its enrolled factor on a new device.
    #[test]
    fn a_right_guess_under_attack_owes_the_factor() {
        let demand = AccountAttack::Ongoing.demand(Demand::NotAsked, Familiarity::New);

        let owed = FactorOwed::under(
            MfaPolicy::Optional,
            demand,
            Enrolment::Enrolled,
            MailReach::Available,
            Vouching::Absent,
        );

        assert_eq!(owed, FactorOwed::Verify);
    }

    /// An account under attack without a factor requires email confirmation;
    /// the sign-in is refused when mail is unavailable.
    #[test]
    fn a_right_guess_without_a_factor_owes_the_mail_or_is_refused() {
        let demand = AccountAttack::Ongoing.demand(Demand::NotAsked, Familiarity::New);
        let owed = |mail| {
            FactorOwed::under(
                MfaPolicy::Optional,
                demand,
                Enrolment::NotEnrolled,
                mail,
                Vouching::Absent,
            )
        };

        assert_eq!(owed(MailReach::Available), FactorOwed::ConfirmByEmail);
        assert_eq!(owed(MailReach::NotSetUp), FactorOwed::Refused);
    }

    /// During an attack, a failed origin is denied while a clean origin is
    /// admitted; a quiet account also admits an origin with recorded failures.
    #[test]
    fn under_attack_a_failed_network_binds_nothing() {
        assert!(!AccountAttack::Ongoing.admits_bind(OriginRecord::of(1)));
        assert!(AccountAttack::Ongoing.admits_bind(OriginRecord::of(0)));
        assert!(AccountAttack::Quiet.admits_bind(OriginRecord::of(4)));
    }

    proptest! {
        /// Whatever the limit, and however often one network fails, a
        /// single network never puts the account under attack.
        #[test]
        fn one_network_never_begins_an_attack(attempts in 1u32..1_000, networks in 0u64..=1) {
            let attack = AccountAttack::of(
                signs(networks, AttackMark::Unmarked),
                &limit(attempts),
                now(),
            );

            prop_assert_eq!(attack, AccountAttack::Quiet);
        }

        /// Whatever the limit, failures from at least twice as many
        /// networks begin an attack, and fewer do not.
        #[test]
        fn many_networks_begin_an_attack(attempts in 1u32..1_000, networks in 0u64..5_000) {
            let policy = limit(attempts);

            let attack = AccountAttack::of(signs(networks, AttackMark::Unmarked), &policy, now());

            let many = u64::from(attempts).saturating_mul(NETWORKS_PER_ALLOWED_FAILURE);
            prop_assert_eq!(attack.is_under_attack(), networks >= many);
        }

        /// Whatever the attack and whatever the rules ask, a device the
        /// person trusted is asked no more.
        #[test]
        fn a_trusted_device_is_never_asked_for_more(
            demand in select(DEMANDS.to_vec()),
            networks in 0u64..100,
            mark in select(vec![AttackMark::Marked, AttackMark::Unmarked]),
        ) {
            let attack = AccountAttack::of(signs(networks, mark), &RateLimitPolicy::DEFAULT, now());

            prop_assert_eq!(attack.demand(demand, Familiarity::Known), demand);
        }

        /// Under attack, whatever the rules, the factors held and the mail,
        /// a right password from a new device that nothing vouches for
        /// never finishes on the password alone, and never asks less than
        /// it would have in quiet times.
        #[test]
        fn under_attack_a_new_device_proves_more_than_the_password(
            policy in select(vec![MfaPolicy::Disabled, MfaPolicy::Optional, MfaPolicy::Required]),
            demand in select(DEMANDS.to_vec()),
            enrolment in select(vec![Enrolment::Enrolled, Enrolment::NotEnrolled]),
            mail in select(vec![MailReach::Available, MailReach::NotSetUp]),
        ) {
            let owed = |asked| FactorOwed::under(policy, asked, enrolment, mail, Vouching::Absent);
            let quiet = owed(AccountAttack::Quiet.demand(demand, Familiarity::New));
            let attacked = owed(AccountAttack::Ongoing.demand(demand, Familiarity::New));

            prop_assert_ne!(attacked.proof(), PersonProof::Nothing);
            prop_assert!(attacked.proof() >= quiet.proof());
        }
    }
}
