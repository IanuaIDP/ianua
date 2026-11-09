//! Who a human is across the accounts they hold.

use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{ActorRef, AgentId, ConsumerId, Email, OrgUserId, PrincipalRef, UserId};

text_value! {
    /// A human's identity across their accounts.
    ///
    /// It is the verified email address they sign in with, which a person's
    /// tenant account and organization account share. Rules that need two
    /// different people compare this, never the accounts. Ann with a tenant
    /// account and an organization account is still one person, and must not
    /// count as two approvers.
    ///
    /// Spellings that reach one mailbox are one person. Case is folded, and
    /// so is a `+tag` on the local part, so `alice+ops@corp.com` is
    /// `alice@corp.com`. A verified sub-address proves the same inbox. Gmail
    /// also ignores dots and answers to `googlemail.com`, so
    /// `A.Lice@googlemail.com` is `alice@gmail.com`. A tag is kept when
    /// dropping it would leave no address, as in `a.+x@corp.com`.
    pub struct PersonKey;
}

impl TextValue for PersonKey {
    const FIELD: &'static str = "person";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.email()
    }

    fn normalized(value: String) -> String {
        mailbox_of(&value)
    }
}

impl PersonKey {
    /// The person a verified email address belongs to.
    #[must_use]
    pub fn of(email: &Email) -> Self {
        Self(mailbox_of(email.as_str()))
    }
}

/// The mailbox an address reaches.
///
/// It is lowercased, any `+tag` is dropped from the local part, and Gmail's
/// dots and second domain are folded.
fn mailbox_of(address: &str) -> String {
    let lowered = address.to_ascii_lowercase();
    let Some((local, domain)) = lowered.rsplit_once('@') else {
        return lowered;
    };
    if matches!(domain, "gmail.com" | "googlemail.com") {
        return format!("{}@gmail.com", gmail_mailbox(local));
    }
    format!("{}@{domain}", without_tag(local))
}

/// `local` without its `+tag`, unless what is left is not a mailbox.
fn without_tag(local: &str) -> &str {
    match local.split_once('+') {
        Some((base, _)) if !base.is_empty() && !base.ends_with('.') => base,
        Some(_) | None => local,
    }
}

/// A Gmail local part as Gmail delivers it: no tag and no dots.
fn gmail_mailbox(local: &str) -> String {
    let base = local.split_once('+').map_or(local, |(base, _)| base);
    let folded: String = base.chars().filter(|c| *c != '.').collect();
    if folded.is_empty() {
        return without_tag(local).to_owned();
    }
    folded
}

/// An account a human signs in to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HumanAccount {
    /// A tenant user account.
    User(UserId),
    /// An organization account.
    OrgUser(OrgUserId),
}

impl From<HumanAccount> for PrincipalRef {
    fn from(account: HumanAccount) -> Self {
        match account {
            HumanAccount::User(id) => Self::User(id),
            HumanAccount::OrgUser(id) => Self::OrgUser(id),
        }
    }
}

/// The account as the actor an audit record names.
impl From<HumanAccount> for ActorRef {
    fn from(account: HumanAccount) -> Self {
        match account {
            HumanAccount::User(id) => Self::User(id),
            HumanAccount::OrgUser(id) => Self::OrgUser(id),
        }
    }
}

/// A human acting through one of their accounts.
///
/// It keeps the account for the record, and the person behind it, which is
/// what two-person rules compare. It holds only a human's account, so an
/// agent or a consumer can never stand where a human decision is required.
///
/// A record that keeps who did something keeps both, so a two-person rule
/// checked later still sees the person.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Human {
    account: HumanAccount,
    person: PersonKey,
}

impl Human {
    /// `person`, acting through `account`.
    #[must_use]
    pub fn new(account: HumanAccount, person: PersonKey) -> Self {
        Self { account, person }
    }

    /// The account they acted through.
    #[must_use]
    pub fn account(&self) -> HumanAccount {
        self.account
    }

    /// The account as a principal.
    #[must_use]
    pub fn principal(&self) -> PrincipalRef {
        self.account.into()
    }

    /// Who they are across their accounts.
    #[must_use]
    pub fn person(&self) -> &PersonKey {
        &self.person
    }

    /// Whether `other` is the same human, by the same account or the same
    /// person through any of their accounts. Every two-person check uses
    /// this rule.
    ///
    /// It leans towards "the same", which is safe only for refusing. Never
    /// grant on it. A person key is an address, and matching it would hand
    /// one account's rights to another that only shares the address. Grants
    /// compare accounts with [`is_same_account_as`](Self::is_same_account_as).
    #[must_use]
    pub fn is_same_person_as(&self, other: &Self) -> bool {
        self.account == other.account || self.person == other.person
    }

    /// Whether `other` acts through this very account.
    ///
    /// This is the rule for what someone owns, since rights belong to the
    /// account that holds them.
    #[must_use]
    pub fn is_same_account_as(&self, other: &Self) -> bool {
        self.account == other.account
    }
}

/// Who set something in motion: a human with the person behind them, or a
/// machine acting for itself.
///
/// A human always carries their person, so no record can name a human
/// initiator in a way that slips past the two-person rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Initiator {
    /// A human, through one of their accounts.
    Human(Human),
    /// A nonhuman identity acting under its own agent credentials.
    Agent(AgentId),
    /// A consumer outside the platform.
    Consumer(ConsumerId),
}

impl Initiator {
    /// The account or machine, as a principal.
    #[must_use]
    pub fn principal(&self) -> PrincipalRef {
        match self {
            Self::Human(human) => human.principal(),
            Self::Agent(id) => PrincipalRef::Agent(*id),
            Self::Consumer(id) => PrincipalRef::Consumer(*id),
        }
    }

    /// The human behind it, if a human started it.
    #[must_use]
    pub fn human(&self) -> Option<&Human> {
        match self {
            Self::Human(human) => Some(human),
            Self::Agent(_) | Self::Consumer(_) => None,
        }
    }

    /// Whether `by` is who started this, through any of their accounts.
    #[must_use]
    pub fn is(&self, by: &Human) -> bool {
        self.human()
            .is_some_and(|human| human.is_same_person_as(by))
    }

    /// Whether `self` and `other` are the same party. That is one person
    /// through any of their accounts, one agent, or one consumer.
    #[must_use]
    pub fn is_same_party_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Human(mine), Self::Human(theirs)) => mine.is_same_person_as(theirs),
            (Self::Agent(mine), Self::Agent(theirs)) => mine == theirs,
            (Self::Consumer(mine), Self::Consumer(theirs)) => mine == theirs,
            (Self::Human(_) | Self::Agent(_) | Self::Consumer(_), _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(address: &str) -> PersonKey {
        PersonKey::of(&Email::new(address).unwrap())
    }

    fn human(account: HumanAccount, address: &str) -> Human {
        Human::new(account, key(address))
    }

    /// Accounts that sign in as `Alice@Corp.com` and `alice@corp.com` belong
    /// to one person.
    #[test]
    fn one_address_is_one_person_whatever_its_case() {
        assert_eq!(key("Alice@Corp.com"), key("alice@corp.com"));
    }

    /// Tagged and mixed-case spellings of Alice's mailbox resolve to the same
    /// person key used by two-person checks.
    #[test]
    fn a_sub_address_is_the_same_person() {
        assert_eq!(key("alice+ops@corp.com"), key("alice@corp.com"));
        assert_eq!(key("Alice+Tenant+X@Corp.com"), key("alice@corp.com"));
    }

    /// `A.Lice+x@googlemail.com` and `a.l.i.c.e@gmail.com` both reach
    /// Alice's Gmail inbox, so they are one person. At other domains dots
    /// count, so `a.lice@corp.com` is someone else.
    #[test]
    fn gmail_spellings_of_one_inbox_are_one_person() {
        assert_eq!(key("A.Lice+x@googlemail.com"), key("alice@gmail.com"));
        assert_eq!(key("a.l.i.c.e@gmail.com"), key("alice@gmail.com"));
        assert_ne!(key("a.lice@corp.com"), key("alice@corp.com"));
    }

    /// For `a.+x@corp.com`, dropping the tag would leave no valid address.
    /// The tag is kept, so the stored key reads back as the same person.
    #[test]
    fn a_tag_that_is_the_whole_mailbox_is_kept_and_reads_back() {
        for address in ["a.+x@corp.com", "a.+ops+x@corp.com"] {
            let person = key(address);

            assert_eq!(PersonKey::new(person.as_str()).unwrap(), person);
        }
    }

    /// `alicia@corp.com` and `alice@other.com` are different people from
    /// `alice@corp.com`.
    #[test]
    fn different_mailboxes_are_different_people() {
        assert_ne!(key("alice@corp.com"), key("alicia@corp.com"));
        assert_ne!(key("alice@corp.com"), key("alice@other.com"));
    }

    /// A stored key `Alice+ops@corp.com` reads back folded, as
    /// `alice@corp.com`. A stored value that is not an address is refused.
    #[test]
    fn a_stored_person_is_folded_the_same_way() {
        assert_eq!(
            PersonKey::new("Alice+ops@corp.com").unwrap(),
            key("alice@corp.com")
        );
        assert!(PersonKey::new("not an address").is_err());
    }

    /// Alice's tenant account and organization account compare as one person
    /// even when the organization address has a mailbox tag.
    #[test]
    fn the_same_person_through_another_account_is_the_same_human() {
        let tenant = human(HumanAccount::User(UserId::new()), "alice@corp.com");
        let org = human(
            HumanAccount::OrgUser(OrgUserId::new()),
            "alice+org@corp.com",
        );

        assert!(tenant.is_same_person_as(&org));
    }

    /// Alice and Bob, each with their own address, are two humans.
    #[test]
    fn two_people_are_two_humans() {
        let alice = human(HumanAccount::User(UserId::new()), "alice@corp.com");
        let bob = human(HumanAccount::User(UserId::new()), "bob@corp.com");

        assert!(!alice.is_same_person_as(&bob));
    }

    /// Something started by an agent or a consumer was never started by
    /// Alice, so a machine cannot pass for her.
    #[test]
    fn a_machine_initiator_is_never_a_human() {
        let alice = human(HumanAccount::User(UserId::new()), "alice@corp.com");

        assert!(!Initiator::Agent(AgentId::new()).is(&alice));
        assert!(!Initiator::Consumer(ConsumerId::new()).is(&alice));
    }

    /// Alice starts a change with her tenant account and comes back through
    /// her organization account. She is still the one who started it.
    #[test]
    fn a_human_initiator_is_recognised_through_any_of_their_accounts() {
        let started = human(HumanAccount::User(UserId::new()), "alice@corp.com");
        let later = human(HumanAccount::OrgUser(OrgUserId::new()), "alice@corp.com");

        assert!(Initiator::Human(started).is(&later));
    }
}
