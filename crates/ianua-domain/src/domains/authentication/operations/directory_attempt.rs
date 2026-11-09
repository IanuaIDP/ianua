//! What a directory client's bind and search leave on the record.
//!
//! LDAP has no sessions, and neither a bind nor a search changes anything
//! the tenant keeps. Each is still recorded, a refused one too: guessing a
//! password with a bind, then exporting the directory with a search, is a
//! classic attack. Each attempt is a short-lived value that raises its
//! record once the outcome is known and is dropped once the record is
//! taken, stamped with the tenant the attempt was made in.

use std::marker::PhantomData;

use crate::domains::authentication::directory_service::account::DirectoryServiceAccount;
use crate::domains::authentication::directory_service::scope::ServiceAccountName;
use crate::domains::authentication::events::directory::{
    DirectoryBindSucceeded, DirectorySearchDenied, DirectorySearchPerformed,
};
use crate::domains::authentication::events::login::{
    AccountUnderAttack, LockedAddress, LoginFailed, LoginFailureReason,
};
use crate::domains::authentication::events::service_account::{
    DirectoryServiceBound, DirectoryServiceSearchDenied, DirectoryServiceSearchPerformed,
};
use crate::domains::authentication::risk_engine::attack::AttackBegun;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{
    DirectoryServiceAccountId, Email, EventLabel, Fact, IpAddress, UntrustedText, UserId,
};

/// One LDAP simple bind, from the address it named and the client it came
/// from, until it is refused or binds.
#[derive(Debug)]
pub struct DirectoryBindAttempt<T: TenantScope> {
    email: UntrustedText,
    ip_address: Fact<IpAddress>,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> DirectoryBindAttempt<T> {
    /// A bind naming `email`, made from `ip_address`. It has raised nothing
    /// yet.
    #[must_use]
    pub fn new(email: &Email, ip_address: Fact<IpAddress>) -> Self {
        Self {
            email: UntrustedText::record(email.as_str()),
            ip_address,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// A bind naming the service account `name`, made from `ip_address`. A
    /// refusal records the name where a person's bind records the address.
    /// It has raised nothing yet.
    #[must_use]
    pub fn naming_service(name: &ServiceAccountName, ip_address: Fact<IpAddress>) -> Self {
        Self {
            email: UntrustedText::record(name.as_str()),
            ip_address,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// The bind proved the service account `account`. Raises
    /// `authentication.directory_service_bound`, naming the account.
    pub fn record_service_bind(&mut self, account: &DirectoryServiceAccount<T>) {
        self.raised.raise(DirectoryServiceBound {
            account_id: *account.id(),
            name: EventLabel::of(account.name().as_str()),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// The bind was refused for `reason`. Raises
    /// `authentication.login_failed` with the address it named and where it
    /// came from.
    pub fn record_refusal(&mut self, reason: LoginFailureReason) {
        self.raised.raise(LoginFailed {
            email: self.email.clone(),
            reason,
            ip_address: self.ip_address.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// The bind found `begun`, an attack on `account`. Raises
    /// `authentication.account_under_attack`, naming the account and how
    /// many networks failed on it, never which.
    pub fn record_attack(&mut self, account: &User<T>, begun: AttackBegun) {
        self.raised.raise(AccountUnderAttack {
            user_id: LockedAddress::Account(*account.id()),
            user_label: EventLabel::of(account.email().as_str()),
            networks: begun.networks().get(),
            until: begun.until(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// The bind proved `account`. Raises
    /// `authentication.directory_bind_succeeded`, naming the account by the
    /// address it holds.
    pub fn record_user_bind(&mut self, account: &User<T>) {
        self.raised.raise(DirectoryBindSucceeded {
            user_id: *account.id(),
            user_label: EventLabel::of(account.email().as_str()),
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for DirectoryBindAttempt<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// One LDAP search by a bound person, until it is denied or returns what it
/// read.
#[derive(Debug)]
pub struct DirectorySearchAttempt<T: TenantScope> {
    user_id: UserId,
    user_label: EventLabel,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> DirectorySearchAttempt<T> {
    /// A search by the person bound as `user_id`, named in the record as
    /// `user_label`, the address they bound with. It has raised nothing
    /// yet.
    #[must_use]
    pub fn new(user_id: UserId, user_label: EventLabel) -> Self {
        Self {
            user_id,
            user_label,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// The search was refused. Raises `authentication.directory_search_denied`.
    pub fn record_denial(&mut self) {
        self.raised.raise(DirectorySearchDenied {
            user_id: self.user_id,
            user_label: self.user_label.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// The search returned `users_returned` user entries and
    /// `groups_returned` group entries. Raises
    /// `authentication.directory_search_performed` with both counts, not
    /// the entries, so the record tracks who read personal data without
    /// copying it. A count too large to record is kept at the largest one.
    pub fn record_search(&mut self, users_returned: usize, groups_returned: usize) {
        self.raised.raise(DirectorySearchPerformed {
            user_id: self.user_id,
            user_label: self.user_label.clone(),
            users_returned: recorded_count(users_returned),
            groups_returned: recorded_count(groups_returned),
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for DirectorySearchAttempt<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// One LDAP search by an application bound as a service account, until it
/// is denied or returns what it read.
#[derive(Debug)]
pub struct ServiceSearchAttempt<T: TenantScope> {
    account_id: DirectoryServiceAccountId,
    name: EventLabel,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ServiceSearchAttempt<T> {
    /// A search by the application bound as `account`, read again for it.
    /// It has raised nothing yet.
    #[must_use]
    pub fn by(account: &DirectoryServiceAccount<T>) -> Self {
        Self {
            account_id: *account.id(),
            name: EventLabel::of(account.name().as_str()),
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// The search was refused. Raises
    /// `authentication.directory_service_search_denied`.
    pub fn record_denial(&mut self) {
        self.raised.raise(DirectoryServiceSearchDenied {
            account_id: self.account_id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// The search returned `users_returned` user entries and
    /// `groups_returned` group entries. Raises
    /// `authentication.directory_service_search_performed` with both counts,
    /// not the entries. A count too large to record is kept at the largest
    /// one.
    pub fn record_search(&mut self, users_returned: usize, groups_returned: usize) {
        self.raised.raise(DirectoryServiceSearchPerformed {
            account_id: self.account_id,
            name: self.name.clone(),
            users_returned: recorded_count(users_returned),
            groups_returned: recorded_count(groups_returned),
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for ServiceSearchAttempt<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// `count` as the record keeps it, at most `u32::MAX`.
fn recorded_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::CredentialChange;

    fn bind_by_ann() -> DirectoryBindAttempt<ResolvedTenant> {
        DirectoryBindAttempt::new(
            &Email::new("ann@acme.com").unwrap(),
            Fact::Known(IpAddress::new("10.0.0.1").unwrap()),
        )
    }

    fn search_by_ann() -> DirectorySearchAttempt<ResolvedTenant> {
        DirectorySearchAttempt::new(UserId::new(), EventLabel::of("ann@acme.com"))
    }

    /// A bind is begun. Until its outcome is known it has raised nothing.
    #[test]
    fn a_bind_begun_has_raised_nothing() {
        let mut attempt = bind_by_ann();

        assert!(raised_names(&mut attempt).is_empty());
    }

    /// Recording a password-bind refusal raises a login failure with the
    /// attempted email address, reason, and source IP.
    #[test]
    fn a_refused_bind_raises_login_failed() {
        let mut attempt = bind_by_ann();

        attempt.record_refusal(LoginFailureReason::BadPassword);

        let events = raised(&mut attempt);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.login_failed"
        );
        let payload = events[0].payload();
        assert_eq!(payload.get("email"), Some("ann@acme.com"));
        assert_eq!(payload.get("reason"), Some("bad_password"));
        assert_eq!(payload.get("ip_address"), Some("10.0.0.1"));
    }

    /// Ann binds with her password and her laptop's certificate. It raises
    /// `authentication.directory_bind_succeeded`, naming her account.
    #[test]
    fn a_bind_that_proves_the_account_raises_the_bind() {
        let ann = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);
        let mut attempt = DirectoryBindAttempt::<ResolvedTenant>::new(ann.email(), Fact::Unknown);

        attempt.record_user_bind(&ann);

        assert_eq!(
            raised_names(&mut attempt),
            ["authentication.directory_bind_succeeded"]
        );
    }

    /// Ann's search returns three users and one group. It raises
    /// `authentication.directory_search_performed` with the counts.
    #[test]
    fn a_search_raises_what_it_returned() {
        let mut attempt = search_by_ann();

        attempt.record_search(3, 1);

        let events = raised(&mut attempt);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.directory_search_performed"
        );
        assert_eq!(events[0].payload().get("users_returned"), Some("3"));
        assert_eq!(events[0].payload().get("groups_returned"), Some("1"));
    }

    /// Recording a refused search raises the directory-search denial event.
    #[test]
    fn a_denied_search_raises_the_denial() {
        let mut attempt = search_by_ann();

        attempt.record_denial();

        assert_eq!(
            raised_names(&mut attempt),
            ["authentication.directory_search_denied"]
        );
    }

    /// Jira binds as its service account. It raises
    /// `authentication.directory_service_bound`, naming the account.
    #[test]
    fn a_service_bind_raises_the_bind_naming_the_account() {
        let jira = crate::domains::authentication::directory_service::account::tests::jira();
        let mut attempt =
            DirectoryBindAttempt::<ResolvedTenant>::naming_service(jira.name(), Fact::Unknown);

        attempt.record_service_bind(&jira);

        let events = raised(&mut attempt);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.directory_service_bound"
        );
        assert_eq!(
            events[0].payload().get("service_account"),
            Some(jira.id().to_string().as_str())
        );
    }

    /// A recorded service-bind refusal names Jira's service account.
    #[test]
    fn a_refused_service_bind_names_the_account() {
        let jira = crate::domains::authentication::directory_service::account::tests::jira();
        let mut attempt =
            DirectoryBindAttempt::<ResolvedTenant>::naming_service(jira.name(), Fact::Unknown);

        attempt.record_refusal(LoginFailureReason::BadPassword);

        assert_eq!(raised(&mut attempt)[0].payload().get("email"), Some("jira"));
    }

    /// Jira's connection reads the directory. The search is recorded naming
    /// Jira's account, with how many entries it read and none of them.
    #[test]
    fn a_service_search_is_recorded_with_its_counts() {
        let jira = crate::domains::authentication::directory_service::account::tests::jira();
        let mut attempt = ServiceSearchAttempt::by(&jira);

        attempt.record_search(12, 3);

        let events = raised(&mut attempt);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.directory_service_search_performed"
        );
        assert_eq!(events[0].payload().get("users_returned"), Some("12"));
        assert_eq!(events[0].payload().get("groups_returned"), Some("3"));
    }

    /// Recording a refused service-account search raises a directory-search denial.
    #[test]
    fn a_refused_service_search_is_recorded() {
        let jira = crate::domains::authentication::directory_service::account::tests::jira();
        let mut attempt = ServiceSearchAttempt::by(&jira);

        attempt.record_denial();

        assert_eq!(
            raised_names(&mut attempt),
            ["authentication.directory_service_search_denied"]
        );
    }

    /// A count past what the record holds is kept at the largest it holds.
    #[test]
    fn a_count_too_large_is_kept_at_the_largest() {
        assert_eq!(recorded_count(usize::MAX), u32::MAX);
    }
}
