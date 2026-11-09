//! Whose sign-ins a log is narrowed to, worked out from the trail itself:
//! the person's account, and every address it held and when, read from
//! the records of its address changing.
//!
//! A failed sign-in names only the address typed. An address the account
//! gave up may later be someone else's, so an attempt counts as the
//! person's only when it was typed while their account held the address.
//! The person-facing list of sign-ins and the person's data export narrow
//! the log the same way, through [`sign_ins_of`].

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::FieldValue;
use ianua_domain::types::{Email, UserId};
use time::OffsetDateTime;

use crate::listing::{Limit, PageRequest, Sort, SortOrder};
use crate::ports::audit::{
    AuditLogEntry, AuditLogFilter, AuditLogSortField, HeldAddress, NamedInRecord, SignInsOf,
    TenantAuditLogStore,
};
use crate::tenancy::ScopedTenant;

/// The event type the trail records an address change under.
const ADDRESS_CHANGED: &str = "identity.email_changed";

/// How many address changes one page reads.
const CHANGES_PAGE: u32 = 100;

/// The most pages of address changes read. An account changes its address
/// a handful of times; past this the oldest are left out, which narrows
/// the attempts counted as the person's and never widens them.
const MOST_PAGES: usize = 10;

/// One change of an account's address, as the trail recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressChange {
    /// The address before.
    pub from: Email,
    /// The address after.
    pub to: Email,
    /// When it changed.
    pub at: OffsetDateTime,
}

/// The sign-ins of `user`, whose account holds `current` now, in
/// `tenant`'s trail.
///
/// # Errors
///
/// Returns [`DomainError`] when the trail cannot be read.
pub async fn sign_ins_of(
    audit_log: &dyn TenantAuditLogStore,
    tenant: &ScopedTenant,
    user: &UserId,
    current: &Email,
) -> Result<SignInsOf, DomainError> {
    let changes = address_changes(audit_log, tenant, user).await?;
    Ok(SignInsOf {
        user: *user,
        addresses: held_addresses(current, &changes),
    })
}

/// Every recorded change of `user`'s address, oldest first.
async fn address_changes(
    audit_log: &dyn TenantAuditLogStore,
    tenant: &ScopedTenant,
    user: &UserId,
) -> Result<Vec<AddressChange>, DomainError> {
    let filter = AuditLogFilter {
        event_type: Some(ADDRESS_CHANGED.to_owned()),
        names: Some(NamedInRecord::Account(*user)),
        ..AuditLogFilter::default()
    };
    let order = SortOrder::single(Sort::ascending(AuditLogSortField::OccurredAt));
    let mut page = PageRequest::first(Limit::internal(CHANGES_PAGE));
    let mut changes = Vec::new();
    for _ in 0..MOST_PAGES {
        let read = audit_log.query(tenant, &filter, &order, &page).await?;
        changes.extend(read.items.iter().filter_map(address_change));
        let Some(next) = read.next else {
            break;
        };
        page = PageRequest::new(Some(next), Limit::internal(CHANGES_PAGE));
    }
    Ok(changes)
}

/// The change `entry` records, when its details read as one.
fn address_change(entry: &AuditLogEntry) -> Option<AddressChange> {
    let Some(FieldValue::Change(change)) = entry.payload.value("email") else {
        return None;
    };
    Some(AddressChange {
        from: Email::new(change.from()?).ok()?,
        to: Email::new(change.to()?).ok()?,
        at: entry.occurred_at,
    })
}

/// The addresses an account holding `current` held, each with when, from
/// its address `changes` oldest first.
///
/// The first address was held from before anything recorded until the
/// first change; each new one from its change until the next. When the
/// last recorded change does not end at `current`, the trail lost a
/// change, and `current` is counted only from the last change on.
#[must_use]
pub(crate) fn held_addresses(current: &Email, changes: &[AddressChange]) -> Vec<HeldAddress> {
    let Some(first) = changes.first() else {
        return vec![HeldAddress {
            address: current.clone(),
            since: None,
            until: None,
        }];
    };
    let mut held = vec![HeldAddress {
        address: first.from.clone(),
        since: None,
        until: Some(first.at),
    }];
    held.extend(changes.iter().enumerate().map(|(at, change)| HeldAddress {
        address: change.to.clone(),
        since: Some(change.at),
        until: changes.get(at.saturating_add(1)).map(|next| next.at),
    }));
    let ends_at_current = changes.last().is_some_and(|last| last.to == *current);
    if !ends_at_current {
        held.push(HeldAddress {
            address: current.clone(),
            since: changes.last().map(|last| last.at),
            until: None,
        });
    }
    held
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn email(address: &str) -> Email {
        Email::new(address).unwrap()
    }

    fn moment(minutes: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::minutes(minutes)
    }

    fn change(from: &str, to: &str, minutes: i64) -> AddressChange {
        AddressChange {
            from: email(from),
            to: email(to),
            at: moment(minutes),
        }
    }

    /// An account that never changed its address held it all along.
    #[test]
    fn an_unchanged_address_is_held_all_along() {
        let held = held_addresses(&email("ann@acme.test"), &[]);

        assert_eq!(
            held,
            [HeldAddress {
                address: email("ann@acme.test"),
                since: None,
                until: None,
            }]
        );
    }

    /// Ann's address history bounds each address by the changes that began
    /// and ended her ownership, leaving only her current address open-ended.
    #[test]
    fn each_address_is_held_only_between_its_changes() {
        let held = held_addresses(
            &email("ann@new.test"),
            &[
                change("ann@old.test", "ann@mid.test", 10),
                change("ann@mid.test", "ann@new.test", 20),
            ],
        );

        let windows: Vec<(&str, Option<OffsetDateTime>, Option<OffsetDateTime>)> = held
            .iter()
            .map(|one| (one.address.as_str(), one.since, one.until))
            .collect();
        assert_eq!(
            windows,
            [
                ("ann@old.test", None, Some(moment(10))),
                ("ann@mid.test", Some(moment(10)), Some(moment(20))),
                ("ann@new.test", Some(moment(20)), None),
            ]
        );
    }

    /// When the trail does not reach Ann's current address, that address is
    /// counted only from the last recorded change onward.
    #[test]
    fn a_lost_change_counts_the_current_address_from_the_last_one() {
        let held = held_addresses(
            &email("ann@now.test"),
            &[change("ann@old.test", "ann@mid.test", 10)],
        );

        let last = held.last().unwrap();
        assert_eq!(last.address, email("ann@now.test"));
        assert_eq!(last.since, Some(moment(10)));
        assert_eq!(last.until, None);
    }
}
