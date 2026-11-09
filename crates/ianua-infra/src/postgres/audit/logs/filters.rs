//! How a filter of an audit log, the list's or an export's, narrows the
//! tables the records are kept in.
//!
//! Both tables name their columns alike, so one set of conditions serves
//! a tenant's records and the platform's. Each condition is a fixed piece
//! of SQL with one value bound. Which tenant's records are read is not a
//! condition here: it chooses the sources a log is read from.

use ianua_app::ports::audit::{AuditLogFilter, HeldAddress, NamedInRecord, SignInsOf};
use ianua_domain::domains::audit::export::filter::AuditExportFilter;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::audit::actors::actor_parts;
use crate::postgres::foundation::paging::PageQuery;
use crate::postgres::foundation::paging::picks::Picks;

/// What a log is narrowed to, whichever filter said it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Narrowing {
    event_prefix: Option<String>,
    after: Option<OffsetDateTime>,
    before: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    actor: Option<(&'static str, Option<Uuid>)>,
    tenant: Option<Uuid>,
    target: Option<String>,
    ip_address: Option<String>,
    names: Option<NamedInRecord>,
    sign_ins: Option<Picks>,
    acting_as: Option<Uuid>,
}

impl Narrowing {
    /// What the list's `filter` narrows to.
    pub(crate) fn of_log(filter: &AuditLogFilter) -> Self {
        Self {
            event_prefix: filter.event_type.clone(),
            after: filter.after,
            before: filter.before,
            until: None,
            actor: filter.actor.as_ref().map(actor_parts),
            tenant: filter.tenant_id.map(|tenant| *tenant.as_uuid()),
            target: filter.target.clone(),
            ip_address: filter.ip_address.as_ref().map(|ip| ip.as_str().to_owned()),
            names: filter.names.clone(),
            sign_ins: filter.sign_ins_of.as_ref().map(sign_ins_picks),
            acting_as: filter.acting_as.map(|user| *user.as_uuid()),
        }
    }

    /// What an export's `filter` narrows to, never past `until`.
    pub(crate) fn of_export(filter: &AuditExportFilter, until: OffsetDateTime) -> Self {
        let parts = filter.parts();
        Self {
            event_prefix: parts
                .event_type
                .as_ref()
                .map(|prefix| prefix.as_str().to_owned()),
            after: parts.after,
            before: parts.before,
            until: Some(until),
            actor: parts.actor.as_ref().map(actor_parts),
            tenant: parts.tenant_id.map(|tenant| *tenant.as_uuid()),
            target: parts
                .target
                .as_ref()
                .map(|target| target.as_str().to_owned()),
            ip_address: parts.ip_address.as_ref().map(|ip| ip.as_str().to_owned()),
            names: None,
            sign_ins: None,
            acting_as: None,
        }
    }

    /// The same narrowing with no tenant named, for a tenant's own log,
    /// which is always its own whatever the filter says.
    pub(crate) fn without_tenant(self) -> Self {
        Self {
            tenant: None,
            ..self
        }
    }

    /// The one tenant the filter keeps, if it names one.
    pub(crate) fn tenant(&self) -> Option<Uuid> {
        self.tenant
    }

    /// `query` narrowed to the records this keeps, the tenant aside.
    pub(crate) fn applied<Read>(
        &self,
        query: PageQuery<'static, Read>,
    ) -> PageQuery<'static, Read> {
        let mut query = query;
        if let Some(prefix) = &self.event_prefix {
            query = query.filter("event_type LIKE ?", prefix_pattern(prefix));
        }
        if let Some(after) = self.after {
            query = query.filter("occurred_at > ?", after);
        }
        if let Some(before) = self.before {
            query = query.filter("occurred_at < ?", before);
        }
        if let Some(until) = self.until {
            query = query.filter("occurred_at <= ?", until);
        }
        query = by_actor(query, self.actor);
        if let Some(target) = &self.target {
            query = query.filter("target_id = ?", target.clone());
        }
        if let Some(ip) = &self.ip_address {
            query = query.filter("ip_address = ?", ip.clone());
        }
        query = by_named(query, self.names.as_ref());
        if let Some(user) = self.acting_as {
            query = query.filter("as_user_id = ?", user);
        }
        match &self.sign_ins {
            Some(picks) => query.picking(picks),
            None => query,
        }
    }
}

/// The records of a person's sign-ins `of` names, as one tree of
/// conditions: those they made, the lockouts of their account, and the
/// failed attempts nobody signed in to make, typed with an address while
/// their account held it.
fn sign_ins_picks(of: &SignInsOf) -> Picks {
    let made = Picks::Holds(
        "actor_kind = 'tenant_user' AND event_type LIKE 'authentication.login%' \
         AND actor_id = ?::uuid",
        of.user.to_string(),
    );
    let locked = Picks::Holds(
        "event_type = 'authentication.account_locked_out' \
         AND payload -> 'value' -> 'user' ->> 'id' = ?",
        of.user.to_string(),
    );
    of.addresses
        .iter()
        .map(attempts_at)
        .fold(either(made, locked), either)
}

/// The failed attempts nobody signed in to make, typed with `held`'s
/// address over the time the account held it.
fn attempts_at(held: &HeldAddress) -> Picks {
    let typed = Picks::Holds(
        "event_type = 'authentication.login_failed' AND actor_id IS NULL \
         AND lower(payload -> 'value' ->> 'email') = ?",
        held.address.as_str().to_lowercase(),
    );
    let since = held.since.map(|at| {
        Picks::Holds(
            "occurred_at >= 'epoch'::timestamptz + ?::bigint * interval '1 microsecond'",
            micros(at),
        )
    });
    let until = held.until.map(|at| {
        Picks::Holds(
            "occurred_at < 'epoch'::timestamptz + ?::bigint * interval '1 microsecond'",
            micros(at),
        )
    });
    [since, until]
        .into_iter()
        .flatten()
        .fold(typed, |kept, bound| {
            Picks::And(Box::new(kept), Box::new(bound))
        })
}

/// The rows `left` or `right` keeps.
fn either(left: Picks, right: Picks) -> Picks {
    Picks::Or(Box::new(left), Box::new(right))
}

/// `at` as whole microseconds since the Unix epoch, written as text for a
/// condition to bind.
fn micros(at: OffsetDateTime) -> String {
    at.unix_timestamp_nanos().div_euclid(1_000).to_string()
}

/// `query` narrowed to the records whose details name `named`, read from
/// the payload's fields as `postgres/audit/payload.rs` keeps them.
fn by_named<Read>(
    query: PageQuery<'static, Read>,
    named: Option<&NamedInRecord>,
) -> PageQuery<'static, Read> {
    match named {
        None => query,
        Some(NamedInRecord::Address(email)) => query.filter(
            "lower(payload -> 'value' ->> 'email') = ?",
            email.as_str().to_lowercase(),
        ),
        Some(NamedInRecord::Account(user)) => query.filter(
            "payload -> 'value' -> 'user' ->> 'id' = ?",
            user.to_string(),
        ),
    }
}

/// `query` narrowed to the records `actor` acted in, by kind and id.
fn by_actor<Read>(
    query: PageQuery<'static, Read>,
    actor: Option<(&'static str, Option<Uuid>)>,
) -> PageQuery<'static, Read> {
    let Some((kind, id)) = actor else {
        return query;
    };
    let query = query.filter("actor_kind = ?", kind);
    let Some(id) = id else {
        return query.keep("actor_id IS NULL");
    };
    query.filter("actor_id = ?", id)
}

/// The pattern matching every event type that starts with `prefix`, its
/// own `%`, `_` and `\` matched as themselves.
fn prefix_pattern(prefix: &str) -> String {
    let escaped: String = prefix
        .chars()
        .flat_map(|character| {
            let escape = matches!(character, '%' | '_' | '\\').then_some('\\');
            escape.into_iter().chain(std::iter::once(character))
        })
        .collect();
    format!("{escaped}%")
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{ActingFor, ActorRef, AgentId};

    use super::*;

    /// Prefix patterns escape literal underscores and percent signs before
    /// adding the wildcard for the remaining event name.
    #[test]
    fn a_prefix_matches_its_own_marks_as_themselves() {
        assert_eq!(
            prefix_pattern("organization.org_user"),
            "organization.org\\_user%"
        );
        assert_eq!(prefix_pattern("50%"), "50\\%%");
    }

    /// A filter by an agent keeps the agent's kind and id, so its records
    /// are found whoever it acted for.
    #[test]
    fn a_filter_by_actor_keeps_its_kind_and_id() {
        let agent = AgentId::new();
        let filter = AuditLogFilter {
            actor: Some(ActorRef::Agent {
                id: agent,
                on_behalf_of: ActingFor::Itself,
            }),
            ..AuditLogFilter::default()
        };

        let narrowing = Narrowing::of_log(&filter);

        assert_eq!(narrowing.actor, Some(("agent", Some(*agent.as_uuid()))));
    }
}
