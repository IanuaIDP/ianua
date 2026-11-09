//! What the counting stages count under: who a request is counted as, and
//! the fixed window it falls in.
//!
//! Every key names its tenant. A client address is the same for every
//! tenant it calls, so without the tenant one tenant's traffic would spend
//! another's allowance for that address.

use std::net::IpAddr;

use ianua_domain::domains::proxy::request::context::{Caller, ConsumerCredential, PipelineContext};
use ianua_domain::domains::proxy::stages::stage::RateLimitKey;
use ianua_domain::types::{Seconds, StageId, TenantId};
use time::OffsetDateTime;

/// One fixed counting window, numbered from the Unix epoch, so every
/// instance agrees on where one ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FixedWindow {
    index: i64,
    resets_in: u32,
}

impl FixedWindow {
    /// The window of `length` that `now` falls in.
    pub(super) fn at(length: Seconds, now: OffsetDateTime) -> Self {
        let length = i64::from(length.get().max(1));
        let now = now.unix_timestamp();
        let elapsed = now.rem_euclid(length);
        Self {
            index: now.div_euclid(length),
            resets_in: u32::try_from(length - elapsed).unwrap_or(u32::MAX),
        }
    }

    /// The window's number.
    pub(super) fn index(self) -> i64 {
        self.index
    }

    /// Seconds until the next window starts.
    pub(super) fn resets_in(self) -> u32 {
        self.resets_in
    }
}

/// The client's address, as the edge established it.
pub(super) fn client_address(ctx: &PipelineContext) -> Option<IpAddr> {
    ctx.ip_address.known()?.as_str().parse().ok()
}

/// Whose requests a limit keyed by `key_by` counts this one with.
///
/// A request without what the limit is keyed by, such as an anonymous one
/// on a per-caller limit, is counted by its address, so it is still
/// limited. `None` only when the address is unknown too.
pub(super) fn subject(ctx: &PipelineContext, key_by: &RateLimitKey) -> Option<String> {
    named(ctx, key_by).or_else(|| by_address(ctx))
}

/// The counter for `subject` under one stage, in one window.
pub(super) fn counter_key(
    kind: &str,
    scope: CounterScope<'_>,
    subject: &str,
    window: i64,
) -> String {
    let CounterScope { tenant, stage } = scope;
    format!("{kind}:{tenant}:{stage}:{subject}:{window}")
}

/// The tenant and stage that own a counter, regardless of its kind or window.
#[derive(Clone, Copy)]
pub(super) struct CounterScope<'a> {
    /// The tenant whose requests are counted.
    pub(super) tenant: TenantId,
    /// The pipeline stage that owns this counter.
    pub(super) stage: &'a StageId,
}

fn named(ctx: &PipelineContext, key_by: &RateLimitKey) -> Option<String> {
    let caller = ctx.authentication().caller();
    match key_by {
        RateLimitKey::UserId => caller.map(caller_name),
        RateLimitKey::IpAddress => by_address(ctx),
        RateLimitKey::ApiKey => caller.and_then(api_key_holder),
        RateLimitKey::Tenant => Some("tenant".to_owned()),
        RateLimitKey::ConsumerId => caller.and_then(consumer),
    }
}

fn by_address(ctx: &PipelineContext) -> Option<String> {
    client_address(ctx).map(|address| format!("ip:{address}"))
}

/// Each user, agent and consumer on its own. An agent has no user id, so a
/// per-caller limit keyed on users alone would let agents through uncounted.
fn caller_name(caller: &Caller) -> String {
    match caller {
        Caller::User { user_id, .. } => format!("user:{user_id}"),
        Caller::Agent { agent_id, .. } => format!("agent:{agent_id}"),
        Caller::Consumer { consumer_id, .. } => format!("consumer:{consumer_id}"),
    }
}

fn api_key_holder(caller: &Caller) -> Option<String> {
    let Caller::Consumer {
        consumer_id,
        credential: ConsumerCredential::ApiKey,
    } = caller
    else {
        return None;
    };
    Some(format!("apikey:{consumer_id}"))
}

fn consumer(caller: &Caller) -> Option<String> {
    let Caller::Consumer { consumer_id, .. } = caller else {
        return None;
    };
    Some(format!("consumer:{consumer_id}"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::context::UserSignIn;
    use ianua_domain::types::{ConsumerId, Fact, UserId};

    use super::super::fakes::{context, signed_in};
    use super::*;

    /// A minute's window at 10:00:45 ends in fifteen seconds, and every
    /// moment of that minute is the same window.
    #[test]
    fn a_window_says_when_it_resets() {
        let at = |seconds| OffsetDateTime::from_unix_timestamp(seconds).unwrap();

        let window = FixedWindow::at(Seconds::new(60), at(36_045));
        let start = FixedWindow::at(Seconds::new(60), at(36_000));

        assert_eq!(window.resets_in(), 15);
        assert_eq!(window.index(), start.index());
    }

    /// An anonymous request on a per-caller limit is counted by its address,
    /// so it is still limited.
    #[test]
    fn an_anonymous_caller_is_counted_by_address() {
        assert_eq!(
            subject(&context(), &RateLimitKey::UserId).as_deref(),
            Some("ip:203.0.113.7")
        );
    }

    /// A signed-in person is counted as themselves, not by address.
    #[test]
    fn a_person_is_counted_as_themselves() {
        let user_id = UserId::new();
        let ctx = signed_in(Caller::User {
            user_id,
            sign_in: UserSignIn::Token,
        });

        assert_eq!(
            subject(&ctx, &RateLimitKey::UserId),
            Some(format!("user:{user_id}"))
        );
    }

    /// A consumer that signed in with a certificate is not counted as an API
    /// key holder; it falls back to its address.
    #[test]
    fn a_certificate_is_not_an_api_key() {
        let ctx = signed_in(Caller::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::Certificate,
        });

        assert_eq!(
            subject(&ctx, &RateLimitKey::ApiKey).as_deref(),
            Some("ip:203.0.113.7")
        );
    }

    /// Without an address and without what the limit is keyed by, there is
    /// nothing to count the request by.
    #[test]
    fn nothing_to_count_by_without_an_address() {
        let mut ctx = context();
        ctx.ip_address = Fact::Unknown;

        assert_eq!(subject(&ctx, &RateLimitKey::ConsumerId), None);
    }
}
