//! Protocol switches: WebSocket, and anything else that turns a request
//! into a raw two-way stream.
//!
//! The handshake is an ordinary request and passed the ordinary pipeline.
//! What follows the `101` is not HTTP, so no stage can see it, and the
//! domain decides on the handshake whether a switch may happen at all: a
//! pipeline that inspects answers, or a caller on a request budget, is
//! refused one. This module only asks that rule and enforces it, before
//! any backend is contacted.
//!
//! A tunnel is bounded like everything else. Only so many are open at
//! once; each closes when it has carried nothing for the idle time, when
//! the credential it was opened with expires or the lifetime runs out, and
//! when the authority it was opened under no longer holds. A check of that
//! authority that fails or does not answer in time closes it too, recorded
//! as a failed check. The gateway keeps on the request's record why it
//! closed one for access; a tunnel a side closed, or one left idle, adds
//! nothing to it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::{HeaderMap, Request, Response};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use ianua_domain::domains::proxy::observation::TunnelCloseReason;
use ianua_domain::domains::proxy::pipeline::UpgradeRule;
use ianua_domain::types::{CorrelationId, Expiry};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::body::ResponseBody;
use super::client::RequestBody;
use super::error::ForwardError;
use super::headers::{self, Hop};
use super::pool::Lease;
use super::settings::TunnelLimits;
use super::{period, semaphore};
use crate::observability::TunnelCloseRecord;

/// Whether the authority a tunnel was opened under still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    /// It does; the tunnel stays open.
    Holds,
    /// It does not; the tunnel closes.
    Lost,
    /// It could not be told, an error or a timeout; the tunnel closes.
    CheckFailed,
}

/// Asks again whether the caller that opened a tunnel may still use it:
/// an agent whose delegation may be revoked while it is open, or a person
/// who may be suspended or taken out of the route's group.
///
/// The answer is the application's to give; whatever fills this asks it.
/// Anything short of a clear [`Standing::Holds`] closes the tunnel.
#[async_trait]
pub(crate) trait TunnelAuthority: Send + Sync {
    /// Whether the authority still holds.
    async fn standing(&self) -> Standing;
}

/// Whether a request may switch protocols, and what a tunnel it opens is
/// held to.
#[derive(Clone)]
pub(crate) struct UpgradeTerms {
    /// What the pipeline says of a switch on this request.
    pub rule: UpgradeRule,
    /// When the credential the request came with stops being valid. A
    /// tunnel closes then at the latest.
    pub expiry: Expiry,
    /// Asked again while a tunnel is open, when the caller's authority can
    /// end before its credential does.
    pub authority: Option<Arc<dyn TunnelAuthority>>,
    /// For the gateway's log.
    pub correlation_id: CorrelationId,
    /// Where a close the gateway makes for access is recorded, on the
    /// record of the request that opened the tunnel.
    pub closing: TunnelCloseRecord,
}

/// What a request is, by its headers and the pipeline's rule.
///
/// # Errors
///
/// - [`ForwardError::UpgradeRefused`] when it asks to switch and the rule
///   refuses.
pub(super) fn hop_for(headers: &HeaderMap, rule: UpgradeRule) -> Result<Hop, ForwardError> {
    if !headers::asks_to_switch(headers) {
        return Ok(Hop::Message);
    }
    match rule {
        UpgradeRule::Allowed => Ok(Hop::Upgrade),
        UpgradeRule::Refused(refusal) => Err(ForwardError::UpgradeRefused(refusal)),
    }
}

/// The tunnels the gateway may hold, and what holds each.
pub(super) struct Tunnels {
    permits: Arc<Semaphore>,
    limits: TunnelLimits,
}

impl Tunnels {
    /// Room for `limits.max_open` tunnels.
    pub(super) fn new(limits: TunnelLimits) -> Self {
        Self {
            permits: semaphore(limits.max_open),
            limits,
        }
    }

    /// For a switch, a place among the tunnels and the client's side of
    /// it; nothing for a message.
    ///
    /// # Errors
    ///
    /// - [`ForwardError::TunnelsExhausted`] when every place is taken.
    /// - [`ForwardError::UpgradeUnavailable`] when the client's connection
    ///   cannot switch.
    pub(super) fn handshake(
        &self,
        request: &mut Request<RequestBody>,
        hop: Hop,
    ) -> Result<Option<Handshake>, ForwardError> {
        if hop == Hop::Message {
            return Ok(None);
        }
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Err(ForwardError::TunnelsExhausted);
        };
        let Some(client) = request.extensions_mut().remove::<OnUpgrade>() else {
            return Err(ForwardError::UpgradeUnavailable);
        };
        Ok(Some(Handshake {
            client,
            permit,
            limits: self.limits,
        }))
    }
}

/// A switch under way: the client's side and the place it holds.
pub(super) struct Handshake {
    client: OnUpgrade,
    permit: OwnedSemaphorePermit,
    limits: TunnelLimits,
}

impl Handshake {
    /// Joins the client to the backend that agreed with `response`, and
    /// answers the client with that `101`.
    ///
    /// The tunnel runs on its own task: the `101` has to reach the client
    /// before either side sends anything. It keeps its place among the
    /// tunnels, and its backend counted as busy, until it closes.
    pub(super) fn complete(
        self,
        mut response: Response<Incoming>,
        lease: Lease,
        terms: &UpgradeTerms,
    ) -> Response<ResponseBody> {
        let upstream = hyper::upgrade::on(&mut response);
        let tunnel = Tunnel {
            terms: terms.clone(),
            limits: self.limits,
            _held: (lease, self.permit),
        };
        tokio::spawn(tunnel.run(self.client, upstream));
        let (parts, _) = response.into_parts();
        Response::from_parts(parts, ResponseBody::empty())
    }
}

/// An open tunnel and what it holds.
struct Tunnel {
    terms: UpgradeTerms,
    limits: TunnelLimits,
    _held: (Lease, OwnedSemaphorePermit),
}

impl Tunnel {
    /// Waits for both sides to switch, at most the idle time, then copies
    /// between them until either closes or the gateway closes it.
    async fn run(self, client: OnUpgrade, upstream: OnUpgrade) {
        let correlation_id = self.terms.correlation_id;
        let switched = tokio::time::timeout(self.limits.idle, async {
            tokio::try_join!(client, upstream)
        })
        .await;
        let Ok(Ok((client, upstream))) = switched else {
            tracing::warn!(%correlation_id, "a protocol switch was never completed");
            return;
        };
        let ended = join(
            TokioIo::new(client),
            TokioIo::new(upstream),
            &self.terms,
            self.limits,
        )
        .await;
        tracing::info!(%correlation_id, ?ended, "tunnel closed");
        if let Some(reason) = ended.close_reason() {
            self.terms.closing.report(reason);
        }
    }
}

/// Why a tunnel closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TunnelEnd {
    /// Either side closed it.
    Closed,
    /// The credential expired.
    Expired,
    /// The lifetime ran out with the credential still good.
    LifetimeReached,
    /// Nothing moved for the idle time.
    Idle,
    /// The authority it was opened under no longer holds.
    AuthorityLost,
    /// A check of that authority failed or took too long.
    CheckFailed,
}

impl TunnelEnd {
    /// The reason the request's record keeps, when the gateway closed the
    /// tunnel for access.
    fn close_reason(self) -> Option<TunnelCloseReason> {
        match self {
            Self::AuthorityLost => Some(TunnelCloseReason::AccessEnded),
            Self::CheckFailed => Some(TunnelCloseReason::CheckFailed),
            Self::Expired => Some(TunnelCloseReason::CredentialExpired),
            Self::Closed | Self::Idle | Self::LifetimeReached => None,
        }
    }
}

/// Copies between `client` and `upstream` until either closes or the
/// gateway closes the tunnel under `terms` and `limits`.
pub(super) async fn join<C, U>(
    client: C,
    mut upstream: U,
    terms: &UpgradeTerms,
    limits: TunnelLimits,
) -> TunnelEnd
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let mut client = Tracked {
        io: client,
        activity: &activity,
    };
    let left = time_left(OffsetDateTime::now_utc(), terms.expiry, limits.lifetime);
    let deadline = deadline_end(left, limits.lifetime);
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => TunnelEnd::Closed,
        () = tokio::time::sleep(left) => deadline,
        () = activity.quiet_for(limits.idle) => TunnelEnd::Idle,
        ended = wait_for_authority_loss(terms.authority.as_deref(), limits) => ended,
    }
}

/// What a tunnel's deadline, `left` from now, means: the credential ran
/// out, or the lifetime did.
fn deadline_end(left: Duration, lifetime: Duration) -> TunnelEnd {
    if left < lifetime {
        return TunnelEnd::Expired;
    }
    TunnelEnd::LifetimeReached
}

/// How long a tunnel may stay open from `now`: the lifetime, or until
/// `expiry` when that comes first. Nothing once it has passed.
fn time_left(now: OffsetDateTime, expiry: Expiry, lifetime: Duration) -> Duration {
    let Some(at) = expiry.instant() else {
        return lifetime;
    };
    Duration::try_from(at - now)
        .unwrap_or(Duration::ZERO)
        .min(lifetime)
}

/// Resolves, with how, once `authority` no longer clearly holds; never
/// without one.
async fn wait_for_authority_loss(
    authority: Option<&dyn TunnelAuthority>,
    limits: TunnelLimits,
) -> TunnelEnd {
    let Some(authority) = authority else {
        return std::future::pending().await;
    };
    let mut checks = tokio::time::interval(period(limits.recheck_every));
    checks.tick().await;
    loop {
        checks.tick().await;
        match checked(authority, limits.recheck_timeout).await {
            Standing::Holds => {}
            Standing::Lost => return TunnelEnd::AuthorityLost,
            Standing::CheckFailed => return TunnelEnd::CheckFailed,
        }
    }
}

/// `authority`'s standing within `timeout`; a check past it has failed.
async fn checked(authority: &dyn TunnelAuthority, timeout: Duration) -> Standing {
    tokio::time::timeout(timeout, authority.standing())
        .await
        .unwrap_or(Standing::CheckFailed)
}

/// When a tunnel last carried anything.
struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    /// Activity starting now.
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    /// Something moved just now.
    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Relaxed);
    }

    /// How long nothing has moved.
    fn quiet(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }

    /// Resolves once nothing has moved for `idle`.
    async fn quiet_for(&self, idle: Duration) {
        loop {
            let quiet = self.quiet();
            if quiet >= idle {
                return;
            }
            tokio::time::sleep(idle - quiet).await;
        }
    }
}

/// A connection that notes each time something moves through it.
struct Tracked<'a, T> {
    io: T,
    activity: &'a Activity,
}

impl<T: AsyncRead + Unpin> AsyncRead for Tracked<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, data);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            this.activity.touch();
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::atomic::AtomicBool;

    use http::header;
    use ianua_domain::domains::proxy::pipeline::UpgradeRefusal;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::forward::client::empty_body;

    fn limits() -> TunnelLimits {
        TunnelLimits {
            max_open: NonZeroUsize::MIN,
            lifetime: Duration::from_secs(30),
            idle: Duration::from_secs(30),
            recheck_every: Duration::from_millis(20),
            recheck_timeout: Duration::from_secs(5),
        }
    }

    fn terms(expiry: Expiry, authority: Option<Arc<dyn TunnelAuthority>>) -> UpgradeTerms {
        UpgradeTerms {
            rule: UpgradeRule::Allowed,
            expiry,
            authority,
            correlation_id: CorrelationId::new(),
            closing: TunnelCloseRecord::unobserved(),
        }
    }

    fn handshake_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers
    }

    #[test]
    fn a_switch_the_rule_allows_is_tunnelled() {
        let hop = hop_for(&handshake_headers(), UpgradeRule::Allowed).unwrap();

        assert_eq!(hop, Hop::Upgrade);
    }

    /// WebSocket upgrade headers are refused when the pipeline's rule says
    /// it inspects responses, preserving that refusal reason.
    #[test]
    fn a_switch_the_rule_refuses_is_refused() {
        let refused = hop_for(
            &handshake_headers(),
            UpgradeRule::Refused(UpgradeRefusal::InspectsResponses),
        );

        assert!(matches!(
            refused,
            Err(ForwardError::UpgradeRefused(
                UpgradeRefusal::InspectsResponses
            ))
        ));
    }

    #[test]
    fn an_ordinary_request_is_a_message_whatever_the_rule() {
        let refusing = UpgradeRule::Refused(UpgradeRefusal::MeteredCaller);

        let hop = hop_for(&HeaderMap::new(), refusing).unwrap();

        assert_eq!(hop, Hop::Message);
    }

    #[test]
    fn a_switch_beyond_the_open_tunnels_is_refused() {
        let tunnels = Tunnels::new(limits());
        let _taken = Arc::clone(&tunnels.permits).try_acquire_owned().unwrap();
        let mut request = Request::new(empty_body());

        let refused = tunnels.handshake(&mut request, Hop::Upgrade);

        assert!(matches!(refused, Err(ForwardError::TunnelsExhausted)));
    }

    #[test]
    fn a_switch_on_a_connection_that_cannot_switch_is_refused() {
        let tunnels = Tunnels::new(limits());
        let mut request = Request::new(empty_body());

        let refused = tunnels.handshake(&mut request, Hop::Upgrade);

        assert!(matches!(refused, Err(ForwardError::UpgradeUnavailable)));
        assert_eq!(tunnels.permits.available_permits(), 1);
    }

    #[test]
    fn a_tunnel_lives_no_longer_than_its_credential_or_the_lifetime() {
        let now = OffsetDateTime::now_utc();
        let hour = Duration::from_secs(3_600);
        let soon = Expiry::At(now + time::Duration::seconds(60));
        let gone = Expiry::At(now - time::Duration::seconds(1));

        assert_eq!(time_left(now, Expiry::Never, hour), hour);
        assert_eq!(time_left(now, soon, hour), Duration::from_secs(60));
        assert_eq!(time_left(now, gone, hour), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_silent_tunnel_is_closed() {
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let quick = TunnelLimits {
            idle: Duration::from_millis(100),
            ..limits()
        };

        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            join(client, upstream, &terms(Expiry::Never, None), quick),
        )
        .await
        .expect("an idle tunnel is closed");

        assert_eq!(ended, TunnelEnd::Idle);
    }

    #[tokio::test]
    async fn a_tunnel_carries_bytes_both_ways() {
        let (client, mut client_far) = tokio::io::duplex(64);
        let (upstream, mut upstream_far) = tokio::io::duplex(64);
        let terms = terms(Expiry::Never, None);
        let joined = tokio::spawn(async move { join(client, upstream, &terms, limits()).await });

        client_far.write_all(b"ping").await.unwrap();
        let mut heard = [0_u8; 4];
        upstream_far.read_exact(&mut heard).await.unwrap();
        drop(client_far);
        drop(upstream_far);

        assert_eq!(&heard, b"ping");
        assert_eq!(joined.await.unwrap(), TunnelEnd::Closed);
    }

    #[tokio::test]
    async fn a_tunnel_closes_when_its_credential_expires() {
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let expiry = Expiry::At(OffsetDateTime::now_utc() + time::Duration::milliseconds(200));

        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            join(client, upstream, &terms(expiry, None), limits()),
        )
        .await
        .expect("an expired credential's tunnel is closed");

        assert_eq!(ended, TunnelEnd::Expired);
    }

    struct Revocable(AtomicBool);

    #[async_trait]
    impl TunnelAuthority for Revocable {
        async fn standing(&self) -> Standing {
            if self.0.load(Ordering::SeqCst) {
                return Standing::Lost;
            }
            Standing::Holds
        }
    }

    /// Revoking an agent must close the tunnel it opened, not only refuse
    /// its next handshake.
    #[tokio::test]
    async fn losing_the_authority_closes_an_open_tunnel() {
        let authority = Arc::new(Revocable(AtomicBool::new(false)));
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let terms = terms(Expiry::Never, Some(authority.clone()));
        let joined = tokio::spawn(async move { join(client, upstream, &terms, limits()).await });

        authority.0.store(true, Ordering::SeqCst);
        let ended = tokio::time::timeout(Duration::from_secs(2), joined)
            .await
            .expect("the tunnel closes once the authority is lost")
            .unwrap();

        assert_eq!(ended, TunnelEnd::AuthorityLost);
    }

    struct Failing;

    #[async_trait]
    impl TunnelAuthority for Failing {
        async fn standing(&self) -> Standing {
            Standing::CheckFailed
        }
    }

    struct Hung;

    #[async_trait]
    impl TunnelAuthority for Hung {
        async fn standing(&self) -> Standing {
            std::future::pending().await
        }
    }

    /// A check that never answers must not hold the tunnel open.
    #[tokio::test]
    async fn a_check_that_never_answers_closes_the_tunnel() {
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let quick = TunnelLimits {
            recheck_timeout: Duration::from_millis(50),
            ..limits()
        };

        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            join(
                client,
                upstream,
                &terms(Expiry::Never, Some(Arc::new(Hung))),
                quick,
            ),
        )
        .await
        .expect("a hung check closes the tunnel");

        assert_eq!(ended, TunnelEnd::CheckFailed);
    }

    /// A check that says it could not be made closes the tunnel the same
    /// way, as a failed check.
    #[tokio::test]
    async fn a_failed_check_closes_the_tunnel() {
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);

        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            join(
                client,
                upstream,
                &terms(Expiry::Never, Some(Arc::new(Failing))),
                limits(),
            ),
        )
        .await
        .expect("a failed check closes the tunnel");

        assert_eq!(ended, TunnelEnd::CheckFailed);
    }

    /// Only the closes made for access reach the request's record.
    #[test]
    fn only_a_close_for_access_is_recorded() {
        assert_eq!(
            TunnelEnd::AuthorityLost.close_reason(),
            Some(TunnelCloseReason::AccessEnded)
        );
        assert_eq!(
            TunnelEnd::CheckFailed.close_reason(),
            Some(TunnelCloseReason::CheckFailed)
        );
        assert_eq!(
            TunnelEnd::Expired.close_reason(),
            Some(TunnelCloseReason::CredentialExpired)
        );
        for quiet in [
            TunnelEnd::Closed,
            TunnelEnd::Idle,
            TunnelEnd::LifetimeReached,
        ] {
            assert_eq!(quiet.close_reason(), None);
        }
    }

    /// A deadline set by the credential is its expiry; one set by the
    /// lifetime alone is not.
    #[test]
    fn a_deadline_says_what_ended() {
        let hour = Duration::from_secs(3600);

        assert_eq!(
            deadline_end(Duration::from_secs(60), hour),
            TunnelEnd::Expired
        );
        assert_eq!(deadline_end(hour, hour), TunnelEnd::LifetimeReached);
    }
}
