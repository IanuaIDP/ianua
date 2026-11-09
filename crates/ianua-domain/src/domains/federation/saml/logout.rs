//! Single logout: the requests that end a person's session at the other
//! side of a SAML trust, and the answers to them.
//!
//! It runs both ways. As identity provider, this platform asks each app a
//! person signed in to to end its session, and answers an app that asks it
//! to. As service provider, it asks a connection's provider, and answers
//! it. Either way a request is taken only from the peer it names, and an
//! answer only for a request this platform sent.

use time::{Duration, OffsetDateTime};

use crate::domains::federation::saml::name_id::SamlNameIdValue;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    HttpsUrl, SamlEntityId, SamlNameIdFormat, SamlRequestId, SamlResponseId, SessionIndex,
};

/// How long a logout request waits for its answer.
const LOGOUT_WINDOW: Duration = Duration::minutes(10);

/// How a logout went at the other side, as its answer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutStatus {
    /// Every session it was asked to end has ended.
    Success,
    /// Some sessions ended, and some could not be.
    Partial,
    /// It could not log the person out.
    Failed,
}

impl LogoutStatus {
    /// The stable name records carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }

    /// The top-level `StatusCode` written for this status.
    #[must_use]
    pub fn status_code(self) -> &'static str {
        match self {
            Self::Success | Self::Partial => "urn:oasis:names:tc:SAML:2.0:status:Success",
            Self::Failed => "urn:oasis:names:tc:SAML:2.0:status:Responder",
        }
    }

    /// The second-level `StatusCode` written beneath it, for a partial
    /// logout.
    #[must_use]
    pub fn sub_code(self) -> Option<&'static str> {
        match self {
            Self::Partial => Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"),
            Self::Success | Self::Failed => None,
        }
    }

    /// The status an answer's top-level and second-level codes say. Any
    /// top-level code but success is a failure, so a code nobody knows is
    /// never read as a logout that worked.
    #[must_use]
    pub fn from_codes(top: &str, sub: &str) -> Self {
        let partial = Self::Partial.sub_code() == Some(sub);
        match (top == Self::Success.status_code(), partial) {
            (true, true) => Self::Partial,
            (true, false) => Self::Success,
            (false, _) => Self::Failed,
        }
    }
}

/// How far a peer's clock may run from this one, either way, when the issue
/// time of its logout request is read.
pub(crate) const LOGOUT_CLOCK_SKEW: Duration = Duration::seconds(60);

/// How long after it was issued a peer's logout request is taken. The
/// browser carries it on at once, so a few minutes is generous.
pub(crate) const LOGOUT_REQUEST_LIFETIME: Duration = Duration::minutes(5);

/// A logout request from the other side, as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutRequest {
    id: SamlRequestId,
    issuer: SamlEntityId,
    issued_at: OffsetDateTime,
    name_id: SamlNameIdValue,
    session_indexes: Vec<SessionIndex>,
}

/// What a read logout request says.
#[derive(Debug)]
pub struct LogoutRequestParts {
    /// Its `ID`, which the answer names as `InResponseTo`.
    pub id: SamlRequestId,
    /// Who sent it, its `Issuer`.
    pub issuer: SamlEntityId,
    /// When it was issued, its `IssueInstant`.
    pub issued_at: OffsetDateTime,
    /// The `NameID` of the person to log out.
    pub name_id: SamlNameIdValue,
    /// The sessions to end. Empty asks for every session of the person.
    pub session_indexes: Vec<SessionIndex>,
}

impl SamlLogoutRequest {
    /// The request `parts` describe.
    #[must_use]
    pub fn new(parts: LogoutRequestParts) -> Self {
        Self {
            id: parts.id,
            issuer: parts.issuer,
            issued_at: parts.issued_at,
            name_id: parts.name_id,
            session_indexes: parts.session_indexes,
        }
    }

    /// Refuses a request issued more than `LOGOUT_REQUEST_LIFETIME` before
    /// `now`, or issued after it, past `LOGOUT_CLOCK_SKEW` either way.
    ///
    /// A request need not carry `NotOnOrAfter`, so its issue time is what
    /// bounds it. Without the bound, a request captured once would end the
    /// person's sessions whenever it is sent again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the request is too old or issued
    ///   ahead of now.
    pub fn ensure_fresh(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.issued_at > now.saturating_add(LOGOUT_CLOCK_SKEW) {
            return Err(DomainError::invalid(message!(
                "federation-the-logout-request-was-issued-ahead",
                "the logout request was issued ahead of now"
            )));
        }
        let oldest = now.saturating_sub(LOGOUT_REQUEST_LIFETIME.saturating_add(LOGOUT_CLOCK_SKEW));
        if self.issued_at < oldest {
            return Err(DomainError::invalid(message!(
                "federation-the-logout-request-is-too-old",
                "the logout request is too old"
            )));
        }
        Ok(())
    }

    /// When this request stops being taken. Remembering it as spent until
    /// then is enough: afterwards [`ensure_fresh`](Self::ensure_fresh)
    /// refuses it anyway.
    #[must_use]
    pub fn taken_until(&self) -> OffsetDateTime {
        self.issued_at
            .saturating_add(LOGOUT_REQUEST_LIFETIME)
            .saturating_add(LOGOUT_CLOCK_SKEW)
    }

    /// When it was issued.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// The request correlation value copied into the peer's logout answer.
    #[must_use]
    pub fn id(&self) -> &SamlRequestId {
        &self.id
    }

    /// Who sent it.
    #[must_use]
    pub fn issuer(&self) -> &SamlEntityId {
        &self.issuer
    }

    /// The `NameID` of the person to log out.
    #[must_use]
    pub fn name_id(&self) -> &SamlNameIdValue {
        &self.name_id
    }

    /// The sessions to end. Empty asks for every session of the person.
    #[must_use]
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// The answer owed to this request, sent to `destination`, once the
    /// peer it names was found to be the one it came from.
    pub(crate) fn answered_at(&self, destination: HttpsUrl) -> LogoutAnswer {
        LogoutAnswer {
            in_response_to: self.id.clone(),
            destination,
        }
    }
}

/// An answer from the other side to a logout request, as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutResponse {
    id: SamlResponseId,
    issuer: SamlEntityId,
    in_response_to: SamlRequestId,
    status: LogoutStatus,
}

/// What a read logout answer says.
#[derive(Debug)]
pub struct LogoutResponseParts {
    /// The response correlation value supplied by the peer.
    pub id: SamlResponseId,
    /// Who sent it, its `Issuer`.
    pub issuer: SamlEntityId,
    /// The request it answers, its `InResponseTo`.
    pub in_response_to: SamlRequestId,
    /// How the logout went.
    pub status: LogoutStatus,
}

impl SamlLogoutResponse {
    /// The answer `parts` describe.
    #[must_use]
    pub fn new(parts: LogoutResponseParts) -> Self {
        Self {
            id: parts.id,
            issuer: parts.issuer,
            in_response_to: parts.in_response_to,
            status: parts.status,
        }
    }

    /// The response correlation value supplied by the peer.
    #[must_use]
    pub fn id(&self) -> &SamlResponseId {
        &self.id
    }

    /// Who sent it.
    #[must_use]
    pub fn issuer(&self) -> &SamlEntityId {
        &self.issuer
    }

    /// The request it answers.
    #[must_use]
    pub fn in_response_to(&self) -> &SamlRequestId {
        &self.in_response_to
    }

    /// How the logout went.
    #[must_use]
    pub fn status(&self) -> LogoutStatus {
        self.status
    }
}

/// Where the answer to a peer's logout request goes, and what it answers.
///
/// Only the peer the request came from makes one, once it checked the
/// request names it as issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutAnswer {
    in_response_to: SamlRequestId,
    destination: HttpsUrl,
}

impl LogoutAnswer {
    /// The request it answers.
    #[must_use]
    pub fn in_response_to(&self) -> &SamlRequestId {
        &self.in_response_to
    }

    /// The peer's logout address, where the answer is sent.
    #[must_use]
    pub fn destination(&self) -> &HttpsUrl {
        &self.destination
    }
}

/// The session a logout request asks a peer to end.
#[derive(Debug, Clone)]
pub struct LogoutSubject {
    /// The `ID` the request is sent with. The caller makes it.
    pub request_id: SamlRequestId,
    /// The `NameID` the person is known by at the peer.
    pub name_id: SamlNameIdValue,
    /// The session the peer knows them by.
    pub session_index: SessionIndex,
}

/// A logout request this platform sent, kept until its answer comes back.
///
/// An answer is taken only when it names this request, comes from the peer
/// it went to, and arrives within ten minutes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentLogoutRequest {
    id: SamlRequestId,
    peer: SamlEntityId,
    destination: HttpsUrl,
    name_id_format: SamlNameIdFormat,
    name_id: SamlNameIdValue,
    session_index: SessionIndex,
    sent_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// A sent logout request as stored, for [`SentLogoutRequest::reconstitute`].
#[derive(Debug)]
pub struct SentLogoutRequestRow {
    /// The request correlation value used to match the peer's later answer.
    pub id: SamlRequestId,
    /// The peer it went to.
    pub peer: SamlEntityId,
    /// The peer's logout address.
    pub destination: HttpsUrl,
    /// The format of the `NameID` it names.
    pub name_id_format: SamlNameIdFormat,
    /// The `NameID` it names.
    pub name_id: SamlNameIdValue,
    /// The session it asks the peer to end.
    pub session_index: SessionIndex,
    /// When it was sent.
    pub sent_at: OffsetDateTime,
    /// When an answer to it stops being taken.
    pub expires_at: OffsetDateTime,
}

/// Where a logout request goes, and how the person is named there.
pub(crate) struct LogoutPeer {
    pub(crate) peer: SamlEntityId,
    pub(crate) destination: HttpsUrl,
    pub(crate) name_id_format: SamlNameIdFormat,
}

impl SentLogoutRequest {
    /// A logout request for `subject`, sent now to `to`.
    pub(crate) fn sent(to: LogoutPeer, subject: LogoutSubject) -> Self {
        let sent_at = crate::shared::clock::now();
        Self {
            id: subject.request_id,
            peer: to.peer,
            destination: to.destination,
            name_id_format: to.name_id_format,
            name_id: subject.name_id,
            session_index: subject.session_index,
            sent_at,
            expires_at: sent_at.saturating_add(LOGOUT_WINDOW),
        }
    }

    /// Rebuilds a sent request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row runs out before it was
    ///   sent, or waits longer than ten minutes.
    pub fn reconstitute(row: SentLogoutRequestRow) -> Result<Self, DomainError> {
        RowCheck::of("sent logout request")
            .in_order(row.sent_at, row.expires_at, "runs out before it was sent")
            .holds(
                row.expires_at <= row.sent_at.saturating_add(LOGOUT_WINDOW),
                "waits longer for its answer than a logout request does",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            peer: row.peer,
            destination: row.destination,
            name_id_format: row.name_id_format,
            name_id: row.name_id,
            session_index: row.session_index,
            sent_at: row.sent_at,
            expires_at: row.expires_at,
        })
    }

    /// The request correlation value used to match the peer's later answer.
    #[must_use]
    pub fn id(&self) -> &SamlRequestId {
        &self.id
    }

    /// The peer it went to.
    #[must_use]
    pub fn peer(&self) -> &SamlEntityId {
        &self.peer
    }

    /// The peer's logout address.
    #[must_use]
    pub fn destination(&self) -> &HttpsUrl {
        &self.destination
    }

    /// The format of the `NameID` it names.
    #[must_use]
    pub fn name_id_format(&self) -> &SamlNameIdFormat {
        &self.name_id_format
    }

    /// The `NameID` it names.
    #[must_use]
    pub fn name_id(&self) -> &SamlNameIdValue {
        &self.name_id
    }

    /// The session it asks the peer to end.
    #[must_use]
    pub fn session_index(&self) -> &SessionIndex {
        &self.session_index
    }

    /// When it was sent.
    #[must_use]
    pub fn sent_at(&self) -> OffsetDateTime {
        self.sent_at
    }

    /// When an answer to it stops being taken.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// How the logout went, by `response`, once it is the answer to this
    /// request from the peer it went to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `response` answers another request,
    ///   or comes from another peer.
    /// - [`DomainError::Conflict`] when it came after ten minutes.
    pub fn accept_response(
        &self,
        response: &SamlLogoutResponse,
    ) -> Result<LogoutStatus, DomainError> {
        if response.in_response_to != self.id {
            return Err(DomainError::forbidden(message!(
                "federation-this-answer-is-for-a-logout",
                "this answer is for a logout request that was not sent"
            )));
        }
        if response.issuer != self.peer {
            return Err(DomainError::forbidden(message!(
                "federation-this-answer-comes-from-another-peer",
                "this answer comes from another peer than the request went to"
            )));
        }
        if crate::shared::clock::now() >= self.expires_at {
            return Err(DomainError::conflict(message!(
                "federation-the-logout-request-stopped-waiting-for",
                "the logout request stopped waiting for its answer"
            )));
        }
        Ok(response.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn entity(s: &str) -> SamlEntityId {
        SamlEntityId::new(s).unwrap()
    }

    fn request_id(s: &str) -> SamlRequestId {
        SamlRequestId::new(s).unwrap()
    }

    fn sent_to(peer: &str) -> SentLogoutRequest {
        SentLogoutRequest::sent(
            LogoutPeer {
                peer: entity(peer),
                destination: HttpsUrl::new("https://app.acme.com/slo").unwrap(),
                name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT).unwrap(),
            },
            LogoutSubject {
                request_id: request_id("_logout_1"),
                name_id: SamlNameIdValue::new("p-123").unwrap(),
                session_index: SessionIndex::new("_session_1").unwrap(),
            },
        )
    }

    fn answer(from: &str, to: &str, status: LogoutStatus) -> SamlLogoutResponse {
        SamlLogoutResponse::new(LogoutResponseParts {
            id: SamlResponseId::new("_answer_1").unwrap(),
            issuer: entity(from),
            in_response_to: request_id(to),
            status,
        })
    }

    fn issued(at: OffsetDateTime) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: request_id("_their_logout"),
            issuer: entity("https://app.acme.com"),
            issued_at: at,
            name_id: SamlNameIdValue::new("p-123").unwrap(),
            session_indexes: Vec::new(),
        })
    }

    /// Logout requests issued an hour ago or five minutes ahead fail
    /// freshness validation; a request issued one minute ago is accepted.
    #[test]
    fn a_logout_request_is_taken_only_while_fresh() {
        let now = crate::shared::clock::now();

        let old = issued(now - Duration::hours(1)).ensure_fresh(now);
        let ahead = issued(now + Duration::minutes(5)).ensure_fresh(now);
        let fresh = issued(now - Duration::minutes(1)).ensure_fresh(now);

        assert!(matches!(old, Err(DomainError::Validation(_))));
        assert!(matches!(ahead, Err(DomainError::Validation(_))));
        assert!(fresh.is_ok());
    }

    /// A request is remembered as spent until just after it would be
    /// refused as too old, so no window is left where it is neither.
    #[test]
    fn a_request_is_remembered_until_it_is_too_old() {
        let now = crate::shared::clock::now();
        let request = issued(now);

        let until = request.taken_until();

        assert!(request.ensure_fresh(until).is_ok());
        assert!(request.ensure_fresh(until + Duration::seconds(1)).is_err());
    }

    /// The app answers the logout request it was sent with a partial
    /// logout. The answer is taken and says partial.
    #[test]
    fn the_answer_to_a_sent_request_is_taken() {
        let sent = sent_to("https://app.acme.com");

        let status = sent.accept_response(&answer(
            "https://app.acme.com",
            "_logout_1",
            LogoutStatus::Partial,
        ));

        assert_eq!(status.unwrap(), LogoutStatus::Partial);
    }

    /// A logout answer naming a different request is forbidden even when
    /// its issuer matches the expected app.
    #[test]
    fn an_answer_to_a_request_never_sent_is_refused() {
        let sent = sent_to("https://app.acme.com");

        let status = sent.accept_response(&answer(
            "https://app.acme.com",
            "_logout_other",
            LogoutStatus::Success,
        ));

        assert!(matches!(status, Err(DomainError::Forbidden(_))));
    }

    /// A logout answer from another app is forbidden even when it names
    /// the correct request.
    #[test]
    fn an_answer_from_another_peer_is_refused() {
        let sent = sent_to("https://app.acme.com");

        let status = sent.accept_response(&answer(
            "https://evil.example.com",
            "_logout_1",
            LogoutStatus::Success,
        ));

        assert!(matches!(status, Err(DomainError::Forbidden(_))));
    }

    /// An answer arriving eleven minutes after the request is refused, so a
    /// captured answer cannot be played back later.
    #[test]
    fn an_answer_after_ten_minutes_is_refused() {
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let sent = sent_to("https://app.acme.com");
        let _later = crate::shared::clock::freeze(start + Duration::minutes(11));

        let status = sent.accept_response(&answer(
            "https://app.acme.com",
            "_logout_1",
            LogoutStatus::Success,
        ));

        assert!(matches!(status, Err(DomainError::Conflict(_))));
    }

    /// Success with the partial sub-code reads as partial, success alone as
    /// success, and any other top-level code as failed.
    #[test]
    fn an_answers_codes_read_as_its_status() {
        let success = LogoutStatus::Success.status_code();
        let partial = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

        assert_eq!(
            LogoutStatus::from_codes(success, partial),
            LogoutStatus::Partial
        );
        assert_eq!(LogoutStatus::from_codes(success, ""), LogoutStatus::Success);
        assert_eq!(
            LogoutStatus::from_codes("urn:oasis:names:tc:SAML:2.0:status:Requester", ""),
            LogoutStatus::Failed
        );
    }

    fn stored_row() -> SentLogoutRequestRow {
        let sent = sent_to("https://app.acme.com");
        SentLogoutRequestRow {
            id: sent.id,
            peer: sent.peer,
            destination: sent.destination,
            name_id_format: sent.name_id_format,
            name_id: sent.name_id,
            session_index: sent.session_index,
            sent_at: sent.sent_at,
            expires_at: sent.expires_at,
        }
    }

    /// A stored request waiting a day for its answer is refused as corrupt,
    /// never taken as one that waits that long.
    #[test]
    fn a_stored_request_waiting_too_long_is_refused() {
        let row = stored_row();
        let expires_at = row.sent_at + Duration::days(1);

        let read = SentLogoutRequest::reconstitute(SentLogoutRequestRow { expires_at, ..row });

        assert!(refused_as_corrupt(&read));
    }

    /// A stored request read back keeps its id and peer.
    #[test]
    fn a_stored_request_reads_back_as_it_was_sent() {
        let read = SentLogoutRequest::reconstitute(stored_row()).unwrap();

        assert_eq!(read.id().as_str(), "_logout_1");
        assert_eq!(read.peer().as_str(), "https://app.acme.com");
    }
}
