//! JWT types, and which tokens may be presented as a credential.
//!
//! One tenant key signs most JWTs the platform issues, such as access
//! tokens and task tokens. What the proxy makes for an upstream, the
//! identity assertion, the down-scoped exchanged token and the request and
//! response signatures, is signed with the tenant's assertion keys instead
//! (see [`assertion_key`](crate::domains::crypto::assertion_key)), which
//! the gateway holds and the tenant's signing keys never are. Without a way
//! to tell them apart, someone could copy an upstream token off the wire
//! and present it to the proxy as an access token. So each kind carries
//! its own `typ` header, as RFC 8725 §3.11 describes, and only the access
//! type is accepted as a credential.

/// The kind of a platform-signed JWT, carried in its `typ` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtType {
    /// A token a caller presents to authenticate: access and task tokens.
    Access,
    /// The proxy's identity assertion to an upstream, `X-Ianua-Assertion`,
    /// signed with the tenant's assertion keys.
    UpstreamAssertion,
    /// A down-scoped token the proxy mints for an upstream's audience,
    /// signed with the tenant's assertion keys. See
    /// [`ExchangedToken`](crate::domains::proxy::exchange::ExchangedToken).
    ExchangedToken,
    /// A signature over a request or response the proxy relayed, signed
    /// with the tenant's assertion keys.
    MessageSignature,
    /// The signed authorship of a message the agent relay forwarded.
    MessageProvenance,
    /// A proof of possession of the key a task token is bound to, as in
    /// RFC 9449. The holder of that key, an agent's runner, signs it.
    DpopProof,
    /// The session a person holds on one app's host after signing in there.
    /// Accepted only from that host's session cookie, never as a bearer
    /// token, so it cannot be lifted off one app and presented to another.
    AppSession,
    /// An OpenID Connect ID token: a statement to a client about who signed
    /// in, never something to present back as a credential.
    IdToken,
    /// A security event token (RFC 8417) sent to a signals receiver.
    SecurityEvent,
    /// A logout token posted to an app's server when a person signs out
    /// (OpenID Connect Back-Channel Logout 1.0, 2.4). Typed apart from an
    /// ID token, so neither can be passed off as the other.
    LogoutToken,
    /// The pass a workflow run's Protected apps step carries for one call,
    /// acting as the run's person on one route. Accepted only on the
    /// gateway's workflow listener, never as a bearer token elsewhere, so a
    /// pass taken off the wire opens nothing a person's token would.
    RunPass,
    /// The seal over a tenant's audit log export: a statement naming the
    /// file's digest, for an auditor to check against the tenant's keys.
    /// Never a credential.
    AuditSeal,
}

impl JwtType {
    /// Every kind, so a check over all of them cannot miss one added later.
    pub const ALL: [Self; 12] = [
        Self::Access,
        Self::UpstreamAssertion,
        Self::ExchangedToken,
        Self::MessageSignature,
        Self::MessageProvenance,
        Self::DpopProof,
        Self::AppSession,
        Self::IdToken,
        Self::SecurityEvent,
        Self::LogoutToken,
        Self::RunPass,
        Self::AuditSeal,
    ];

    /// The `typ` header value this kind is signed with.
    ///
    /// Access tokens are `at+jwt`, from RFC 9068. It is the one type
    /// accepted as a credential. ID tokens are plain `JWT`, as OpenID Connect
    /// clients expect. Widely used client libraries refuse an ID token typed
    /// any other way, and `JWT` is never accepted as a credential.
    #[must_use]
    pub fn header_value(self) -> &'static str {
        match self {
            Self::Access => "at+jwt",
            Self::UpstreamAssertion => "ianua-assertion+jwt",
            Self::ExchangedToken => "ianua-exchanged+jwt",
            Self::MessageSignature => "ianua-signature+jwt",
            Self::MessageProvenance => "ianua-provenance+jwt",
            Self::DpopProof => "dpop+jwt",
            Self::AppSession => "ianua-app-session+jwt",
            Self::IdToken => "JWT",
            Self::SecurityEvent => "secevent+jwt",
            Self::LogoutToken => "logout+jwt",
            Self::RunPass => "ianua-run-pass+jwt",
            Self::AuditSeal => "ianua-audit-seal+jwt",
        }
    }

    /// Whether a `typ` header names exactly this kind. A missing header names
    /// no platform-minted kind.
    #[must_use]
    pub fn is_named_by(self, typ: Option<&str>) -> bool {
        typ.is_some_and(|typ| media_type(typ).eq_ignore_ascii_case(self.header_value()))
    }

    /// Whether a JWT with this `typ` header may be presented as a credential.
    ///
    /// Only an access token, `at+jwt` from RFC 9068, is accepted. Every other
    /// kind is refused. A plain `JWT` is an ID token, which tells a client
    /// who signed in. If it worked as a bearer token, any client that gets
    /// ID tokens could call a service its audience names. A token with no
    /// `typ` is refused too, because every token the platform signs has one.
    /// The comparison ignores case and an `application/` prefix, as RFC 7515
    /// allows.
    #[must_use]
    pub fn accepted_as_credential(typ: Option<&str>) -> bool {
        typ.is_some_and(|typ| media_type(typ) == "at+jwt")
    }
}

/// A `typ` value lowercased and without its optional `application/` prefix.
fn media_type(typ: &str) -> String {
    let lowered = typ.to_ascii_lowercase();
    lowered
        .strip_prefix("application/")
        .map_or_else(|| lowered.clone(), str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An access token typed `at+jwt` is accepted as a credential, also when
    /// written `application/at+JWT`.
    #[test]
    fn an_access_token_is_a_credential() {
        assert!(JwtType::accepted_as_credential(Some(
            JwtType::Access.header_value()
        )));
        assert!(JwtType::accepted_as_credential(Some("at+jwt")));
        assert!(JwtType::accepted_as_credential(Some("application/at+JWT")));
    }

    /// ID, logout and security event token types are refused as credentials,
    /// including the plain `JWT` type used for ID tokens.
    #[test]
    fn an_id_token_or_security_event_is_not_a_credential() {
        for kind in [
            JwtType::IdToken,
            JwtType::LogoutToken,
            JwtType::SecurityEvent,
        ] {
            assert!(
                !JwtType::accepted_as_credential(Some(kind.header_value())),
                "{kind:?} must never authenticate a caller"
            );
        }
        assert!(!JwtType::accepted_as_credential(Some("JWT")));
    }

    /// An ID token is typed `JWT`. Strict OpenID Connect client libraries
    /// refuse any other type, which would break every sign-in through them.
    #[test]
    fn an_id_token_is_typed_as_openid_connect_clients_expect() {
        assert_eq!(JwtType::IdToken.header_value(), "JWT");
    }

    /// Of all twelve kinds, only the access token is accepted as a credential.
    /// A kind added later is caught here through `JwtType::ALL`.
    #[test]
    fn exactly_one_kind_is_a_credential() {
        let credentials: Vec<JwtType> = JwtType::ALL
            .into_iter()
            .filter(|kind| JwtType::accepted_as_credential(Some(kind.header_value())))
            .collect();

        assert_eq!(credentials, [JwtType::Access]);
    }

    /// A token with no `typ` header is refused. Every token the platform
    /// signs is typed, so this one was not minted as a credential.
    #[test]
    fn an_untyped_token_is_not_a_credential() {
        assert!(!JwtType::accepted_as_credential(None));
    }

    /// Assertions, exchanged tokens, message signatures, provenance and DPoP
    /// proofs have types that cannot be used as bearer credentials.
    #[test]
    fn no_proxy_minted_token_is_a_credential() {
        for kind in [
            JwtType::UpstreamAssertion,
            JwtType::ExchangedToken,
            JwtType::MessageSignature,
            JwtType::MessageProvenance,
            JwtType::DpopProof,
        ] {
            assert!(
                !JwtType::accepted_as_credential(Some(kind.header_value())),
                "{kind:?} must never authenticate a caller"
            );
        }
    }

    /// An app session's type is refused as a bearer credential. Its own
    /// header identifies it, while the ID token's `JWT` header does not.
    #[test]
    fn an_app_session_is_not_a_bearer_credential() {
        assert!(!JwtType::accepted_as_credential(Some(
            JwtType::AppSession.header_value()
        )));
        assert!(JwtType::AppSession.is_named_by(Some("ianua-app-session+jwt")));
        assert!(!JwtType::AppSession.is_named_by(Some("JWT")));
    }

    /// Types other than `at+jwt`, such as `dpop+jwt`, `example+jwt` or an
    /// empty string, are refused as credentials.
    #[test]
    fn an_unknown_type_is_not_a_credential() {
        assert!(!JwtType::accepted_as_credential(Some("dpop+jwt")));
        assert!(!JwtType::accepted_as_credential(Some("example+jwt")));
        assert!(!JwtType::accepted_as_credential(Some("")));
    }

    /// Logout tokens use `logout+jwt`; neither that header nor an ID token's
    /// `JWT` header can identify the other kind of token.
    #[test]
    fn a_logout_token_is_typed_apart_from_an_id_token() {
        assert_eq!(JwtType::LogoutToken.header_value(), "logout+jwt");
        assert!(!JwtType::LogoutToken.is_named_by(Some("JWT")));
        assert!(!JwtType::IdToken.is_named_by(Some("logout+jwt")));
    }

    /// A provenance token is named by `ianua-provenance+jwt` in any case and
    /// with an `application/` prefix. It is not named by `JWT`, by another
    /// kind's header or by no header.
    #[test]
    fn a_kind_is_named_only_by_its_own_header() {
        assert!(JwtType::MessageProvenance.is_named_by(Some("ianua-provenance+jwt")));
        assert!(JwtType::MessageProvenance.is_named_by(Some("application/IANUA-provenance+JWT")));
        assert!(!JwtType::MessageProvenance.is_named_by(Some("JWT")));
        assert!(!JwtType::MessageProvenance.is_named_by(Some("ianua-signature+jwt")));
        assert!(!JwtType::MessageProvenance.is_named_by(None));
    }

    /// Each of the eleven kinds is named by its own header, and case does not
    /// matter, so `jwt` names an ID token and `AT+JWT` an access token.
    #[test]
    fn every_kind_is_named_by_its_own_header() {
        for kind in JwtType::ALL {
            assert!(kind.is_named_by(Some(kind.header_value())), "{kind:?}");
        }
        assert!(JwtType::IdToken.is_named_by(Some("jwt")));
        assert!(JwtType::Access.is_named_by(Some("AT+JWT")));
    }

    /// No two kinds share a `typ` value. A shared value would let one kind
    /// pass for the other.
    #[test]
    fn every_kind_has_a_distinct_header_value() {
        let values = JwtType::ALL.map(JwtType::header_value);
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
