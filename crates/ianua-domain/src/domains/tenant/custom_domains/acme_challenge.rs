//! The proof a certificate authority asks for before it will issue.
//!
//! Let's Encrypt does not take our word that we control `hello.acme.com`. It
//! hands us a token and waits until that token is readable at a well-known URL
//! on the domain itself. Only something already serving the domain can put it
//! there, and that is what the check tests.
//!
//! Two processes are involved. The control plane talks to the certificate
//! authority. The proxy is the only thing answering on the domain. So the
//! control plane writes the answer here, and the proxy reads it from here.

use time::{Duration, OffsetDateTime};

use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::DomainName;

/// How long an unanswered challenge is kept.
///
/// A certificate authority checks within seconds, and the order expires within
/// the hour. Anything still here after this was abandoned, for example by a
/// failed provisioning run. Keeping them forever would leave a growing set of
/// URLs that answer.
const LIFETIME_MINUTES: i64 = 60;

text_value! {
    /// The random identifier a certificate authority issues for one challenge.
    ///
    /// It is the last path segment of the URL the authority fetches. Every
    /// request to that path compares untrusted input against it, so only a
    /// checked token can take part in the comparison.
    pub struct ChallengeToken;
}

impl TextValue for ChallengeToken {
    const FIELD: &'static str = "acme_challenge_token";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=255,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

text_value! {
    /// What the certificate authority expects to read back.
    ///
    /// The token joined to a fingerprint of our account key. It is not a
    /// secret, since anyone can fetch it. It is the proof itself, so it has its
    /// own type.
    pub struct KeyAuthorization;
}

impl TextValue for KeyAuthorization {
    const FIELD: &'static str = "acme_key_authorization";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=512,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::DOT,
        )
    }
}

/// Stored fields of an [`AcmeChallenge`], read back by repositories.
pub struct AcmeChallengeRow {
    /// The token forming the challenge URL's last segment.
    pub token: ChallengeToken,
    /// The body the certificate authority expects to read.
    pub key_authorization: KeyAuthorization,
    /// The domain being proved.
    pub domain: DomainName,
    /// When this stops being answered.
    pub expires_at: OffsetDateTime,
}

/// One outstanding HTTP-01 challenge.
///
/// It belongs to no tenant scope. A certificate authority fetches the
/// challenge URL with no session and no tenant, so the token alone has to
/// find it. The authority made the token, so there is nothing else to look it
/// up by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeChallenge {
    token: ChallengeToken,
    key_authorization: KeyAuthorization,
    domain: DomainName,
    expires_at: OffsetDateTime,
}

impl AcmeChallenge {
    /// Opens a challenge, to be answered until it expires.
    #[must_use]
    pub fn open(
        token: ChallengeToken,
        key_authorization: KeyAuthorization,
        domain: DomainName,
    ) -> Self {
        Self {
            token,
            key_authorization,
            domain,
            expires_at: crate::shared::clock::now()
                .saturating_add(Duration::minutes(LIFETIME_MINUTES)),
        }
    }

    /// Rebuilds an ACME challenge from storage.
    ///
    /// # Errors
    ///
    /// - None. Each field is already a checked type and no two fields can
    ///   contradict each other.
    pub fn reconstitute(row: AcmeChallengeRow) -> Result<Self, DomainError> {
        Ok(Self {
            token: row.token,
            key_authorization: row.key_authorization,
            domain: row.domain,
            expires_at: row.expires_at,
        })
    }

    /// The token forming the challenge URL's last segment.
    #[must_use]
    pub fn token(&self) -> &ChallengeToken {
        &self.token
    }

    /// The domain this challenge proves control of.
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// When this stops being answered.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// The stored proof, whatever the clock says.
    ///
    /// This is for storage, which must write a challenge back exactly as it
    /// found it. Code answering a request uses [`answer`](Self::answer)
    /// instead, which gives nothing once the challenge has expired.
    #[must_use]
    pub fn key_authorization(&self) -> &KeyAuthorization {
        &self.key_authorization
    }

    /// The body to serve, or `None` once the challenge has expired.
    ///
    /// Expiry is checked here, not by whoever stored the row. So a row that a
    /// cleanup sweep missed still stops answering on time.
    #[must_use]
    pub fn answer(&self, now: OffsetDateTime) -> Option<&KeyAuthorization> {
        if now >= self.expires_at {
            return None;
        }
        Some(&self.key_authorization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> AcmeChallenge {
        AcmeChallenge::open(
            ChallengeToken::new("tok_abc123").unwrap(),
            KeyAuthorization::new("tok_abc123.thumbprint").unwrap(),
            DomainName::new("hello.acme.com").unwrap(),
        )
    }

    /// A challenge for `hello.acme.com` was just opened. Asked now, it
    /// answers with the key authorization the authority expects.
    #[test]
    fn an_open_challenge_answers_with_its_key_authorization() {
        let challenge = challenge();

        let answer = challenge.answer(crate::shared::clock::now());

        assert_eq!(
            answer.map(KeyAuthorization::as_str),
            Some("tok_abc123.thumbprint")
        );
    }

    /// A challenge is asked one second after it expired. It answers nothing,
    /// even when the cleanup sweep has not removed the row yet.
    #[test]
    fn an_expired_challenge_answers_nothing() {
        let challenge = challenge();

        let later = challenge.expires_at() + Duration::seconds(1);

        assert!(challenge.answer(later).is_none());
    }

    /// A challenge is asked at the exact instant it expires. It answers
    /// nothing.
    #[test]
    fn a_challenge_stops_answering_exactly_at_its_expiry() {
        let challenge = challenge();

        assert!(challenge.answer(challenge.expires_at()).is_none());
    }

    /// Challenge tokens reject slashes, plus signs, spaces and dots, including
    /// a string shaped like a parent-directory path.
    #[test]
    fn a_token_outside_the_base64url_alphabet_is_refused() {
        for bad in ["tok/abc", "tok+abc", "tok abc", "tok.abc", "../etc/passwd"] {
            assert!(
                ChallengeToken::new(bad).is_err(),
                "{bad} should not parse as a token"
            );
        }
    }

    /// An empty challenge token is refused.
    #[test]
    fn an_empty_token_is_refused() {
        assert!(ChallengeToken::new("").is_err());
    }

    /// A token mixing cases, digits, a hyphen and an underscore, as an
    /// authority issues them, is accepted and kept as given.
    #[test]
    fn a_token_the_authority_would_issue_is_accepted() {
        let token = ChallengeToken::new("aBc-123_XyZ").unwrap();

        assert_eq!(token.as_str(), "aBc-123_XyZ");
    }

    /// Empty proof text cannot become a key authorization.
    #[test]
    fn an_empty_key_authorization_is_refused() {
        assert!(KeyAuthorization::new("").is_err());
    }

    /// A challenge has expired. Storage still reads its key authorization to
    /// write it back, while a request asking for it gets nothing.
    #[test]
    fn an_expired_challenge_still_persists_its_proof_but_will_not_serve_it() {
        let challenge = challenge();
        let later = challenge.expires_at() + Duration::seconds(1);

        assert_eq!(
            challenge.key_authorization().as_str(),
            "tok_abc123.thumbprint"
        );
        assert!(challenge.answer(later).is_none());
    }

    /// A valid token reads from JSON and writes back the same. `../etc/passwd`
    /// read from JSON is refused, as it is in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_token_read_from_json_is_held_to_the_base64url_alphabet() {
        let token: ChallengeToken = serde_json::from_str("\"aBc-123_XyZ\"").unwrap();

        assert_eq!(serde_json::to_string(&token).unwrap(), "\"aBc-123_XyZ\"");
        assert!(serde_json::from_str::<ChallengeToken>("\"../etc/passwd\"").is_err());
    }

    /// `tok.thumb` reads from JSON and writes back the same. An empty value
    /// and one with an accented letter are refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_key_authorization_read_from_json_is_validated() {
        let proof: KeyAuthorization = serde_json::from_str("\"tok.thumb\"").unwrap();

        assert_eq!(serde_json::to_string(&proof).unwrap(), "\"tok.thumb\"");
        assert!(serde_json::from_str::<KeyAuthorization>("\"\"").is_err());
        assert!(serde_json::from_str::<KeyAuthorization>("\"caf\u{e9}\"").is_err());
    }

    /// An open challenge is stored and read back. It equals the original,
    /// expiry included.
    #[test]
    fn reconstitute_preserves_every_field() {
        let original = challenge();

        let restored = AcmeChallenge::reconstitute(AcmeChallengeRow {
            token: original.token().clone(),
            key_authorization: KeyAuthorization::new("tok_abc123.thumbprint").unwrap(),
            domain: original.domain().clone(),
            expires_at: original.expires_at(),
        })
        .unwrap();

        assert_eq!(restored, original);
    }
}
