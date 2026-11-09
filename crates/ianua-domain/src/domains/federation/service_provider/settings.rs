//! How a SAML app is answered: where assertions go, how they are signed
//! and sealed, and what its requests must carry.

use crate::domains::federation::control::FederationRight;
use crate::domains::federation::saml::name_id::NameIdFormat;
use crate::domains::federation::service_provider::attributes::AttributeStatements;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CertificatePem, HttpsUrl, Label, Setting};

/// The most addresses one app may have its assertions posted to.
const MAX_ACS_URLS: usize = 32;

/// The addresses an app's assertions may be posted to, its Assertion
/// Consumer Service URLs, with the one used when a request names none.
///
/// An assertion signs a person in to whoever receives it, so it goes only
/// to an address the app registered, never to one a request names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsUrls {
    default: HttpsUrl,
    others: Vec<HttpsUrl>,
}

impl AcsUrls {
    /// The addresses `default` and `others`, each named once.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when an address is listed twice, or
    ///   when there are more than 32.
    pub fn new(default: HttpsUrl, others: Vec<HttpsUrl>) -> Result<Self, DomainError> {
        validate_count("acs_urls", others.len().saturating_add(1), 1..=MAX_ACS_URLS)?;
        let all = std::iter::once(&default).chain(&others);
        if let Some(twice) = first_repeat(all) {
            return Err(DomainError::invalid(message!(
                "federation-the-assertion-address-is-listed-twice",
                format!("the assertion address {} is listed twice", twice.as_str())
            )));
        }
        Ok(Self { default, others })
    }

    /// The address used when a request names none, and for a sign-in the
    /// app did not ask for.
    #[must_use]
    pub fn default_url(&self) -> &HttpsUrl {
        &self.default
    }

    /// The other registered addresses.
    #[must_use]
    pub fn others(&self) -> &[HttpsUrl] {
        &self.others
    }

    /// Whether `url` is one of the registered addresses, exactly.
    #[must_use]
    pub fn registered(&self, url: &HttpsUrl) -> bool {
        self.default == *url || self.others.contains(url)
    }

    /// Whether these name an address `before` did not.
    pub(crate) fn adds_beyond(&self, before: &Self) -> bool {
        std::iter::once(&self.default)
            .chain(&self.others)
            .any(|url| !before.registered(url))
    }
}

/// What this platform signs in its answer to an app.
///
/// The assertion is always signed, so it holds up on its own wherever it
/// is taken. An app may ask for the response around it to be signed too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedParts {
    /// Only the assertion.
    Assertion,
    /// The assertion and the response that carries it.
    AssertionAndResponse,
}

impl SignedParts {
    /// The stable name it is stored and sent under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assertion => "assertion",
            Self::AssertionAndResponse => "assertion_and_response",
        }
    }

    /// Whether the response itself is signed as well.
    #[must_use]
    pub fn signs_response(self) -> bool {
        self == Self::AssertionAndResponse
    }
}

/// Whether an app's assertions are sealed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionEncryption {
    /// The assertion travels signed but readable, through the person's
    /// browser.
    Plain,
    /// The assertion is encrypted to the key in this certificate, which
    /// the app holds, so the browser it passes through cannot read it.
    EncryptedFor(CertificatePem),
}

/// Whether an app's sign-in requests must be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSigningRule {
    /// Any request naming the app is answered.
    NotRequired,
    /// Only a request signed by the key in this certificate is answered.
    /// Nobody else can then start a sign-in in the app's name, with its
    /// own choice of `ForceAuthn` or address.
    Required(CertificatePem),
}

/// How an app is answered, as one value its changes are made to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlServiceProviderSettings {
    /// Where its assertions may be posted.
    pub acs_urls: AcsUrls,
    /// Where logout requests and answers to it go. Unset, single logout
    /// with it is off.
    pub logout_url: Setting<HttpsUrl>,
    /// How people are named to it.
    pub name_id_format: NameIdFormat,
    /// Which of a person's attributes it is sent, and under which names.
    pub attributes: AttributeStatements,
    /// What is signed in an answer to it.
    pub signing: SignedParts,
    /// Whether its assertions are sealed for it.
    pub encryption: AssertionEncryption,
    /// Whether its requests must be signed.
    pub request_signing: RequestSigningRule,
}

/// One change to a SAML app, made through
/// [`SamlServiceProvider::update`](crate::domains::federation::service_provider::SamlServiceProvider::update).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlServiceProviderChange {
    /// A new name.
    Rename(Label),
    /// New assertion addresses, replacing the old ones.
    AcsUrls(AcsUrls),
    /// A new logout address, or none.
    LogoutUrl(Setting<HttpsUrl>),
    /// A new `NameID` format.
    NameIdFormat(NameIdFormat),
    /// New attribute statements, replacing the old ones.
    Attributes(AttributeStatements),
    /// A new choice of what is signed.
    Signing(SignedParts),
    /// A new choice of whether assertions are sealed, and for which key.
    Encryption(AssertionEncryption),
    /// A new rule for its requests.
    RequestSigning(RequestSigningRule),
}

impl SamlServiceProviderChange {
    /// The right needed for the requested settings, against the app as it is `now`.
    ///
    /// A change that sends more of a person, or sends it to more places or
    /// more keys, or checks less, needs the full federation right. One
    /// that only narrows what the app gets needs the update right.
    pub(crate) fn needs(&self, now: &SamlServiceProviderSettings) -> FederationRight {
        if self.widens(now) {
            return FederationRight::TrustConnection;
        }
        FederationRight::EditConnection
    }

    fn widens(&self, now: &SamlServiceProviderSettings) -> bool {
        match self {
            Self::Rename(_) => false,
            Self::AcsUrls(urls) => urls.adds_beyond(&now.acs_urls),
            Self::LogoutUrl(url) => url
                .value()
                .is_some_and(|url| now.logout_url.value() != Some(url)),
            Self::NameIdFormat(format) => *format != now.name_id_format,
            Self::Attributes(attributes) => attributes.releases_beyond(&now.attributes),
            Self::Signing(signing) => !signing.signs_response() && now.signing.signs_response(),
            Self::Encryption(encryption) => *encryption != now.encryption,
            Self::RequestSigning(rule) => *rule != now.request_signing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> HttpsUrl {
        HttpsUrl::new(s).unwrap()
    }

    fn acs(urls: &[&str]) -> AcsUrls {
        AcsUrls::new(url(urls[0]), urls[1..].iter().map(|u| url(u)).collect()).unwrap()
    }

    /// An app registers `/acs` and `/acs/eu`. Both are registered; `/acs`
    /// is the default.
    #[test]
    fn the_first_address_is_the_default() {
        let urls = acs(&["https://app.acme.com/acs", "https://app.acme.com/acs/eu"]);

        assert_eq!(urls.default_url().as_str(), "https://app.acme.com/acs");
        assert!(urls.registered(&url("https://app.acme.com/acs/eu")));
    }

    /// Extending a registered assertion URL's path or hostname does not
    /// make the resulting URL registered.
    #[test]
    fn only_an_exact_address_is_registered() {
        let urls = acs(&["https://app.acme.com/acs"]);

        assert!(!urls.registered(&url("https://app.acme.com/acs/evil")));
        assert!(!urls.registered(&url("https://app.acme.com.evil.io/acs")));
    }

    /// An address listed twice is refused, so the list stays one entry per
    /// address.
    #[test]
    fn an_address_listed_twice_is_refused() {
        let result = AcsUrls::new(
            url("https://app.acme.com/acs"),
            vec![url("https://app.acme.com/acs")],
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Thirty-three addresses are refused, so one app cannot hold an
    /// unbounded list.
    #[test]
    fn more_than_thirty_two_addresses_are_refused() {
        let others = (1..=32)
            .map(|n| url(&format!("https://app.acme.com/acs/{n}")))
            .collect();

        let result = AcsUrls::new(url("https://app.acme.com/acs"), others);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Dropping an address adds nothing; naming a new one does.
    #[test]
    fn only_a_new_address_adds_beyond_the_old_list() {
        let before = acs(&["https://app.acme.com/acs", "https://app.acme.com/acs/eu"]);

        assert!(!acs(&["https://app.acme.com/acs"]).adds_beyond(&before));
        assert!(acs(&["https://app.acme.com/acs/us"]).adds_beyond(&before));
    }

    /// Only signing both the assertion and the response signs the response.
    #[test]
    fn only_the_wider_choice_signs_the_response() {
        assert!(SignedParts::AssertionAndResponse.signs_response());
        assert!(!SignedParts::Assertion.signs_response());
    }
}
