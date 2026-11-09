//! The `NameID` this platform names a person by to a SAML app, in the
//! formats an app may be set up for.
//!
//! A `NameID` is how the app recognises the person on their next sign-in,
//! so which one goes out is a rule here, not a choice of the code that
//! writes the assertion.

use crate::domains::federation::saml::authn_request::NameIdAsked;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{SamlNameIdFormat, SamlServiceProviderId, UserId};

/// The format URN that leaves the choice of `NameID` to the identity
/// provider.
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// The longest `NameID` value written or read.
const MAX_NAME_ID_BYTES: usize = 512;

/// The `NameID` format a SAML app is set up to receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameIdFormat {
    /// A pairwise id: the same for one person at one app for good, and
    /// different at every other app, so two apps cannot match their
    /// records of a person by it.
    Persistent,
    /// The person's address. Only a verified address goes out, since an app
    /// keyed on it would hand the records to whoever the address names.
    EmailAddress,
    /// A fresh random value at every sign-in, for an app that needs no
    /// lasting name for the person.
    Transient,
}

impl NameIdFormat {
    /// Every format, in the order metadata lists them.
    pub const ALL: [Self; 3] = [Self::Persistent, Self::EmailAddress, Self::Transient];

    /// The URN SAML names the format by.
    #[must_use]
    pub fn urn(self) -> &'static str {
        match self {
            Self::Persistent => SamlNameIdFormat::PERSISTENT,
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        }
    }

    /// The stable name the format is stored and sent under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::EmailAddress => "email_address",
            Self::Transient => "transient",
        }
    }

    /// The format stored under `value`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when no format is stored under
    ///   that name. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|format| format.as_str() == value)
            .ok_or_else(|| DomainError::corrupt_row("SAML app", "an unknown NameID format"))
    }

    /// Whether a request asking for `asked` is answered in this format: it
    /// asked for none, for this one, or left the choice to the identity
    /// provider.
    #[must_use]
    pub fn answers(self, asked: &NameIdAsked) -> bool {
        match asked {
            NameIdAsked::AnyFormat => true,
            NameIdAsked::Format(format) => {
                format.as_str() == self.urn() || format.as_str() == UNSPECIFIED
            }
        }
    }

    /// The `NameID` in this format for `user` at the app `provider`.
    ///
    /// The pairwise and the transient value come from `mint`. An address
    /// goes out only once its owner was shown to hold it.
    pub(crate) fn issue<T: TenantScope>(
        self,
        provider: &SamlServiceProviderId,
        user: &User<T>,
        mint: &impl NameIdMint,
    ) -> Result<IssuedNameId, DomainError> {
        let value = match self {
            Self::Persistent => mint.pairwise(provider, user.id())?,
            Self::EmailAddress => verified_address(user)?,
            Self::Transient => mint.transient()?,
        };
        Ok(IssuedNameId {
            format: self,
            value,
        })
    }
}

/// `user`'s address as a `NameID`, once its owner was shown to hold it.
fn verified_address<T: TenantScope>(user: &User<T>) -> Result<SamlNameIdValue, DomainError> {
    if !user.address().is_verified() {
        return Err(DomainError::conflict(message!(
            "federation-this-app-names-people-by-their",
            "this app names people by their address, and this account's address is not verified"
        )));
    }
    Ok(SamlNameIdValue::new(user.email().as_str())?)
}

text_value! {
    /// The text of a SAML `NameID`: a pairwise id, an address or a
    /// transient value this platform sent, or one a logout request names.
    pub struct SamlNameIdValue;
}

impl TextValue for SamlNameIdValue {
    const FIELD: &'static str = "name_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .max_bytes(MAX_NAME_ID_BYTES)
            .no_control_chars()
            .no_invisible_chars()
    }
}

/// The `NameID` an assertion names the person by, in the format the app
/// is set up for.
///
/// Only [`NameIdFormat::issue`] makes one, so no assertion carries an
/// unverified address or a value the app was not set up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedNameId {
    format: NameIdFormat,
    value: SamlNameIdValue,
}

impl IssuedNameId {
    /// The format it is written in.
    #[must_use]
    pub fn format(&self) -> NameIdFormat {
        self.format
    }

    /// The value written as the `NameID`.
    #[must_use]
    pub fn value(&self) -> &SamlNameIdValue {
        &self.value
    }

    /// A `NameID` of `format` holding `value`, for tests that write
    /// assertions.
    #[cfg(test)]
    pub(crate) fn of(format: NameIdFormat, value: &str) -> Self {
        Self {
            format,
            value: SamlNameIdValue::new(value).expect("a test passes a valid NameID"),
        }
    }
}

/// Makes the `NameID` values that need a secret or a random source.
///
/// # Implementors
///
/// - **Infrastructure:** a keyed hash of the app and the account under a
///   tenant secret for the pairwise id, and random bytes for the transient
///   one.
/// - **Tests:** a fake returning fixed values.
pub trait NameIdMint {
    /// The pairwise id of `account` at `provider`. The same inputs give the
    /// same id every time, and nobody without the secret can link two apps'
    /// ids for one person.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the secret cannot be read.
    fn pairwise(
        &self,
        provider: &SamlServiceProviderId,
        account: &UserId,
    ) -> Result<SamlNameIdValue, DomainError>;

    /// A fresh random value, never given out before.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the random source fails.
    fn transient(&self) -> Result<SamlNameIdValue, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every format is stored under its name and read back as itself, so a
    /// stored app keeps the format it was set up with.
    #[test]
    fn a_format_reads_back_from_its_stored_name() {
        for format in NameIdFormat::ALL {
            assert_eq!(NameIdFormat::from_stored(format.as_str()).unwrap(), format);
        }
    }

    /// A row naming a format no version wrote is refused as corrupt, never
    /// read as the persistent format.
    #[test]
    fn an_unknown_stored_format_is_refused_as_corrupt() {
        let read = NameIdFormat::from_stored("x509_subject");

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    fn asked(urn: &str) -> NameIdAsked {
        NameIdAsked::Format(SamlNameIdFormat::new(urn).unwrap())
    }

    /// An app set up for addresses asks for addresses, for the
    /// unspecified format, or for nothing. Each is answered in its format.
    #[test]
    fn a_request_for_the_set_up_format_or_none_is_answered() {
        let format = NameIdFormat::EmailAddress;

        assert!(format.answers(&NameIdAsked::AnyFormat));
        assert!(format.answers(&asked(UNSPECIFIED)));
        assert!(format.answers(&asked(format.urn())));
    }

    /// A persistent NameID configuration accepts neither an email-address
    /// request nor a transient-format request.
    #[test]
    fn a_request_for_another_format_is_not_answered() {
        let format = NameIdFormat::Persistent;

        assert!(!format.answers(&asked(NameIdFormat::EmailAddress.urn())));
        assert!(!format.answers(&asked(NameIdFormat::Transient.urn())));
    }

    /// A `NameID` with a line break inside it is refused, so it cannot
    /// split the document it is written into.
    #[test]
    fn a_name_id_value_with_a_line_break_is_refused() {
        assert!(SamlNameIdValue::new("ann\nbob").is_err());
        assert!(SamlNameIdValue::new("").is_err());
    }
}
