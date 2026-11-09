//! XML text shared by the documents this platform writes.

use time::format_description::well_known::Iso8601;
use time::{OffsetDateTime, UtcOffset};

use crate::message;
use crate::shared::errors::DomainError;

/// Escapes the characters XML reserves, for attribute values and text.
pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Writes `at` the way SAML writes every time: an `xs:dateTime` in UTC.
///
/// `what` names the time in the refusal. A time that cannot be written is
/// refused rather than left empty, since an empty `NotOnOrAfter` reads to
/// some service providers as no end at all.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `at`, moved to UTC, falls outside the
///   years 0 to 9999, which this form cannot write.
pub(crate) fn xml_date_time(what: &str, at: OffsetDateTime) -> Result<String, DomainError> {
    at.checked_to_offset(UtcOffset::UTC)
        .and_then(|utc| utc.format(&Iso8601::DEFAULT).ok())
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "federation-the-cannot-be-written-as-a",
                format!("the {what} cannot be written as a SAML time")
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sign-in at 10:00 in Berlin, an hour ahead of UTC, is written as
    /// 09:00 UTC. SAML takes times only in UTC.
    #[test]
    fn a_time_is_written_in_utc() {
        let berlin = UtcOffset::from_hms(1, 0, 0).unwrap();
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .to_offset(berlin);

        let written = xml_date_time("sign-in time", at).unwrap();

        let utc = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(written, utc.format(&Iso8601::DEFAULT).unwrap());
    }

    /// A date before year zero fails SAML time formatting with a
    /// validation error.
    #[test]
    fn a_time_outside_the_years_saml_writes_is_refused() {
        let at = time::Date::from_calendar_date(-1, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc();

        let written = xml_date_time("sign-in time", at);

        assert!(matches!(written, Err(DomainError::Validation(_))));
    }
}
