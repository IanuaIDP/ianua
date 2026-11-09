//! The name a record answers for.

use crate::message;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::DomainName;

text_value! {
    /// The name a record answers for.
    ///
    /// It is not a [`DomainName`]. A hostname may not hold an underscore, and
    /// `DomainName` refuses one. A DNS *owner* name may, and this type
    /// exists to carry the reserved `_` labels. Examples are
    /// `_acme-challenge` for a certificate challenge, `_dmarc` and
    /// `_domainkey` for mail, and `_sip._tcp` for a service.
    ///
    /// Letting `DomainName` accept them would weaken every hostname in the
    /// system for names that are not hostnames.
    #[derive(PartialOrd, Ord)]
    pub struct RecordName;
}

impl TextValue for RecordName {
    const FIELD: &'static str = "record_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .identifier(
                1..=253,
                Charset::LOWERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE
                    | Charset::ASTERISK,
            )
            .rule(&WellFormedLabels)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

impl RecordName {
    /// Whether this name is `apex` itself or sits beneath it.
    ///
    /// A zone answers only for the names inside it. A record for any other
    /// name belongs to another zone, and no resolver would ever ask us for
    /// it.
    #[must_use]
    pub fn is_within(&self, apex: &DomainName) -> bool {
        let apex = apex.as_str().to_ascii_lowercase();
        self.0 == apex || self.0.ends_with(&format!(".{apex}"))
    }

    /// Whether this name is the zone's own apex.
    #[must_use]
    pub fn is_apex_of(&self, apex: &DomainName) -> bool {
        self.0 == apex.as_str().to_ascii_lowercase()
    }

    /// The leftmost label, which is the only one a wildcard may occupy.
    fn first_label(&self) -> &str {
        self.0.split('.').next().unwrap_or(&self.0)
    }

    /// Whether this name matches every name beneath its parent.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.first_label() == "*"
    }

    /// The name one label up, or `None` at a single label.
    ///
    /// A resolver takes this step as it walks up to a zone's apex, looking
    /// for a wildcard or the closest name that exists.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0
            .split_once('.')
            .map(|(_, rest)| Self(rest.to_owned()))
    }

    /// Whether this name sits strictly beneath `ancestor`.
    ///
    /// It compares whole labels, not text. `notacme.com` is not beneath
    /// `acme.com`, though it ends in the same letters.
    #[must_use]
    pub fn is_beneath(&self, ancestor: &Self) -> bool {
        self.0
            .strip_suffix(&ancestor.0)
            .is_some_and(|above| above.ends_with('.'))
    }

    /// This name with its leftmost label replaced by `*`.
    ///
    /// It is the name a wildcard must have to answer for this one.
    #[must_use]
    pub fn as_wildcard(&self) -> Self {
        match self.parent() {
            Some(parent) => Self(format!("*.{}", parent.0)),
            None => Self("*".to_owned()),
        }
    }
}

impl From<&DomainName> for RecordName {
    /// Every hostname is a valid owner name, so this cannot fail.
    fn from(domain: &DomainName) -> Self {
        Self(domain.as_str().to_ascii_lowercase())
    }
}

/// No empty label, and a wildcard only as the whole leftmost label.
struct WellFormedLabels;

/// What is wrong with the labels of `name`, if anything.
fn label_problem(name: &str) -> Option<&'static str> {
    if name.split('.').any(str::is_empty) {
        return Some("has an empty label; check for a leading, trailing, or doubled dot");
    }
    let mut labels = name.split('.');
    let first = labels.next().unwrap_or_default();
    if labels.any(|label| label.contains('*')) {
        return Some("may hold a wildcard only as its leftmost label");
    }
    (first.contains('*') && first != "*")
        .then_some("may hold a wildcard only as a whole label, `*`; DNS has no partial wildcard")
}

impl Rule for WellFormedLabels {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let problem = label_problem(value)?;
        Some(ValidationError::Custom {
            field,
            code: "invalid_record_name".to_owned(),
            message: message!("tenant-message", format!("{field} {problem}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apex() -> DomainName {
        DomainName::new("auth.acme.com").unwrap()
    }

    /// `_acme-challenge.hello.acme.com` is a valid record name but not a
    /// valid hostname. A certificate authority reads DNS-01 from there, so
    /// the zone must accept it.
    #[test]
    fn an_underscore_label_is_a_valid_record_name() {
        let challenge = RecordName::new("_acme-challenge.hello.acme.com").unwrap();

        assert_eq!(challenge.as_str(), "_acme-challenge.hello.acme.com");
        assert!(
            DomainName::new("_acme-challenge.hello.acme.com").is_err(),
            "and is still refused as a hostname, which is the point"
        );
    }

    /// A tenant types `_ACME-Challenge.Hello.ACME.com`. It is stored in lower
    /// case, so one name never shows up as two.
    #[test]
    fn a_record_name_is_lowercased_on_the_way_in() {
        assert_eq!(
            RecordName::new("_ACME-Challenge.Hello.ACME.com")
                .unwrap()
                .as_str(),
            "_acme-challenge.hello.acme.com"
        );
    }

    /// Names with a leading, trailing or doubled dot are refused.
    #[test]
    fn a_name_with_an_empty_label_is_refused() {
        for bad in [".hello.acme.com", "hello.acme.com.", "hello..acme.com"] {
            assert!(
                RecordName::new(bad).is_err(),
                "{bad} should not parse as a record name"
            );
        }
    }

    /// Names holding a space, a slash or an `@` are refused.
    #[test]
    fn a_name_outside_the_dns_alphabet_is_refused() {
        for bad in ["hello acme.com", "hello/acme.com", "hello@acme.com"] {
            assert!(
                RecordName::new(bad).is_err(),
                "{bad} should not parse as a record name"
            );
        }
    }

    /// An empty string cannot become a DNS record name.
    #[test]
    fn an_empty_record_name_is_refused() {
        assert!(RecordName::new("").is_err());
    }

    /// `_acme-challenge.acme.com` reads from JSON and writes back the same.
    /// A mid-name wildcard and a doubled dot read from JSON are refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_record_name_read_from_json_is_validated() {
        let name: RecordName = serde_json::from_str("\"_acme-challenge.acme.com\"").unwrap();

        assert_eq!(
            serde_json::to_string(&name).unwrap(),
            "\"_acme-challenge.acme.com\""
        );
        assert!(serde_json::from_str::<RecordName>("\"api.*.acme.com\"").is_err());
        assert!(serde_json::from_str::<RecordName>("\"acme..com\"").is_err());
    }

    /// The hostname `hello.acme.com` converts to the same record name. Every
    /// hostname is a valid owner name.
    #[test]
    fn a_hostname_converts_to_a_record_name() {
        let hostname = DomainName::new("hello.acme.com").unwrap();

        assert_eq!(RecordName::from(&hostname).as_str(), "hello.acme.com");
    }

    /// `*.auth.acme.com` reads as a wildcard and `auth.acme.com` does not.
    #[test]
    fn a_leftmost_asterisk_is_a_wildcard() {
        assert!(RecordName::new("*.auth.acme.com").unwrap().is_wildcard());
        assert!(!RecordName::new("auth.acme.com").unwrap().is_wildcard());
    }

    /// `api.*.acme.com` is refused. DNS matches a wildcard only at the
    /// leftmost label, so anywhere else it is an asterisk nobody asks for.
    #[test]
    fn a_wildcard_anywhere_but_the_leftmost_label_is_refused() {
        assert!(RecordName::new("api.*.acme.com").is_err());
    }

    /// `*api.auth.acme.com` is refused. A `*` matches only a whole label, so
    /// `*api` would be a plain name with an asterisk in it.
    #[test]
    fn a_partial_wildcard_label_is_refused() {
        assert!(RecordName::new("*api.auth.acme.com").is_err());
    }

    /// The zone `auth.acme.com` holds itself and names one or two labels
    /// beneath it.
    #[test]
    fn a_name_inside_the_zone_is_within_it() {
        for inside in ["auth.acme.com", "api.auth.acme.com", "a.b.auth.acme.com"] {
            assert!(
                RecordName::new(inside).unwrap().is_within(&apex()),
                "{inside} is inside the zone"
            );
        }
    }

    /// A zone does not contain its parent, a sibling, an unrelated domain or
    /// a name that merely shares its ending letters.
    #[test]
    fn a_name_outside_the_zone_is_not_within_it() {
        for outside in ["acme.com", "other.acme.com", "evil.com", "notauth.acme.com"] {
            assert!(
                !RecordName::new(outside).unwrap().is_within(&apex()),
                "{outside} is outside the zone"
            );
        }
    }

    /// The parent of `a.b.auth.acme.com` is `b.auth.acme.com`.
    #[test]
    fn a_parent_drops_the_leftmost_label() {
        let name = RecordName::new("a.b.auth.acme.com").unwrap();

        assert_eq!(name.parent().unwrap().as_str(), "b.auth.acme.com");
    }

    /// `localhost` is one label and has no parent.
    #[test]
    fn a_single_label_has_no_parent() {
        assert!(RecordName::new("localhost").unwrap().parent().is_none());
    }

    /// Walking up from `a.b.c.d.acme.com` ends at `com` in a few steps. So a
    /// resolver's search for a wildcard always finishes.
    #[test]
    fn walking_up_from_any_name_reaches_a_single_label() {
        let mut name = RecordName::new("a.b.c.d.acme.com").unwrap();
        let mut steps = 0;

        while let Some(parent) = name.parent() {
            name = parent;
            steps += 1;
            assert!(steps < 10, "walking up did not terminate");
        }

        assert_eq!(name.as_str(), "com");
    }

    /// Names one and two labels under `auth.acme.com` are beneath it.
    /// `auth.acme.com` is not beneath itself.
    #[test]
    fn a_name_is_beneath_its_ancestors_but_not_itself() {
        let apex = RecordName::new("auth.acme.com").unwrap();

        assert!(
            RecordName::new("api.auth.acme.com")
                .unwrap()
                .is_beneath(&apex)
        );
        assert!(
            RecordName::new("a.b.auth.acme.com")
                .unwrap()
                .is_beneath(&apex)
        );
        assert!(!apex.is_beneath(&apex));
    }

    /// Names sharing only the letters at the start or end of `acme.com` are
    /// not descendants of that domain.
    #[test]
    fn a_name_sharing_only_a_prefix_is_not_beneath_it() {
        let apex = RecordName::new("acme.com").unwrap();

        assert!(
            !RecordName::new("acme.com.evil.example")
                .unwrap()
                .is_beneath(&apex)
        );
        assert!(!RecordName::new("notacme.com").unwrap().is_beneath(&apex));
    }

    /// The wildcard for `api.auth.acme.com` is `*.auth.acme.com`.
    #[test]
    fn a_names_wildcard_replaces_its_leftmost_label() {
        assert_eq!(
            RecordName::new("api.auth.acme.com")
                .unwrap()
                .as_wildcard()
                .as_str(),
            "*.auth.acme.com"
        );
    }

    /// `auth.acme.com` is the apex of its zone. `api.auth.acme.com` is not.
    #[test]
    fn only_the_zones_own_hostname_is_its_apex() {
        assert!(
            RecordName::new("auth.acme.com")
                .unwrap()
                .is_apex_of(&apex())
        );
        assert!(
            !RecordName::new("api.auth.acme.com")
                .unwrap()
                .is_apex_of(&apex())
        );
    }

    /// `api.auth.acme.com` prints as itself. Zone files and the logs an
    /// operator reads show this text.
    #[test]
    fn a_name_displays_as_the_name_it_holds() {
        assert_eq!(
            RecordName::new("api.auth.acme.com").unwrap().to_string(),
            "api.auth.acme.com"
        );
    }
}
