//! Parameter rules: which hosts a route's URL parameters may name.
//!
//! A service that fetches what it is told to gets past every other control.
//! The agent names a destination, and the request leaves from the service.
//! The egress gateway stops the second hop, and this module stops the first.
//! A route that takes a URL or a host name declares which parameter carries
//! it and which hosts it may name.
//!
//! An agent request is refused before it reaches the service when it names
//! any other host, encodes one oddly, or carries a URL in a field no rule
//! covers.

mod address;
mod screening;

use address::host_of;
pub use screening::*;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::shared::web::parameter_key::ParameterKey;
use crate::types::DomainName;

/// Whether a route's service goes only where it was built to, or where it
/// is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RouteReach {
    /// The service reaches only what it was built to.
    #[default]
    Fixed,
    /// The service fetches whatever URL or host it is given. Every request to
    /// it is a message to somewhere the caller chooses, so it is judged as
    /// communicating. An agent may call it only within parameter rules, or
    /// with a person's approval for each call.
    OpenEnded,
}

impl RouteReach {
    /// The stored form, `fixed` or `open_ended`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::OpenEnded => "open_ended",
        }
    }

    /// Parses the stored form.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for an unknown value. A stored reach
    ///   that does not parse is corrupt data.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "fixed" => Ok(Self::Fixed),
            "open_ended" => Ok(Self::OpenEnded),
            _ => Err(DomainError::corrupt_row(
                "route",
                "an unknown parameter reach",
            )),
        }
    }
}

/// Whether every call an agent makes to a route needs a person's approval.
///
/// That is so for an open-ended route with no parameter rules. Without
/// approval, it would take the agent anywhere it names.
#[must_use]
pub fn needs_approval_for_agents(reach: RouteReach, rules: &[ParameterRule]) -> bool {
    reach == RouteReach::OpenEnded && rules.is_empty()
}

/// The most hosts one rule may allow.
pub(crate) const MAX_ALLOWED_HOSTS: usize = 32;

/// Where a parameter is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ParameterLocation {
    /// In the query string.
    Query,
    /// A top-level field of a JSON object body.
    JsonBody,
    /// A part of the path the route's pattern captures. That is a `{name}`
    /// placeholder, or `rest` for a trailing `/*`.
    Path,
    /// A request header.
    Header,
}

/// Headers the proxy reads or replaces itself. What a client sends in them
/// never reaches the upstream as a parameter. They carry its credentials,
/// its proof of key, its cookies and the host it asked for.
const CONSUMED_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "dpop",
    "cookie",
    "host",
];

/// One declared URL or host parameter and the hosts it may name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ParameterRuleWire"))]
pub struct ParameterRule {
    name: ParameterName,
    location: ParameterLocation,
    allowed_hosts: Vec<DomainName>,
}

/// The stored shape of a [`ParameterRule`], before validation.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
pub(crate) struct ParameterRuleWire {
    name: String,
    location: ParameterLocation,
    allowed_hosts: Vec<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<ParameterRuleWire> for ParameterRule {
    type Error = DomainError;

    fn try_from(wire: ParameterRuleWire) -> Result<Self, Self::Error> {
        let hosts = wire
            .allowed_hosts
            .into_iter()
            .map(|h| DomainName::new(h).map_err(DomainError::from))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(wire.name, wire.location, hosts)
    }
}

impl ParameterRule {
    /// A checked rule.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a name that is not a
    ///   [`ParameterName`].
    /// - [`DomainError::Validation`] for no hosts, or more than
    ///   `MAX_ALLOWED_HOSTS`.
    /// - [`DomainError::Validation`] for a wildcard host.
    pub fn new(
        name: impl Into<String>,
        location: ParameterLocation,
        allowed_hosts: Vec<DomainName>,
    ) -> Result<Self, DomainError> {
        let name = ParameterName::new(name)?;
        validate_count("allowed_hosts", allowed_hosts.len(), 1..=MAX_ALLOWED_HOSTS)?;
        if allowed_hosts.iter().any(DomainName::is_wildcard) {
            return Err(DomainError::invalid(message!(
                "routing-a-parameter-rule-names-hosts-exactly",
                "a parameter rule names hosts exactly; wildcards are not accepted"
            )));
        }
        Ok(Self {
            name,
            location,
            allowed_hosts,
        })
    }

    /// The parameter's name.
    #[must_use]
    pub fn name(&self) -> &ParameterName {
        &self.name
    }

    /// Where it is carried.
    #[must_use]
    pub fn location(&self) -> ParameterLocation {
        self.location
    }

    /// The hosts it may name.
    #[must_use]
    pub fn allowed_hosts(&self) -> &[DomainName] {
        &self.allowed_hosts
    }

    fn admits(&self, value: &str) -> bool {
        host_of(value).is_some_and(|host| {
            self.allowed_hosts
                .iter()
                .any(|allowed| allowed.as_str().eq_ignore_ascii_case(&host))
        })
    }

    /// Whether this rule screens the parameter `name` at `location`, under
    /// any spelling a server reads as the same name.
    fn screens(&self, location: ParameterLocation, name: &ParameterKey) -> bool {
        self.location == location && ParameterKey::written(self.name.as_str()) == *name
    }
}

/// The rule screening `name` at `location`, if one does.
fn rule_for<'a>(
    rules: &'a [ParameterRule],
    location: ParameterLocation,
    name: &str,
) -> Option<&'a ParameterRule> {
    let key = ParameterKey::written(name);
    rules.iter().find(|rule| rule.screens(location, &key))
}

text_value! {
    /// The name of a request parameter a rule screens. It holds letters,
    /// digits, `_`, `-` and `.`.
    pub struct ParameterName;
}

impl TextValue for ParameterName {
    const FIELD: &'static str = "parameter";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=64,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::UNDERSCORE
                | Charset::HYPHEN
                | Charset::DOT,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UntrustedText;

    fn rule(name: &str, location: ParameterLocation, hosts: &[&str]) -> ParameterRule {
        ParameterRule::new(
            name,
            location,
            hosts.iter().map(|h| DomainName::new(*h).unwrap()).collect(),
        )
        .unwrap()
    }

    const NO_BODY: BodyFields = BodyFields::None;

    fn query(q: &str) -> RequestParameters<'_> {
        RequestParameters {
            query: RawQuery::Present(q),
            body: &NO_BODY,
            captured: &[],
            headers: &[],
        }
    }

    fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// An allowed query URL does not permit an undeclared address in a path
    /// capture or header. Screening refuses both requests.
    #[test]
    fn an_address_in_a_path_capture_or_header_is_refused() {
        let captured = owned(&[("rest", "evil.net/x")]);
        let headers = owned(&[("X-Target", "evil.net")]);

        let in_path = RequestParameters {
            captured: &captured,
            ..query("url=https://docs.example.com/")
        };
        let in_header = RequestParameters {
            headers: &headers,
            ..query("url=https://docs.example.com/")
        };

        assert!(check(&fetch(), &in_path).is_err());
        assert!(check(&fetch(), &in_header).is_err());
    }

    /// Rules declare a path capture `host` and a header `x-target`. Both
    /// naming `docs.example.com` pass, and a path naming `evil.net` is
    /// refused.
    #[test]
    fn a_declared_path_capture_or_header_names_a_listed_host() {
        let rules = vec![
            rule("host", ParameterLocation::Path, &["docs.example.com"]),
            rule("x-target", ParameterLocation::Header, &["docs.example.com"]),
        ];
        let captured = owned(&[("host", "docs.example.com")]);
        let headers = owned(&[("X-Target", "https://docs.example.com/")]);
        let elsewhere = owned(&[("host", "evil.net")]);

        let allowed = RequestParameters {
            query: RawQuery::Absent,
            body: &NO_BODY,
            captured: &captured,
            headers: &headers,
        };
        let refused = RequestParameters {
            captured: &elsewhere,
            ..allowed
        };

        assert!(check(&rules, &allowed).is_ok());
        assert!(check(&rules, &refused).is_err());
    }

    /// A request carries `Authorization`, `DPoP` and `Cookie` headers whose
    /// tokens look like dotted names. They are not screened, since the proxy
    /// reads them itself, and the request passes.
    #[test]
    fn headers_the_proxy_consumes_are_not_screened() {
        let headers = owned(&[
            ("Authorization", "Bearer aaa.bbb.ccc"),
            ("DPoP", "aaa.bbb.ccc"),
            ("Cookie", "session=aaa.bbb"),
        ]);
        let request = RequestParameters {
            headers: &headers,
            ..query("url=https://docs.example.com/")
        };

        assert!(check(&fetch(), &request).is_ok());
    }

    fn fields(pairs: &[(&str, &str)]) -> BodyFields {
        BodyFields::Fields(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), BodyValue::Text((*v).to_owned())))
                .collect(),
        )
    }

    fn text(value: &str) -> BodyValue {
        BodyValue::Text(value.to_owned())
    }

    fn body(fields: &BodyFields) -> RequestParameters<'_> {
        RequestParameters {
            query: RawQuery::Absent,
            body: fields,
            captured: &[],
            headers: &[],
        }
    }

    fn fetch() -> Vec<ParameterRule> {
        vec![rule("url", ParameterLocation::Query, &["docs.example.com"])]
    }

    /// A route with no parameter rules gets `url=https://anywhere.gov/`. It
    /// passes, since there is nothing to screen against.
    #[test]
    fn a_route_without_rules_passes_everything() {
        assert!(check(&[], &query("url=https://anywhere.gov/")).is_ok());
    }

    /// A listed host passes when encoded or differently cased. Other hosts,
    /// lookalike suffixes, userinfo forms, a metadata address and a file URL
    /// are refused.
    #[test]
    fn a_listed_host_passes_and_any_other_is_refused() {
        assert!(check(&fetch(), &query("url=https%3A%2F%2Fdocs.example.com%2Fa")).is_ok());
        assert!(check(&fetch(), &query("url=https://DOCS.example.com/a")).is_ok());
        assert_eq!(
            check(&fetch(), &query("url=https://www.gov.example/")),
            Err(ParameterViolation::HostNotAllowed(UntrustedText::record(
                "url"
            )))
        );
        assert!(check(&fetch(), &query("url=https://docs.example.com.evil.net/")).is_err());
        assert!(check(&fetch(), &query("url=https://docs.example.com@evil.net/")).is_err());
        assert!(check(&fetch(), &query("url=http://169.254.169.254/")).is_err());
        assert!(check(&fetch(), &query("url=file:///etc/passwd")).is_err());
    }

    /// A double-encoded URL reports odd encoding. Encoded control characters
    /// and a malformed escape are also refused.
    #[test]
    fn double_encoding_and_control_characters_are_refused() {
        assert_eq!(
            check(&fetch(), &query("url=https%253A%252F%252Fevil.net")),
            Err(ParameterViolation::OddEncoding(UntrustedText::record(
                "url"
            )))
        );
        assert!(
            check(
                &fetch(),
                &query("url=https://docs.example.com%0d%0aHost:evil")
            )
            .is_err()
        );
        assert!(check(&fetch(), &query("url=%zz")).is_err());
    }

    /// An extra address-bearing query field is reported by name as undeclared.
    /// Ordinary page and search values pass beside the allowed URL.
    #[test]
    fn an_address_in_a_field_no_rule_covers_is_refused() {
        assert_eq!(
            check(
                &fetch(),
                &query("url=https://docs.example.com/&next=https://evil.net")
            ),
            Err(ParameterViolation::Undeclared(UntrustedText::record(
                "next"
            )))
        );
        assert!(
            check(
                &fetch(),
                &query("url=https://docs.example.com/&page=2&q=rust")
            )
            .is_ok()
        );
    }

    /// IPv4 and IPv6 addresses, including forms with ports, are refused in
    /// an undeclared body field.
    #[test]
    fn an_ip_address_in_a_field_no_rule_covers_is_refused() {
        for value in [
            "169.254.169.254",
            "10.0.0.5:8080",
            "[::1]",
            "[fd00::1]:443",
            "::1",
        ] {
            let fields = fields(&[("target", value)]);

            assert!(
                matches!(
                    check(&fetch(), &body(&fields)),
                    Err(ParameterViolation::Undeclared(_))
                ),
                "{value}"
            );
        }
    }

    /// The rule for `url` applies to its encoded query name and refuses an
    /// unlisted destination.
    #[test]
    fn an_encoded_query_name_meets_the_rule_for_it() {
        let rules = vec![rule("url", ParameterLocation::Query, &["api.example.com"])];

        let result = check(&rules, &query("ur%6c=https://evil.example"));

        assert!(matches!(result, Err(ParameterViolation::HostNotAllowed(_))));
    }

    /// An undeclared field name containing a newline produces a refusal
    /// reason without that line break.
    #[test]
    fn a_refusal_cannot_forge_a_log_line_through_a_field_name() {
        let forged = fields(&[
            ("url", "https://docs.example.com/"),
            ("x\nlevel=INFO msg=allowed", "https://evil.net"),
        ]);

        let Err(violation) = check(&fetch_from_body(), &body(&forged)) else {
            panic!("the field should have been refused");
        };

        assert!(!violation.reason().contains('\n'));
    }

    fn fetch_from_body() -> Vec<ParameterRule> {
        vec![rule(
            "url",
            ParameterLocation::JsonBody,
            &["docs.example.com"],
        )]
    }

    /// A body field `target` may name `api.example.com`. An allowed body
    /// passes, while another host in `target` or `evil.net` in a second field
    /// is refused.
    #[test]
    fn body_fields_are_checked_whole() {
        let rules = vec![rule(
            "target",
            ParameterLocation::JsonBody,
            &["api.example.com"],
        )];

        let listed = fields(&[("target", "https://api.example.com/x"), ("n", "1")]);
        let elsewhere = fields(&[("target", "https://evil.net/")]);
        let smuggled = fields(&[("target", "https://api.example.com"), ("cb", "evil.net")]);
        assert!(check(&rules, &body(&listed)).is_ok());
        assert!(check(&rules, &body(&elsewhere)).is_err());
        assert!(check(&rules, &body(&smuggled)).is_err());
    }

    /// Screening reports an unreadable body when a body parameter rule is set.
    #[test]
    fn a_body_that_cannot_be_read_whole_is_refused() {
        let rules = vec![rule(
            "target",
            ParameterLocation::JsonBody,
            &["api.example.com"],
        )];

        assert_eq!(
            check(&rules, &body(&BodyFields::Unreadable)),
            Err(ParameterViolation::BodyUnreadable)
        );
    }

    /// A rule with a wildcard host, with no hosts, or with the name `u rl`
    /// is refused.
    #[test]
    fn a_rule_names_exact_hosts() {
        assert!(
            ParameterRule::new(
                "url",
                ParameterLocation::Query,
                vec![DomainName::new("*.example.com").unwrap()]
            )
            .is_err()
        );
        assert!(ParameterRule::new("url", ParameterLocation::Query, vec![]).is_err());
        assert!(
            ParameterRule::new(
                "u rl",
                ParameterLocation::Query,
                vec![DomainName::new("example.com").unwrap()]
            )
            .is_err()
        );
    }

    /// `redirect_uri` and `next` are accepted as parameter names.
    #[test]
    fn a_well_formed_parameter_name_is_accepted() {
        for value in ["redirect_uri", "next"] {
            assert!(ParameterName::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty name, `a b` and `a/b` are refused as parameter names.
    #[test]
    fn a_malformed_parameter_name_is_refused() {
        for value in ["", "a b", "a/b"] {
            assert!(ParameterName::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// Address spellings that must not bypass an undeclared-field check.
    const UNDECLARED_ADDRESSES: &[&str] = &[
        "localhost",
        "localhost:8080",
        "redis:6379",
        "evil.net",
        "evil.net.",
        "evil.net:443",
        "127.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "https:evil.net",
        "https:/evil.net",
        "https:\\\\evil.net",
        "\\\\evil.net\\share",
        "https%3A%2F%2Fevil.net",
        "evil\u{3002}net",
        "evil.net/steal",
        "evil.net?x=1",
        "evil.net#x",
        "evil.net:",
        "evil.net:443/x",
        "my_svc.internal",
        "\u{FF45}\u{FF56}\u{FF49}\u{FF4C}.\u{FF43}\u{FF4F}\u{FF4D}",
        "b\u{FC}cher.de",
        "127.1/latest/meta-data",
        "10.0.0.5:8080/admin",
        "/\\evil.net",
        "\\/evil.net",
        "/\t/evil.net",
        "/\n/evil.net",
        "\u{1}//evil.net",
        " //evil.net",
    ];

    /// Undeclared fields reject address forms including internal names,
    /// shortened or hexadecimal IPs, unusual slashes, encoded URLs and
    /// internationalized names.
    #[test]
    fn every_spelling_of_an_address_in_an_undeclared_field_is_refused() {
        for &value in UNDECLARED_ADDRESSES {
            let sent = fields(&[("url", "https://docs.example.com/"), ("next", value)]);

            assert!(
                check(&fetch_from_body(), &body(&sent)).is_err(),
                "{value:?} passed"
            );
        }
    }

    /// An undeclared field `note` holds a word, an id, a sentence, a
    /// percentage, a version tag or an email address. Each passes, since none
    /// is an address a service would fetch.
    #[test]
    fn ordinary_values_in_an_undeclared_field_pass() {
        for value in [
            "rust",
            "123456789",
            "a sentence, with: punctuation",
            "50%",
            "v1-beta",
            "alice@corp.example",
        ] {
            let sent = fields(&[("url", "https://docs.example.com/"), ("note", value)]);

            assert!(
                check(&fetch_from_body(), &body(&sent)).is_ok(),
                "{value:?} was refused"
            );
        }
    }

    /// A metadata URL nested inside an object's list is refused as undeclared.
    #[test]
    fn an_address_nested_in_a_body_value_is_refused() {
        let nested = BodyFields::Fields(vec![
            ("url".to_owned(), text("https://docs.example.com/")),
            (
                "options".to_owned(),
                BodyValue::Object(vec![(
                    "mirrors".to_owned(),
                    BodyValue::List(vec![text("rust"), text("http://169.254.169.254/")]),
                )]),
            ),
        ]);

        assert!(matches!(
            check(&fetch_from_body(), &body(&nested)),
            Err(ParameterViolation::Undeclared(_))
        ));
    }

    /// Duplicate body keys are refused both at the top level and inside a
    /// nested object.
    #[test]
    fn a_body_naming_a_key_twice_is_refused() {
        let twice = BodyFields::Fields(vec![
            ("url".to_owned(), text("https://docs.example.com/")),
            ("url".to_owned(), text("https://evil.net/")),
        ]);
        let nested_twice = BodyFields::Fields(vec![
            ("url".to_owned(), text("https://docs.example.com/")),
            (
                "o".to_owned(),
                BodyValue::Object(vec![
                    ("k".to_owned(), text("a")),
                    ("k".to_owned(), text("b")),
                ]),
            ),
        ]);

        assert!(matches!(
            check(&fetch_from_body(), &body(&twice)),
            Err(ParameterViolation::DuplicateField(_))
        ));
        assert!(matches!(
            check(&fetch_from_body(), &body(&nested_twice)),
            Err(ParameterViolation::DuplicateField(_))
        ));
    }

    /// A declared URL list containing an allowed host and an unlisted host
    /// reports a disallowed host.
    #[test]
    fn every_entry_of_a_declared_field_must_be_allowed() {
        let list = BodyFields::Fields(vec![(
            "url".to_owned(),
            BodyValue::List(vec![
                text("https://docs.example.com/"),
                text("https://evil.net/"),
            ]),
        )]);

        assert!(matches!(
            check(&fetch_from_body(), &body(&list)),
            Err(ParameterViolation::HostNotAllowed(_))
        ));
    }

    /// Address-like dotted numbers are refused in undeclared fields, while
    /// the integer page value `42` passes.
    #[test]
    fn a_dotted_number_in_an_undeclared_field_is_refused() {
        for written in ["169.16689662", "127.1", "10.1"] {
            let sent = BodyFields::Fields(vec![
                ("url".to_owned(), text("https://docs.example.com/")),
                ("mirror".to_owned(), BodyValue::Number(written.to_owned())),
            ]);

            assert!(
                matches!(
                    check(&fetch_from_body(), &body(&sent)),
                    Err(ParameterViolation::Undeclared(_))
                ),
                "{written} passed"
            );
        }

        let id = BodyFields::Fields(vec![
            ("url".to_owned(), text("https://docs.example.com/")),
            ("page".to_owned(), BodyValue::Number("42".to_owned())),
        ]);
        assert!(check(&fetch_from_body(), &body(&id)).is_ok());
    }

    /// Case variants, semicolon-separated, bracketed and encoded query keys
    /// all meet the host rule and reject unlisted hosts. An allowed host
    /// passes under an uppercase key.
    #[test]
    fn a_declared_query_parameter_is_judged_under_every_spelling() {
        let rules = vec![rule("host", ParameterLocation::Query, &["api.partner.com"])];

        for sent in [
            "HOST=redis",
            "Host=metadata",
            "x=1;host=evil.net",
            "host[]=redis",
            "host[0]=redis",
            "ho%73t=redis",
        ] {
            assert!(
                matches!(
                    check(&rules, &query(sent)),
                    Err(ParameterViolation::HostNotAllowed(_))
                ),
                "{sent:?} passed"
            );
        }
        assert!(check(&rules, &query("HOST=api.partner.com")).is_ok());
    }

    /// The lowercase URL rule applies to an uppercase body key and refuses
    /// its unlisted host.
    #[test]
    fn a_declared_body_field_is_judged_under_any_case() {
        let sent = fields(&[("URL", "redis")]);

        assert!(matches!(
            check(&fetch_from_body(), &body(&sent)),
            Err(ParameterViolation::HostNotAllowed(_))
        ));
    }

    /// A declared URL field rejects an object keyed by a URL, an empty list
    /// and an empty object as values that name no allowed host.
    #[test]
    fn a_declared_field_must_name_an_allowed_host_and_nothing_else() {
        let in_a_key = BodyFields::Fields(vec![(
            "url".to_owned(),
            BodyValue::Object(vec![(
                "https://evil.net/".to_owned(),
                BodyValue::List(vec![]),
            )]),
        )]);
        let empty_list = BodyFields::Fields(vec![("url".to_owned(), BodyValue::List(vec![]))]);
        let empty_object = BodyFields::Fields(vec![("url".to_owned(), BodyValue::Object(vec![]))]);

        for sent in [&in_a_key, &empty_list, &empty_object] {
            assert!(
                matches!(
                    check(&fetch_from_body(), &body(sent)),
                    Err(ParameterViolation::HostNotAllowed(_))
                ),
                "{sent:?} passed"
            );
        }
    }

    /// A body field is nested 100,000 lists deep. It is walked without
    /// running out of stack, and the request passes.
    #[test]
    fn a_deeply_nested_body_is_checked_without_recursion() {
        let mut deep = text("rust");
        for _ in 0..100_000 {
            deep = BodyValue::List(vec![deep]);
        }
        let body_fields = BodyFields::Fields(vec![
            ("url".to_owned(), text("https://docs.example.com/")),
            ("deep".to_owned(), deep),
        ]);

        assert!(check(&fetch_from_body(), &body(&body_fields)).is_ok());
    }
}
