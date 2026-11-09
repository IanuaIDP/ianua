//! What a record answers with: its rdata, one type per record kind.
//!
//! Every value knows how a zone file spells it and how to read that spelling
//! back. Storage keeps the spelling, not a column per field. The rdata shape
//! differs per type, and a table wide enough for all of them would be mostly
//! null. That is safe only if the spelling reads back to the same value, so
//! every type here is tested for it.

use crate::domains::tenant::custom_domains::dns_zone::kind::RecordKind;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{DomainName, IpAddress};

text_value! {
    /// Free text, as `TXT` carries it.
    ///
    /// It is not a [`Text`](crate::types::Text). That type stops at 500
    /// characters, which suits a reason a person writes. A 4096-bit `DKIM`
    /// public key is longer, and tenants need to publish one.
    ///
    /// A resolver sees this as one or more 255-byte strings. The nameserver
    /// splits it into those, not the tenant.
    pub struct TxtValue;
}

impl TextValue for TxtValue {
    const FIELD: &'static str = "txt_value";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .max_bytes(Self::MAX_BYTES)
            .no_control_chars()
    }
}

impl TxtValue {
    /// The longest string we hold, in bytes. It fits a 4096-bit `DKIM` key
    /// with room to spare, and stays well short of what a resolver refuses.
    const MAX_BYTES: usize = 2048;
}

/// Where mail for a name goes, and in what order.
///
/// A lower `priority` is tried first. The number is a rank, not a weight.
/// That direction surprises people, so the field has a name of its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MailExchange {
    priority: u16,
    host: DomainName,
}

impl MailExchange {
    /// The rdata of an `MX` record.
    #[must_use]
    pub fn new(priority: u16, host: DomainName) -> Self {
        Self { priority, host }
    }

    /// The rank. Lower is tried first.
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// The host that accepts the mail.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }
}

/// Where a named service runs, and how clients should spread across it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceTarget {
    priority: u16,
    weight: u16,
    port: u16,
    host: DomainName,
}

impl ServiceTarget {
    /// The rdata of an `SRV` record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `port` is zero. RFC 2782 reads port
    ///   zero as "this service is not offered". A tenant who forgot the port
    ///   does not mean that.
    pub fn new(
        priority: u16,
        weight: u16,
        port: u16,
        host: DomainName,
    ) -> Result<Self, DomainError> {
        validate_range("srv_port", port, 1..=u16::MAX)?;

        Ok(Self {
            priority,
            weight,
            port,
            host,
        })
    }

    /// The rank. Lower is tried first.
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// The share of traffic among targets of equal priority.
    #[must_use]
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// The port the service listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host running the service.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }
}

/// Which property of certificate issuance a `CAA` record states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaaTag {
    /// Authorises an issuer for this exact name.
    Issue,
    /// Authorises an issuer for wildcards beneath this name.
    IssueWild,
    /// Where to report an issuance the policy forbids.
    Iodef,
}

impl CaaTag {
    /// Every tag, in the order a zone file lists them.
    pub const ALL: [Self; 3] = [Self::Issue, Self::IssueWild, Self::Iodef];

    /// The tag as a zone file spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::IssueWild => "issuewild",
            Self::Iodef => "iodef",
        }
    }

    /// The tag a zone file spelling names, in any case and with spaces
    /// trimmed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when no tag has that spelling. The
    ///   message lists the tags that exist.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let lower = value.trim().to_ascii_lowercase();

        Self::ALL
            .into_iter()
            .find(|tag| tag.as_str() == lower)
            .ok_or_else(|| {
                let known = Self::ALL.map(Self::as_str).join(", ");
                DomainError::invalid(message!(
                    "tenant-unknown-caa-tag-expected-one-of",
                    format!("unknown CAA tag '{value}'; expected one of {known}")
                ))
            })
    }
}

/// What an issuer does with a CAA property whose tag it does not understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaaHandling {
    /// It must stop issuing.
    Critical,
    /// It may ignore the property.
    NonCritical,
}

/// One statement about who may issue certificates for a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaaProperty {
    handling: CaaHandling,
    tag: CaaTag,
    value: TxtValue,
}

impl CaaProperty {
    /// The flags byte a critical property carries. Bit 0 is the only bit
    /// RFC 8659 defines, and it is the high-order one.
    const CRITICAL_FLAG: u8 = 128;

    /// One `CAA` statement.
    ///
    /// When it is critical, an issuer that does not understand the tag must
    /// stop issuing instead of ignoring it.
    #[must_use]
    pub fn new(handling: CaaHandling, tag: CaaTag, value: TxtValue) -> Self {
        Self {
            handling,
            tag,
            value,
        }
    }

    /// What an issuer does with this property when it cannot read its tag.
    #[must_use]
    pub fn handling(&self) -> CaaHandling {
        self.handling
    }

    /// Whether an issuer must refuse rather than ignore a tag it cannot read.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.handling == CaaHandling::Critical
    }

    /// Which property this states.
    #[must_use]
    pub fn tag(&self) -> CaaTag {
        self.tag
    }

    /// The property's value: an issuer domain or a reporting address.
    #[must_use]
    pub fn value(&self) -> &TxtValue {
        &self.value
    }

    /// The flags byte as a zone file spells it.
    #[must_use]
    fn flags(&self) -> u8 {
        match self.handling {
            CaaHandling::Critical => Self::CRITICAL_FLAG,
            CaaHandling::NonCritical => 0,
        }
    }

    /// The handling a flags byte stands for.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for any value other than the two RFC
    ///   8659 defines, 0 and 128. Guessing at an undefined bit would put a
    ///   policy on a name that nobody wrote.
    fn handling_from_flags(flags: u8) -> Result<CaaHandling, DomainError> {
        match flags {
            0 => Ok(CaaHandling::NonCritical),
            Self::CRITICAL_FLAG => Ok(CaaHandling::Critical),
            other => Err(DomainError::invalid(message!(
                "tenant-caa-flags-must-be-0-or",
                format!(
                    "caa_flags must be 0 or {}, got {other}",
                    Self::CRITICAL_FLAG
                )
            ))),
        }
    }
}

/// What a record answers with.
///
/// There is one variant per [`RecordKind`], so a value cannot disagree with
/// its type. `A` and `AAAA` share [`RecordValue::Address`], because the
/// address itself says which family it is. Two variants would let the
/// address and the declared type contradict each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordValue {
    /// An IPv4 or IPv6 address, for `A` and `AAAA`.
    Address(IpAddress),
    /// The name this name is an alias for, for `CNAME`.
    Alias(DomainName),
    /// Free text, for `TXT`.
    Text(TxtValue),
    /// Where mail goes, for `MX`.
    Mail(MailExchange),
    /// Where a service runs, for `SRV`.
    Service(ServiceTarget),
    /// Who may issue certificates, for `CAA`.
    Authority(CaaProperty),
}

impl RecordValue {
    /// The record type this value answers as.
    #[must_use]
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Address(address) if address.is_ipv6() => RecordKind::Aaaa,
            Self::Address(_) => RecordKind::A,
            Self::Alias(_) => RecordKind::Cname,
            Self::Text(_) => RecordKind::Txt,
            Self::Mail(_) => RecordKind::Mx,
            Self::Service(_) => RecordKind::Srv,
            Self::Authority(_) => RecordKind::Caa,
        }
    }

    /// The value as a zone file spells it.
    ///
    /// Storage holds this text and [`RecordValue::parse`] reads it back to
    /// the same value, for every type.
    #[must_use]
    pub fn as_presentation(&self) -> String {
        match self {
            Self::Address(address) => address.as_str().to_owned(),
            Self::Alias(host) => host.as_str().to_owned(),
            Self::Text(text) => text.as_str().to_owned(),
            Self::Mail(mail) => format!("{} {}", mail.priority(), mail.host().as_str()),
            Self::Service(service) => format!(
                "{} {} {} {}",
                service.priority(),
                service.weight(),
                service.port(),
                service.host().as_str()
            ),
            Self::Authority(caa) => format!(
                "{} {} \"{}\"",
                caa.flags(),
                caa.tag().as_str(),
                caa.value().as_str()
            ),
        }
    }

    /// The value of `kind` that a zone file spelling names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the spelling does not parse as
    ///   `kind`. Examples are a malformed address, the wrong number of `SRV`
    ///   fields or an unknown `CAA` tag.
    pub fn parse(kind: RecordKind, value: &str) -> Result<Self, DomainError> {
        let value = value.trim();

        match kind {
            RecordKind::A | RecordKind::Aaaa => Self::parse_address(kind, value),
            RecordKind::Cname => Ok(Self::Alias(host(value)?)),
            RecordKind::Txt => Ok(Self::Text(TxtValue::new(value)?)),
            RecordKind::Mx => Self::parse_mail(value),
            RecordKind::Srv => Self::parse_service(value),
            RecordKind::Caa => Self::parse_authority(value),
        }
    }

    fn parse_address(kind: RecordKind, value: &str) -> Result<Self, DomainError> {
        let address = IpAddress::new(value).map_err(|e| {
            DomainError::invalid(message!("tenant-record", format!("{kind} record: {e}")))
        })?;

        let family = if address.is_ipv6() {
            RecordKind::Aaaa
        } else {
            RecordKind::A
        };

        let wanted = if kind == RecordKind::A {
            "IPv4"
        } else {
            "IPv6"
        };
        if family != kind {
            return Err(DomainError::invalid(message!(
                "tenant-an-record-needs-an-address-and",
                format!("an {kind} record needs an {wanted} address, and '{value}' is {family}")
            )));
        }

        Ok(Self::Address(address))
    }

    fn parse_mail(value: &str) -> Result<Self, DomainError> {
        let (priority, host_name) = value.split_once(char::is_whitespace).ok_or_else(|| {
            DomainError::invalid(message!(
                "tenant-an-mx-record-is-a-priority",
                "an MX record is a priority and a host, as in '10 mail.acme.com'"
            ))
        })?;

        Ok(Self::Mail(MailExchange::new(
            number("mx_priority", priority)?,
            host(host_name)?,
        )))
    }

    fn parse_service(value: &str) -> Result<Self, DomainError> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let [priority, weight, port, host_name] = fields.as_slice() else {
            return Err(DomainError::invalid(message!(
                "tenant-an-srv-record-is-a-priority",
                "an SRV record is a priority, weight, port, and host, as in \
                 '10 5 443 sip.acme.com'"
            )));
        };

        Ok(Self::Service(ServiceTarget::new(
            number("srv_priority", priority)?,
            number("srv_weight", weight)?,
            number("srv_port", port)?,
            host(host_name)?,
        )?))
    }

    fn parse_authority(value: &str) -> Result<Self, DomainError> {
        let mut fields = value.splitn(3, char::is_whitespace);
        let (Some(flags), Some(tag), Some(property)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(DomainError::invalid(message!(
                "tenant-a-caa-record-is-flags-a",
                "a CAA record is flags, a tag, and a quoted value, as in \
                 '0 issue \"letsencrypt.org\"'"
            )));
        };

        Ok(Self::Authority(CaaProperty::new(
            CaaProperty::handling_from_flags(number("caa_flags", flags)?)?,
            CaaTag::parse(tag)?,
            TxtValue::new(property.trim().trim_matches('"'))?,
        )))
    }
}

/// Parses one of the numeric fields an `MX`, `SRV`, or `CAA` record carries.
fn number<T>(field: &str, value: &str) -> Result<T, DomainError>
where
    T: std::str::FromStr,
{
    value.trim().parse::<T>().map_err(|_| {
        DomainError::invalid(message!(
            "tenant-must-be-a-whole-number-got",
            format!("{field} must be a whole number, got '{value}'")
        ))
    })
}

/// Parses the hostname an `MX`, `SRV`, or `CNAME` record points at.
fn host(value: &str) -> Result<DomainName, DomainError> {
    DomainName::new(value.trim().trim_end_matches('.')).map_err(DomainError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> DomainName {
        DomainName::new(value).unwrap()
    }

    fn text(value: &str) -> TxtValue {
        TxtValue::new(value).unwrap()
    }

    /// Storage keeps the presentation form, so a value that does not survive
    /// the round trip is a value the zone would answer with wrongly.
    fn round_trips(value: &RecordValue) {
        let spelled = value.as_presentation();
        let read_back = RecordValue::parse(value.kind(), &spelled)
            .unwrap_or_else(|e| panic!("'{spelled}' did not parse back: {e}"));

        assert_eq!(&read_back, value, "via '{spelled}'");
    }

    /// `203.0.113.10` is spelled out and parsed back as the same `A` value.
    #[test]
    fn an_ipv4_address_round_trips_as_an_a_record() {
        round_trips(&RecordValue::Address(
            IpAddress::new("203.0.113.10").unwrap(),
        ));
    }

    /// `2001:db8::1` is spelled out and parsed back as the same `AAAA` value.
    #[test]
    fn an_ipv6_address_round_trips_as_an_aaaa_record() {
        round_trips(&RecordValue::Address(
            IpAddress::new("2001:db8::1").unwrap(),
        ));
    }

    /// A `CNAME` to `target.acme.com` is spelled out and parsed back the same.
    #[test]
    fn an_alias_round_trips() {
        round_trips(&RecordValue::Alias(domain("target.acme.com")));
    }

    /// An SPF text with an include is spelled out and parsed back the same.
    #[test]
    fn text_round_trips() {
        round_trips(&RecordValue::Text(text(
            "v=spf1 include:_spf.acme.com -all",
        )));
    }

    /// An `MX` of priority 10 to `mail.acme.com` is spelled out and parsed
    /// back the same.
    #[test]
    fn a_mail_exchange_round_trips() {
        round_trips(&RecordValue::Mail(MailExchange::new(
            10,
            domain("mail.acme.com"),
        )));
    }

    /// An `SRV` with priority, weight, port 443 and host is spelled out and
    /// parsed back the same.
    #[test]
    fn a_service_target_round_trips() {
        round_trips(&RecordValue::Service(
            ServiceTarget::new(10, 5, 443, domain("sip.acme.com")).unwrap(),
        ));
    }

    /// A non-critical `CAA` allowing Let's Encrypt is spelled out and parsed
    /// back the same.
    #[test]
    fn a_certificate_authorisation_round_trips() {
        round_trips(&RecordValue::Authority(CaaProperty::new(
            CaaHandling::NonCritical,
            CaaTag::Issue,
            text("letsencrypt.org"),
        )));
    }

    /// A critical `issuewild` `CAA` is spelled out and parsed back the same,
    /// critical flag included.
    #[test]
    fn a_critical_certificate_authorisation_round_trips() {
        round_trips(&RecordValue::Authority(CaaProperty::new(
            CaaHandling::Critical,
            CaaTag::IssueWild,
            text("letsencrypt.org"),
        )));
    }

    /// `MX`, `SRV` and `CAA` values come out as a zone file writes them, such
    /// as `10 mail.acme.com` and `128 issue "letsencrypt.org"`.
    #[test]
    fn each_type_is_spelled_the_way_a_zone_file_spells_it() {
        assert_eq!(
            RecordValue::Mail(MailExchange::new(10, domain("mail.acme.com"))).as_presentation(),
            "10 mail.acme.com"
        );
        assert_eq!(
            RecordValue::Service(ServiceTarget::new(10, 5, 443, domain("sip.acme.com")).unwrap())
                .as_presentation(),
            "10 5 443 sip.acme.com"
        );
        assert_eq!(
            RecordValue::Authority(CaaProperty::new(
                CaaHandling::NonCritical,
                CaaTag::Issue,
                text("letsencrypt.org")
            ))
            .as_presentation(),
            "0 issue \"letsencrypt.org\""
        );
        assert_eq!(
            RecordValue::Authority(CaaProperty::new(
                CaaHandling::Critical,
                CaaTag::Issue,
                text("letsencrypt.org")
            ))
            .as_presentation(),
            "128 issue \"letsencrypt.org\""
        );
    }

    /// An IPv4 address answers as `A` and an IPv6 one as `AAAA`. The type is
    /// read off the address, so the two can never disagree.
    #[test]
    fn the_address_family_decides_the_record_type() {
        assert_eq!(
            RecordValue::Address(IpAddress::new("203.0.113.10").unwrap()).kind(),
            RecordKind::A
        );
        assert_eq!(
            RecordValue::Address(IpAddress::new("2001:db8::1").unwrap()).kind(),
            RecordKind::Aaaa
        );
    }

    /// An IPv6 address typed as `A`, or an IPv4 one typed as `AAAA`, is
    /// refused. A resolver asking for `A` cannot use an IPv6 answer.
    #[test]
    fn an_address_of_the_wrong_family_is_refused() {
        assert!(RecordValue::parse(RecordKind::A, "2001:db8::1").is_err());
        assert!(RecordValue::parse(RecordKind::Aaaa, "203.0.113.10").is_err());
    }

    /// `999.0.0.1` and `not-an-address` are refused as `A` values.
    #[test]
    fn a_malformed_address_is_refused() {
        assert!(RecordValue::parse(RecordKind::A, "999.0.0.1").is_err());
        assert!(RecordValue::parse(RecordKind::A, "not-an-address").is_err());
    }

    /// An `MX` of only `mail.acme.com`, with no priority, is refused.
    #[test]
    fn a_mail_exchange_without_a_priority_is_refused() {
        assert!(RecordValue::parse(RecordKind::Mx, "mail.acme.com").is_err());
    }

    /// An `MX` with the priority `high` is refused, since it must be a whole
    /// number.
    #[test]
    fn a_mail_exchange_with_an_unreadable_priority_is_refused() {
        assert!(RecordValue::parse(RecordKind::Mx, "high mail.acme.com").is_err());
    }

    /// `SRV` values with three, five or one field are refused. It needs
    /// exactly four.
    #[test]
    fn a_service_record_with_the_wrong_field_count_is_refused() {
        for bad in ["10 5 443", "10 5 443 sip.acme.com extra", "sip.acme.com"] {
            assert!(
                RecordValue::parse(RecordKind::Srv, bad).is_err(),
                "'{bad}' should not parse as SRV"
            );
        }
    }

    /// An `SRV` on port 0 is refused, both parsed and built in code. RFC
    /// 2782 reads port 0 as "not offered", which a tenant who forgot the port
    /// does not mean.
    #[test]
    fn a_service_record_on_port_zero_is_refused() {
        assert!(RecordValue::parse(RecordKind::Srv, "10 5 0 sip.acme.com").is_err());
        assert!(ServiceTarget::new(10, 5, 0, domain("sip.acme.com")).is_err());
    }

    /// `CAA` flags of 1 or 64 are refused. Only 0 and 128 are defined, and
    /// guessing at another value would invent a policy.
    #[test]
    fn a_certificate_authorisation_with_undefined_flags_is_refused() {
        assert!(RecordValue::parse(RecordKind::Caa, "1 issue \"letsencrypt.org\"").is_err());
        assert!(RecordValue::parse(RecordKind::Caa, "64 issue \"letsencrypt.org\"").is_err());
    }

    /// A `CAA` with the tag `issueeee` is refused.
    #[test]
    fn a_certificate_authorisation_with_an_unknown_tag_is_refused() {
        assert!(RecordValue::parse(RecordKind::Caa, "0 issueeee \"letsencrypt.org\"").is_err());
    }

    /// A `CAA` of `0 issue` with no value is refused.
    #[test]
    fn a_certificate_authorisation_missing_a_field_is_refused() {
        assert!(RecordValue::parse(RecordKind::Caa, "0 issue").is_err());
    }

    /// A tenant pastes a `CAA` value with quotes, as a zone file writes it,
    /// or without. Both read as the same value.
    #[test]
    fn a_certificate_authorisation_reads_with_or_without_quotes() {
        let quoted = RecordValue::parse(RecordKind::Caa, "0 issue \"letsencrypt.org\"").unwrap();
        let bare = RecordValue::parse(RecordKind::Caa, "0 issue letsencrypt.org").unwrap();

        assert_eq!(quoted, bare);
    }

    /// A tenant copies `target.acme.com.` from a zone file, trailing dot and
    /// all. It is accepted and the dot is dropped.
    #[test]
    fn a_trailing_dot_on_a_target_is_accepted_and_dropped() {
        let dotted = RecordValue::parse(RecordKind::Cname, "target.acme.com.").unwrap();

        assert_eq!(dotted, RecordValue::Alias(domain("target.acme.com")));
    }

    /// A DKIM record with an 800-character key is accepted. It is longer than
    /// `Text` allows, and tenants need to publish one.
    #[test]
    fn a_long_dkim_key_is_accepted() {
        let key = format!("v=DKIM1; k=rsa; p={}", "A".repeat(800));

        assert!(TxtValue::new(key).is_ok());
    }

    /// A text of 2049 bytes, one over the limit, is refused.
    #[test]
    fn text_beyond_what_a_resolver_would_carry_is_refused() {
        assert!(TxtValue::new("A".repeat(2049)).is_err());
    }

    /// An empty text value is refused.
    #[test]
    fn empty_text_is_refused() {
        assert!(TxtValue::new("").is_err());
    }

    /// An SPF text with a line break or a NUL byte in it is refused.
    #[test]
    fn text_holding_a_control_character_is_refused() {
        assert!(TxtValue::new("v=spf1\n-all").is_err());
        assert!(TxtValue::new("v=spf1\0-all").is_err());
    }

    /// `v=spf1 -all` reads from JSON and writes back the same. An empty text
    /// and one with a line break read from JSON are refused.
    #[cfg(feature = "serde")]
    #[test]
    fn text_read_from_json_is_validated() {
        let value: TxtValue = serde_json::from_str("\"v=spf1 -all\"").unwrap();

        assert_eq!(serde_json::to_string(&value).unwrap(), "\"v=spf1 -all\"");
        assert!(serde_json::from_str::<TxtValue>("\"\"").is_err());
        assert!(serde_json::from_str::<TxtValue>("\"v=spf1\\n-all\"").is_err());
    }

    /// Each of the three `CAA` tags parses back from its own spelling.
    #[test]
    fn every_caa_tag_round_trips_through_its_spelling() {
        for tag in CaaTag::ALL {
            assert_eq!(CaaTag::parse(tag.as_str()).unwrap(), tag);
        }
    }

    /// A tenant types `IssueWild`. It parses as the `issuewild` tag.
    #[test]
    fn a_caa_tag_parses_regardless_of_case() {
        assert_eq!(CaaTag::parse("IssueWild").unwrap(), CaaTag::IssueWild);
    }

    /// A `CAA` built as critical reads as critical, and one built as
    /// non-critical does not. The flag tells an authority whether to stop on
    /// a tag it cannot read.
    #[test]
    fn only_a_property_marked_critical_reads_as_critical() {
        let critical = CaaProperty::new(
            CaaHandling::Critical,
            CaaTag::Issue,
            text("letsencrypt.org"),
        );
        let advisory = CaaProperty::new(
            CaaHandling::NonCritical,
            CaaTag::Issue,
            text("letsencrypt.org"),
        );

        assert!(critical.is_critical());
        assert!(!advisory.is_critical());
    }
}
