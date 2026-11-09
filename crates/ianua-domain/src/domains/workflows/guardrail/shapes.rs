//! Personal data written into free text, found by its shape.
//!
//! The tenant's classification rules name fields, such as
//! `customer.email`, and a guardrail applies them to every field of the
//! value it checks. An agent's answer is one text, though, with no fields
//! inside it, so the shapes that personal data always takes are looked
//! for in each text as well: an email address, a payment card number that
//! passes its check digit, and an IBAN that passes its own. Each counts as
//! confidential, the level the classification levels give personal and
//! financial data. A check digit keeps a run of digits that merely looks
//! like a card from being taken for one.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::guardrail::words::{Span, char_spans};

/// The fewest digits a payment card number has.
const CARD_DIGITS_FEWEST: usize = 13;

/// The most digits a payment card number has.
const CARD_DIGITS_MOST: usize = 19;

/// The fewest characters an IBAN has.
const IBAN_FEWEST: usize = 15;

/// The most characters an IBAN has.
const IBAN_MOST: usize = 34;

/// A shape personal data takes in free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextShape {
    /// An email address, such as `ann@acme.example`.
    EmailAddress,
    /// A payment card number whose last digit checks out.
    PaymentCard,
    /// An international bank account number whose check digits check out.
    Iban,
}

impl TextShape {
    /// Every shape, in the order they are looked for.
    pub const ALL: [Self; 3] = [Self::EmailAddress, Self::PaymentCard, Self::Iban];

    /// The stable name a finding records it by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailAddress => "email_address",
            Self::PaymentCard => "payment_card",
            Self::Iban => "iban",
        }
    }

    /// How sensitive data of this shape is.
    #[must_use]
    pub fn level(self) -> DataClassLevel {
        DataClassLevel::Confidential
    }

    /// Where in `text` data of this shape is written.
    pub(crate) fn found_in(self, text: &str) -> Vec<Span> {
        match self {
            Self::EmailAddress => email_addresses(text),
            Self::PaymentCard => card_numbers(text),
            Self::Iban => ibans(text),
        }
    }
}

/// Every email address in `text`: a local part, `@`, and a domain of at
/// least two labels whose last is two letters or more.
fn email_addresses(text: &str) -> Vec<Span> {
    let bytes = text.as_bytes();
    let ranges: Vec<(usize, usize)> = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'@')
        .filter_map(|(at, _)| email_around(bytes, at))
        .collect();
    char_spans(text, &ranges)
}

/// The bytes of the address whose `@` is at `at`, when it is one.
fn email_around(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let local_start = run_before(bytes, at, is_local_byte);
    let start = local_start.saturating_add(leading(bytes.get(local_start..at)?, b'.'));
    let domain_end = run_after(bytes, at.saturating_add(1), is_domain_byte);
    let domain = bytes.get(at.saturating_add(1)..domain_end)?;
    let trimmed = domain
        .len()
        .saturating_sub(trailing(domain, |byte| byte == b'.' || byte == b'-'));
    let domain = domain.get(..trimmed)?;
    if start >= at || !is_domain(domain) {
        return None;
    }
    Some((start, at.saturating_add(1).saturating_add(trimmed)))
}

/// Whether `domain` has two labels or more, none empty, and ends in two
/// letters or more.
fn is_domain(domain: &[u8]) -> bool {
    let labels: Vec<&[u8]> = domain.split(|byte| *byte == b'.').collect();
    let Some(last) = labels.last() else {
        return false;
    };
    labels.len() >= 2
        && labels.iter().all(|label| !label.is_empty())
        && last.len() >= 2
        && last.iter().all(u8::is_ascii_alphabetic)
}

fn is_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

/// Where the run of bytes `keep` takes, ending just before `end`, starts.
fn run_before(bytes: &[u8], end: usize, keep: fn(u8) -> bool) -> usize {
    let before = bytes.get(..end).unwrap_or_default();
    end.saturating_sub(trailing(before, keep))
}

/// Where the run of bytes `keep` takes, starting at `start`, ends.
fn run_after(bytes: &[u8], start: usize, keep: fn(u8) -> bool) -> usize {
    let after = bytes.get(start..).unwrap_or_default();
    start.saturating_add(after.iter().take_while(|byte| keep(**byte)).count())
}

/// How many of the last bytes of `bytes` `keep` takes.
fn trailing(bytes: &[u8], keep: impl Fn(u8) -> bool) -> usize {
    bytes.iter().rev().take_while(|byte| keep(**byte)).count()
}

/// How many of the first bytes of `bytes` are `byte`.
fn leading(bytes: &[u8], byte: u8) -> usize {
    bytes.iter().take_while(|each| **each == byte).count()
}

/// Every payment card number in `text`: 13 to 19 digits, perhaps in groups
/// split by one space or hyphen, whose last digit checks out.
fn card_numbers(text: &str) -> Vec<Span> {
    let ranges: Vec<(usize, usize)> = digit_runs(text.as_bytes())
        .into_iter()
        .filter(|run| (CARD_DIGITS_FEWEST..=CARD_DIGITS_MOST).contains(&run.digits.len()))
        .filter(|run| luhn_holds(&run.digits))
        .map(|run| (run.start, run.end))
        .collect();
    char_spans(text, &ranges)
}

/// Digits written together, perhaps split by single spaces or hyphens.
struct DigitRun {
    start: usize,
    end: usize,
    digits: Vec<u8>,
}

/// Every run of digits in `bytes` not touching a letter or digit before it.
fn digit_runs(bytes: &[u8]) -> Vec<DigitRun> {
    let mut runs = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let starts_run = bytes.get(at).is_some_and(u8::is_ascii_digit)
            && !at
                .checked_sub(1)
                .and_then(|before| bytes.get(before))
                .is_some_and(u8::is_ascii_alphanumeric);
        if !starts_run {
            at = at.saturating_add(1);
            continue;
        }
        let run = digit_run_from(bytes, at);
        at = run.end.max(at.saturating_add(1));
        runs.push(run);
    }
    runs
}

/// The run of digits starting at `start`.
fn digit_run_from(bytes: &[u8], start: usize) -> DigitRun {
    let mut digits = Vec::new();
    let mut at = start;
    let mut end = start;
    while let Some(byte) = bytes.get(at) {
        let next_is_digit = bytes
            .get(at.saturating_add(1))
            .is_some_and(u8::is_ascii_digit);
        match byte {
            b'0'..=b'9' => {
                digits.push(byte.saturating_sub(b'0'));
                end = at.saturating_add(1);
            }
            b' ' | b'-' if next_is_digit && end == at => {}
            _ => break,
        }
        at = at.saturating_add(1);
    }
    DigitRun { start, end, digits }
}

/// Whether `digits` pass the Luhn check payment cards carry.
fn luhn_holds(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(position, digit)| {
            let digit = u32::from(*digit);
            if position.is_multiple_of(2) {
                return digit;
            }
            let doubled = digit.saturating_mul(2);
            if doubled > 9 {
                doubled.saturating_sub(9)
            } else {
                doubled
            }
        })
        .fold(0_u32, u32::saturating_add);
    sum.is_multiple_of(10)
}

/// Every IBAN in `text`: a country's two letters, two check digits and the
/// account, perhaps in groups split by single spaces, whose check digits
/// check out.
fn ibans(text: &str) -> Vec<Span> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let Some(end) = iban_at(bytes, at) else {
            at = at.saturating_add(1);
            continue;
        };
        ranges.push((at, end));
        at = end;
    }
    char_spans(text, &ranges)
}

/// The end of the IBAN starting at `start`, when one does.
fn iban_at(bytes: &[u8], start: usize) -> Option<usize> {
    let after_letter = start
        .checked_sub(1)
        .and_then(|before| bytes.get(before))
        .is_some_and(u8::is_ascii_alphanumeric);
    let head = bytes.get(start..start.saturating_add(4))?;
    let opens = head.get(..2)?.iter().all(u8::is_ascii_alphabetic)
        && head.get(2..)?.iter().all(u8::is_ascii_digit);
    if after_letter || !opens {
        return None;
    }
    let groups = groups_from(bytes, start);
    (1..=groups.len())
        .rev()
        .filter_map(|count| groups.get(..count))
        .find(|taken| iban_holds(&compact(bytes, taken)))
        .and_then(|taken| taken.last())
        .map(|(_, end)| *end)
}

/// The groups of letters and digits from `start`, each split from the next
/// by one space, as byte spans, while they fit an IBAN.
fn groups_from(bytes: &[u8], start: usize) -> Vec<(usize, usize)> {
    let mut groups = Vec::new();
    let mut at = start;
    let mut length: usize = 0;
    loop {
        let end = run_after(bytes, at, |byte| byte.is_ascii_alphanumeric());
        length = length.saturating_add(end.saturating_sub(at));
        if end == at || length > IBAN_MOST {
            return groups;
        }
        groups.push((at, end));
        let spaced = bytes.get(end) == Some(&b' ')
            && bytes
                .get(end.saturating_add(1))
                .is_some_and(u8::is_ascii_alphanumeric);
        if !spaced {
            return groups;
        }
        at = end.saturating_add(1);
    }
}

/// The letters and digits of `groups`, upper-cased and joined.
fn compact(bytes: &[u8], groups: &[(usize, usize)]) -> Vec<u8> {
    groups
        .iter()
        .filter_map(|(start, end)| bytes.get(*start..*end))
        .flatten()
        .map(u8::to_ascii_uppercase)
        .collect()
}

/// Whether `iban`, upper-cased and without spaces, has an IBAN's length
/// and passes its mod-97 check.
fn iban_holds(iban: &[u8]) -> bool {
    if !(IBAN_FEWEST..=IBAN_MOST).contains(&iban.len()) {
        return false;
    }
    let (head, account) = iban.split_at(4);
    let remainder = account
        .iter()
        .chain(head)
        .try_fold(0_u32, |remainder, byte| {
            let value = match byte {
                b'0'..=b'9' => u32::from(byte.saturating_sub(b'0')),
                b'A'..=b'Z' => u32::from(byte.saturating_sub(b'A')).saturating_add(10),
                _ => return None,
            };
            let shift = if value >= 10 { 100 } else { 10 };
            remainder
                .saturating_mul(shift)
                .saturating_add(value)
                .checked_rem(97)
        });
    remainder == Some(1)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// "Write to ann.lee@acme.example." finds the address without the
    /// sentence's full stop.
    #[test]
    fn an_email_address_is_found_without_the_full_stop_after_it() {
        let text = "Write to ann.lee@acme.example.";

        assert_eq!(
            TextShape::EmailAddress.found_in(text),
            [Span::between(9, 29)]
        );
    }

    /// "@here" and "a@b" have no domain of two labels, so neither is taken
    /// for an address.
    #[test]
    fn a_handle_is_not_an_email_address() {
        assert!(
            TextShape::EmailAddress
                .found_in("ping @here and a@b")
                .is_empty()
        );
    }

    /// A card number written in groups of four is found; the same digits
    /// with one changed fail the check digit and are not.
    #[test]
    fn a_card_number_is_found_only_when_its_check_digit_holds() {
        let card = TextShape::PaymentCard.found_in("card 4111 1111 1111 1111 ok");
        let mistyped = TextShape::PaymentCard.found_in("card 4111 1111 1111 1112 ok");

        assert_eq!(card, [Span::between(5, 24)]);
        assert!(mistyped.is_empty());
    }

    /// An order number of eight digits is no card, however it ends.
    #[test]
    fn a_short_number_is_not_a_card() {
        assert!(TextShape::PaymentCard.found_in("order 12345674").is_empty());
    }

    /// A German IBAN written in groups is found, and the words after it are
    /// left out of what was found.
    #[test]
    fn an_iban_in_groups_is_found_without_the_words_after_it() {
        let text = "pay DE89 3704 0044 0532 0130 00 by friday";

        assert_eq!(TextShape::Iban.found_in(text), [Span::between(4, 31)]);
    }

    /// The same IBAN with one digit changed fails its check digits.
    #[test]
    fn a_mistyped_iban_is_not_found() {
        assert!(
            TextShape::Iban
                .found_in("DE89370400440532013001")
                .is_empty()
        );
    }

    /// The check digit that makes `body` pass the Luhn check.
    fn with_check_digit(body: &[u8]) -> Vec<u8> {
        (0..10)
            .map(|check| [body, &[check]].concat())
            .find(|digits| luhn_holds(digits))
            .unwrap()
    }

    fn digits_text(digits: &[u8]) -> String {
        digits
            .iter()
            .map(|digit| char::from(b'0' + digit))
            .collect()
    }

    proptest! {
        /// Any number of 13 to 19 digits that passes the Luhn check is
        /// found, wherever it stands in a sentence.
        #[test]
        fn every_valid_card_number_is_found(
            body in proptest::collection::vec(0_u8..10, 12..19),
            before in "[a-z ]{0,20}",
        ) {
            let card = digits_text(&with_check_digit(&body));
            let text = format!("{before} {card} thanks");

            prop_assert_eq!(TextShape::PaymentCard.found_in(&text).len(), 1);
        }

        /// Changing any one digit of a valid card number breaks its check
        /// digit, so it is no longer found.
        #[test]
        fn one_changed_digit_is_never_a_card(
            body in proptest::collection::vec(0_u8..10, 12..19),
            position in 0_usize..19,
            by in 1_u8..10,
        ) {
            let mut digits = with_check_digit(&body);
            let at = position % digits.len();
            digits[at] = (digits[at] + by) % 10;

            prop_assert!(TextShape::PaymentCard.found_in(&digits_text(&digits)).is_empty());
        }

        /// A built address is found exactly where it was written.
        #[test]
        fn every_built_address_is_found_where_written(
            local in "[a-z][a-z0-9._+-]{0,15}[a-z0-9]",
            host in "[a-z][a-z0-9-]{0,10}[a-z0-9]",
            top in "[a-z]{2,6}",
            before in "[A-Za-z ]{0,10}",
        ) {
            let address = format!("{local}@{host}.{top}");
            let start = before.chars().count() + 1;
            let text = format!("{before} {address}, thanks");

            let found = TextShape::EmailAddress.found_in(&text);

            prop_assert_eq!(found, vec![Span::between(start, start + address.len())]);
        }

        /// Whatever the text, every place found lies inside it.
        #[test]
        fn every_place_lies_inside_the_text(text in "\\PC{0,120}") {
            let length = u32::try_from(text.chars().count()).unwrap();

            for shape in TextShape::ALL {
                for span in shape.found_in(&text) {
                    prop_assert!(span.end() <= length);
                }
            }
        }
    }
}
