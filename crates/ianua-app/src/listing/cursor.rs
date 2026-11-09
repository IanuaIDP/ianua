//! The position a page ends at, handed to callers as an opaque string.
//!
//! A [`Cursor`] holds the sort values of the last row a page gave, then that
//! row's id, and the sort order they were taken in. It is not signed: it is
//! only a position, and every store still filters by the caller's tenant, so
//! a forged cursor can only move where a caller's own list starts.
//!
//! The string form is base64url (no padding) of a small versioned encoding:
//!
//! - one version byte;
//! - the order's signature, such as `-created_at,name`, length-prefixed;
//! - the number of keys, then each key as a tag byte and its value.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::shared::errors::{DomainError, Refusal};
use ianua_domain::shared::validation::ValidationError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::listing::{KeyOrder, RowKeys, SortKey};

/// The encoding this build writes and reads.
const VERSION: u8 = 1;

/// The longest cursor string read back. Sort values are names, times and
/// ids, so a real cursor stays far below this.
const MOST_CURSOR_CHARS: usize = 2048;

const TAG_MISSING: u8 = 0;
const TAG_TEXT: u8 = 1;
const TAG_INTEGER: u8 = 2;
const TAG_TIME: u8 = 3;
const TAG_ID: u8 = 4;

/// Where a page ended: the last row's sort values and id, tied to the sort
/// order they were taken in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    order: String,
    keys: Vec<SortKey>,
}

impl Cursor {
    /// The cursor just after `row` in a list in `order`.
    #[must_use]
    pub fn after_row<T, O: RowKeys<T>>(order: &O, row: &T) -> Self {
        Self::at(order, order.row_keys(row))
    }

    /// The cursor just after the row whose values in `order` are `keys`,
    /// for a store that reads those values beside the row.
    #[must_use]
    pub fn at<O: KeyOrder>(order: &O, keys: Vec<SortKey>) -> Self {
        Self {
            order: order.signature(),
            keys,
        }
    }

    /// The order this cursor was made for, as its signature.
    pub(crate) fn order(&self) -> &str {
        &self.order
    }

    /// The row's sort values, then its id.
    pub(crate) fn keys(&self) -> &[SortKey] {
        &self.keys
    }

    /// The opaque string a caller passes back as `after`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut encoder = Encoder::new();
        encoder.text(&self.order);
        encoder.count(self.keys.len());
        self.keys.iter().for_each(|key| encoder.key(key));
        URL_SAFE_NO_PAD.encode(encoder.bytes)
    }

    /// Reads back a cursor [`Cursor::encode`] wrote.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCursor::Malformed`] when `text` is too long, not
    /// base64url, of another version, cut short, or followed by extra bytes.
    pub fn decode(text: &str) -> Result<Self, InvalidCursor> {
        if text.len() > MOST_CURSOR_CHARS {
            return Err(InvalidCursor::Malformed);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| InvalidCursor::Malformed)?;
        Decoder { bytes: &bytes }.cursor()
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl FromStr for Cursor {
    type Err = InvalidCursor;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::decode(text)
    }
}

/// Writes a cursor's bytes.
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: vec![VERSION],
        }
    }

    fn count(&mut self, count: usize) {
        self.bytes.push(u8::try_from(count).unwrap_or(u8::MAX));
    }

    fn text(&mut self, text: &str) {
        let length = u16::try_from(text.len()).unwrap_or(u16::MAX);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes
            .extend_from_slice(&text.as_bytes()[..usize::from(length)]);
    }

    fn key(&mut self, key: &SortKey) {
        match key {
            SortKey::Missing => self.bytes.push(TAG_MISSING),
            SortKey::Text(text) => {
                self.bytes.push(TAG_TEXT);
                self.text(text);
            }
            SortKey::Integer(number) => self.write_tagged(TAG_INTEGER, &number.to_be_bytes()),
            SortKey::Time(at) => {
                self.write_tagged(TAG_TIME, &at.unix_timestamp_nanos().to_be_bytes())
            }
            SortKey::Id(id) => self.write_tagged(TAG_ID, id.as_bytes()),
        }
    }

    fn write_tagged(&mut self, tag: u8, value: &[u8]) {
        self.bytes.push(tag);
        self.bytes.extend_from_slice(value);
    }
}

/// Reads a cursor's bytes, refusing anything [`Encoder`] would not write.
struct Decoder<'a> {
    bytes: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn cursor(mut self) -> Result<Cursor, InvalidCursor> {
        if self.byte()? != VERSION {
            return Err(InvalidCursor::Malformed);
        }
        let order = self.text()?;
        let count = self.byte()?;
        let keys = (0..count)
            .map(|_| self.key())
            .collect::<Result<Vec<_>, _>>()?;
        if !self.bytes.is_empty() || keys.is_empty() {
            return Err(InvalidCursor::Malformed);
        }
        Ok(Cursor { order, keys })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], InvalidCursor> {
        let Some((head, rest)) = self.bytes.split_at_checked(length) else {
            return Err(InvalidCursor::Malformed);
        };
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], InvalidCursor> {
        self.take(N)?
            .try_into()
            .map_err(|_| InvalidCursor::Malformed)
    }

    fn byte(&mut self) -> Result<u8, InvalidCursor> {
        let [byte] = self.array::<1>()?;
        Ok(byte)
    }

    fn text(&mut self) -> Result<String, InvalidCursor> {
        let length = u16::from_be_bytes(self.array()?);
        let bytes = self.take(usize::from(length))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| InvalidCursor::Malformed)
    }

    fn key(&mut self) -> Result<SortKey, InvalidCursor> {
        match self.byte()? {
            TAG_MISSING => Ok(SortKey::Missing),
            TAG_TEXT => Ok(SortKey::Text(self.text()?)),
            TAG_INTEGER => Ok(SortKey::Integer(i64::from_be_bytes(self.array()?))),
            TAG_TIME => self.time(),
            TAG_ID => Ok(SortKey::Id(Uuid::from_bytes(self.array()?))),
            _ => Err(InvalidCursor::Malformed),
        }
    }

    fn time(&mut self) -> Result<SortKey, InvalidCursor> {
        let nanos = i128::from_be_bytes(self.array()?);
        OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map(SortKey::Time)
            .map_err(|_| InvalidCursor::Malformed)
    }
}

/// A cursor a list cannot read on from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCursor {
    /// The string is not a cursor any list gave out.
    #[error("after is not a cursor this list gave out")]
    Malformed,
    /// The cursor was made for another sort order, so it marks no place in
    /// this one.
    #[error("after was made for another sort order; start again from the first page")]
    OtherOrder,
}

impl InvalidCursor {
    fn code(self) -> &'static str {
        match self {
            Self::Malformed => "invalid_cursor",
            Self::OtherOrder => "cursor_for_other_sort",
        }
    }
}

impl From<InvalidCursor> for ValidationError {
    fn from(refused: InvalidCursor) -> Self {
        Self::Custom {
            field: "after",
            code: refused.code().to_owned(),
            message: Refusal::new(refused.to_string()),
        }
    }
}

impl From<InvalidCursor> for DomainError {
    fn from(refused: InvalidCursor) -> Self {
        Self::Validation(refused.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::define_sort_field;
    use crate::listing::{SortKeys, SortOrder};

    define_sort_field! {
        /// Test field with a descending default.
        enum Field {
            /// Order by creation time.
            CreatedAt => "created_at",
            /// Order by name.
            Name => "name",
        }
        default = CreatedAt;
        default direction = Desc;
    }

    struct Row {
        id: Uuid,
        name: Option<&'static str>,
        created_at: OffsetDateTime,
    }

    impl SortKeys<Field> for Row {
        fn sort_key(&self, field: Field) -> SortKey {
            match field {
                Field::CreatedAt => self.created_at.into(),
                Field::Name => self.name.into(),
            }
        }

        fn tiebreak(&self) -> SortKey {
            self.id.into()
        }
    }

    fn ann() -> Row {
        Row {
            id: Uuid::from_u128(7),
            name: Some("Ann"),
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    /// A cursor handed out with a page reads back as the same position, so
    /// the next request starts where the page ended.
    #[test]
    fn a_cursor_round_trips_through_its_string() {
        let sort = SortOrder::<Field>::parse(Some("name,-created_at")).unwrap();
        let cursor = Cursor::after_row(&sort, &ann());

        let read_back = Cursor::decode(&cursor.encode()).unwrap();

        assert_eq!(read_back, cursor);
    }

    /// A row with no name still makes a cursor that reads back, holding the
    /// missing value.
    #[test]
    fn a_missing_value_round_trips() {
        let sort = SortOrder::<Field>::parse(Some("name")).unwrap();
        let nameless = Row {
            name: None,
            ..ann()
        };

        let read_back = Cursor::decode(&Cursor::after_row(&sort, &nameless).encode()).unwrap();

        assert_eq!(read_back.keys()[0], SortKey::Missing);
    }

    /// The string is opaque but URL-safe, so it travels in a query string
    /// without escaping.
    #[test]
    fn the_string_is_url_safe() {
        let cursor = Cursor::after_row(&SortOrder::<Field>::default(), &ann());

        let text = cursor.encode();

        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    /// Arbitrary text is rejected as a malformed cursor instead of a page position.
    #[test]
    fn text_that_is_no_cursor_is_refused() {
        assert_eq!(
            Cursor::decode("not a cursor!"),
            Err(InvalidCursor::Malformed)
        );
    }

    /// Removing the end of a valid cursor makes decoding fail as malformed.
    #[test]
    fn a_truncated_cursor_is_refused() {
        let text = Cursor::after_row(&SortOrder::<Field>::default(), &ann()).encode();

        assert_eq!(
            Cursor::decode(&text[..text.len() - 4]),
            Err(InvalidCursor::Malformed)
        );
    }

    /// A cursor string exceeding the size cap is rejected as malformed.
    #[test]
    fn an_overlong_cursor_is_refused() {
        assert_eq!(
            Cursor::decode(&"A".repeat(MOST_CURSOR_CHARS + 1)),
            Err(InvalidCursor::Malformed)
        );
    }

    /// A cursor of a version this build does not know is refused rather than
    /// guessed at.
    #[test]
    fn a_cursor_of_another_version_is_refused() {
        let text = URL_SAFE_NO_PAD.encode([VERSION + 1, 0, 0, 0]);

        assert_eq!(Cursor::decode(&text), Err(InvalidCursor::Malformed));
    }

    /// A refused cursor reaches the caller as a validation error on `after`.
    #[test]
    fn a_refused_cursor_is_a_validation_error_on_after() {
        let error: DomainError = InvalidCursor::OtherOrder.into();

        let DomainError::Validation(rule) = error else {
            panic!("a refused cursor is a validation error");
        };
        assert_eq!(
            (rule.field(), rule.code()),
            (Some("after"), "cursor_for_other_sort")
        );
    }
}
