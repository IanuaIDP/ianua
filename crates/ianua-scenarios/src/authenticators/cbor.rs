//! The little CBOR (RFC 8949) a `none` attestation is written in: maps,
//! byte strings, text strings and small integers, in the canonical
//! shortest form an authenticator writes them.

/// The major type of an unsigned integer.
const UNSIGNED: u8 = 0;

/// The major type of a negative integer.
const NEGATIVE: u8 = 1;

/// The major type of a byte string.
const BYTES: u8 = 2;

/// The major type of a text string.
const TEXT: u8 = 3;

/// The major type of a map.
const MAP: u8 = 5;

/// The head of an item of `major` type with the argument `argument`, in
/// its shortest form.
fn head(major: u8, argument: u64) -> Vec<u8> {
    let kind = major << 5;
    match argument {
        0..=23 => vec![kind | argument as u8],
        24..=0xff => vec![kind | 24, argument as u8],
        0x100..=0xffff => [vec![kind | 25], (argument as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => {
            [vec![kind | 26], (argument as u32).to_be_bytes().to_vec()].concat()
        }
        _ => [vec![kind | 27], argument.to_be_bytes().to_vec()].concat(),
    }
}

/// `value` as a CBOR integer.
pub(crate) fn integer(value: i64) -> Vec<u8> {
    if value >= 0 {
        return head(UNSIGNED, value.unsigned_abs());
    }
    head(NEGATIVE, (-1 - value).unsigned_abs())
}

/// `bytes` as a CBOR byte string.
pub(crate) fn bytes(bytes: &[u8]) -> Vec<u8> {
    [head(BYTES, bytes.len() as u64), bytes.to_vec()].concat()
}

/// `text` as a CBOR text string.
pub(crate) fn text(text: &str) -> Vec<u8> {
    [head(TEXT, text.len() as u64), text.as_bytes().to_vec()].concat()
}

/// A CBOR map of `entries`, each an encoded key and an encoded value, in
/// the order given.
pub(crate) fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut encoded = head(MAP, entries.len() as u64);
    for (key, value) in entries {
        encoded.extend_from_slice(key);
        encoded.extend_from_slice(value);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The integers a COSE key uses are written as RFC 8949's examples.
    #[test]
    fn integers_are_written_as_the_rfc_writes_them() {
        assert_eq!(integer(1), [0x01]);
        assert_eq!(integer(-1), [0x20]);
        assert_eq!(integer(-7), [0x26]);
        assert_eq!(integer(24), [0x18, 0x18]);
        assert_eq!(integer(-100), [0x38, 0x63]);
        assert_eq!(integer(1000), [0x19, 0x03, 0xe8]);
    }

    /// A 32-byte coordinate takes a one-byte length.
    #[test]
    fn a_coordinate_takes_a_one_byte_length() {
        let encoded = bytes(&[7; 32]);

        assert_eq!(&encoded[..2], [0x58, 0x20]);
        assert_eq!(encoded.len(), 34);
    }

    /// An empty map is one byte, and a map with a text key is written in
    /// order.
    #[test]
    fn maps_are_written_in_order() {
        assert_eq!(map(&[]), [0xa0]);
        assert_eq!(map(&[(text("a"), integer(1))]), [0xa1, 0x61, b'a', 0x01]);
    }
}
