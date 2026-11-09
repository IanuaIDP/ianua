//! The `Authorization` header a receiver asks its pushes to carry: checked,
//! then sealed before the stream keeps it.
//!
//! The value is the receiver's own credential for its endpoint. Kept as
//! typed, anyone who could read the streams table could post to the
//! receiver as the transmitter, so only its sealed form is stored, and it
//! is opened for one push at a time.

use ianua_domain::domains::signals::delivery::ReceiverAuthorization;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SignalStreamId;

use crate::error::AppError;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// The longest header value a receiver may ask for, in bytes.
const MOST_HEADER_BYTES: usize = 4096;

/// What a receiver asks its pushes to send in the `Authorization` header.
pub enum ReceiverHeader {
    /// No header.
    NotRequired,
    /// This value, such as `Bearer` followed by the receiver's token.
    Header(Secret),
}

/// Where `tenant`'s stream `stream` keeps the header its receiver asked
/// for.
pub(crate) fn header_place(tenant: &ScopedTenant, stream: &SignalStreamId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::SignalReceiverHeader,
        stream,
    )
}

/// `header` as the stream keeps it: nothing, or the value sealed for
/// `place`.
///
/// # Errors
///
/// - `AppError::Domain` when the value is empty, too long, or holds a
///   character a header may not, such as a line break that would let it
///   write headers of its own.
/// - `AppError::Internal` when it cannot be sealed.
pub(in crate::use_cases::signals::streams) async fn sealed_header(
    encryptor: &dyn SecretEncryptor,
    header: ReceiverHeader,
    place: &SealedFor,
) -> Result<ReceiverAuthorization, AppError> {
    let ReceiverHeader::Header(value) = header else {
        return Ok(ReceiverAuthorization::NotRequired);
    };
    ensure_header_value(&value)?;
    let sealed = sealed_text(encryptor, value.expose(), place).await?;
    Ok(ReceiverAuthorization::Header(sealed))
}

/// Refuses a header value that is empty, longer than
/// [`MOST_HEADER_BYTES`], or holds anything but visible characters and
/// spaces.
///
/// # Errors
///
/// `AppError::Domain` when the value is refused.
fn ensure_header_value(value: &Secret) -> Result<(), AppError> {
    let text = value.expose();
    let fits = !text.is_empty()
        && text.len() <= MOST_HEADER_BYTES
        && text
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic());
    if fits {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "signals-the-authorization-header-is-1-to",
        "the authorization header is 1 to 4096 visible characters"
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::{block_on, test_ctx};

    fn place() -> SealedFor {
        header_place(&test_ctx().tenant(), &SignalStreamId::new())
    }

    /// Ann's receiver asks for `Bearer rcv-token`. Only its sealed form is
    /// kept.
    #[test]
    fn a_header_is_kept_sealed() {
        let header = ReceiverHeader::Header(Secret::new("Bearer rcv-token"));

        let place = place();

        let kept = block_on(sealed_header(&FakeEncryptor, header, &place)).unwrap();

        assert_eq!(
            kept,
            ReceiverAuthorization::Header(FakeEncryptor::sealed_for("Bearer rcv-token", &place))
        );
    }

    /// A receiver that asks for no header has none kept.
    #[test]
    fn no_header_keeps_nothing() {
        let kept = block_on(sealed_header(
            &FakeEncryptor,
            ReceiverHeader::NotRequired,
            &place(),
        ))
        .unwrap();

        assert_eq!(kept, ReceiverAuthorization::NotRequired);
    }

    /// Header values containing a line break or no characters return a
    /// domain error when prepared for storage.
    #[test]
    fn a_value_with_a_line_break_or_nothing_is_refused() {
        for value in ["Bearer a\r\nX-Admin: yes", ""] {
            let header = ReceiverHeader::Header(Secret::new(value));

            let result = block_on(sealed_header(&FakeEncryptor, header, &place()));

            assert!(matches!(result, Err(AppError::Domain(_))), "{value:?}");
        }
    }
}
