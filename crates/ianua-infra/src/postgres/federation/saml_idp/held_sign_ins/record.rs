//! A sign-in request held until it is answered, as its row holds it: the
//! port's own value, kept as it arrived.

use ianua_app::ports::federation::{
    HeldSamlSignIn, InboundSamlMessage, RedirectSignature, SamlBinding,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlArrivalId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::federation::saml_idp::held_sign_ins::words::BindingKind;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const HELD: Stored = Stored("held SAML sign-in");

/// A held request as it is read. The store's checked queries fill it.
pub(super) struct HeldRecord {
    pub(super) id: Uuid,
    pub(super) binding: String,
    pub(super) signature_algorithm: Option<String>,
    pub(super) signature: Option<String>,
    pub(super) signed_query: Option<String>,
    pub(super) message: String,
    pub(super) relay_state: Option<String>,
    pub(super) arrived_at: OffsetDateTime,
}

impl HeldRecord {
    /// The request the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the binding is unknown,
    /// or the row holds part of a signature but not all of it, or one for
    /// a posted message.
    pub(super) fn into_held(self) -> Result<HeldSamlSignIn, DomainError> {
        let binding = binding_from(
            HELD.choice(&self.binding)?,
            (self.signature_algorithm, self.signature, self.signed_query),
        )?;
        Ok(HeldSamlSignIn {
            id: SamlArrivalId::from_uuid(self.id),
            message: InboundSamlMessage {
                binding,
                message: self.message,
            },
            relay_state: self.relay_state,
            arrived_at: self.arrived_at,
        })
    }
}

type StoredSignature = (Option<String>, Option<String>, Option<String>);

fn binding_from(kind: BindingKind, signature: StoredSignature) -> Result<SamlBinding, DomainError> {
    match (kind, signature) {
        (BindingKind::Post, (None, None, None)) => Ok(SamlBinding::Post),
        (BindingKind::Redirect, (None, None, None)) => {
            Ok(SamlBinding::Redirect(RedirectSignature::Absent))
        }
        (BindingKind::Redirect, (Some(algorithm), Some(signature), Some(signed_query))) => {
            Ok(SamlBinding::Redirect(RedirectSignature::Present {
                algorithm,
                signature,
                signed_query,
            }))
        }
        (BindingKind::Post | BindingKind::Redirect, _) => Err(DomainError::corrupt_row(
            HELD.0,
            "part of a signature, or one beside a posted message",
        )),
    }
}

/// A held request's columns, as they are written.
pub(super) struct HeldColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) binding: &'static str,
    pub(super) signature_algorithm: Option<&'a str>,
    pub(super) signature: Option<&'a str>,
    pub(super) signed_query: Option<&'a str>,
    pub(super) message: &'a str,
    pub(super) relay_state: Option<&'a str>,
    pub(super) arrived_at: OffsetDateTime,
}

impl<'a> HeldColumns<'a> {
    /// The columns `held` is written to.
    pub(super) fn of(held: &'a HeldSamlSignIn) -> Self {
        let (kind, signature) = match &held.message.binding {
            SamlBinding::Post => (BindingKind::Post, None),
            SamlBinding::Redirect(RedirectSignature::Absent) => (BindingKind::Redirect, None),
            SamlBinding::Redirect(RedirectSignature::Present {
                algorithm,
                signature,
                signed_query,
            }) => (
                BindingKind::Redirect,
                Some((
                    algorithm.as_str(),
                    signature.as_str(),
                    signed_query.as_str(),
                )),
            ),
        };
        Self {
            id: held.id.as_uuid(),
            binding: kind.word(),
            signature_algorithm: signature.map(|parts| parts.0),
            signature: signature.map(|parts| parts.1),
            signed_query: signature.map(|parts| parts.2),
            message: held.message.message.as_str(),
            relay_state: held.relay_state.as_deref(),
            arrived_at: held.arrived_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A redirect binding with a signature algorithm but no signature or
    /// signed query is rejected as corrupt storage.
    #[test]
    fn part_of_a_signature_is_refused() {
        let read = binding_from(
            BindingKind::Redirect,
            (Some("rsa-sha256".to_owned()), None, None),
        );

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
