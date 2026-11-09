//! Who manages a signal stream: a person of the tenant, or the stream's
//! own receiver, signed in with the key it was handed when the stream was
//! registered.
//!
//! A receiver polls its stream, asks it for verification events and says
//! whom it hears about. It never needs one of the tenant's API keys, which
//! reach every stream and every user, so the key it presents manages its
//! own stream and nothing else.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::signals::receiver::{StreamAuthority, StreamReceiver};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SignalStreamId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::signals::{ReceiverKeys, SignalStreamStore};
use crate::tenancy::ScopedTenant;

/// A stream's receiver calling with its own key.
///
/// No `Debug`: it carries the raw key.
pub struct ReceiverCaller {
    /// The tenant the request was addressed to.
    pub tenant: ScopedTenant,
    /// The stream the receiver says it manages.
    pub stream_id: SignalStreamId,
    /// The key it presented.
    pub key: Secret,
}

/// Who calls a signals use case open to people and receivers alike.
// A caller is made once per request and only ever lent out, so the size of
// the person's context costs one copy, not one per call.
#[allow(clippy::large_enum_variant)]
pub enum SignalsCaller {
    /// A person acting in their tenant.
    Person(CallerContext),
    /// A stream's receiver calling with the stream's key.
    Receiver(ReceiverCaller),
}

impl SignalsCaller {
    /// The tenant the caller acts in.
    #[must_use]
    pub fn tenant(&self) -> ScopedTenant {
        match self {
            Self::Person(caller) => caller.tenant(),
            Self::Receiver(caller) => caller.tenant,
        }
    }

    /// The actor an audit record names: the person, or the platform for a
    /// receiver, as for a tenant's directory, with the stream the record
    /// names.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        match self {
            Self::Person(caller) => caller.actor(),
            Self::Receiver(_) => ActorRef::System,
        }
    }
}

/// Where a receiver's key is checked.
pub(super) struct ReceiverSignIn<'a> {
    /// The tenant's streams, each holding its receiver's key digest.
    pub(super) streams: &'a dyn SignalStreamStore,
    /// Hashes the presented key.
    pub(super) keys: &'a dyn ReceiverKeys,
}

/// A signals caller, worked out into what the domain asks for.
pub(super) enum StreamActor {
    /// A person, with what they hold in the tenant now.
    Person(TenantAuthority),
    /// A receiver, signed in with its stream's key.
    Receiver(StreamReceiver),
}

impl StreamActor {
    /// What `caller` acts with: a person's authority from `people`, or a
    /// receiver signed in through `receivers`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key no longer
    ///   counts, or the receiver's key is not its stream's: which of those
    ///   is never said.
    /// - `AppError::Forbidden` when the person may not act in the tenant.
    /// - `AppError::Internal` when a store fails.
    pub(super) async fn of(
        caller: &SignalsCaller,
        people: &dyn TenantAuthorities,
        receivers: ReceiverSignIn<'_>,
    ) -> Result<Self, AppError> {
        match caller {
            SignalsCaller::Person(caller) => Ok(Self::Person(people.authority(caller).await?)),
            SignalsCaller::Receiver(caller) => {
                Ok(Self::Receiver(signed_in_receiver(receivers, caller).await?))
            }
        }
    }

    /// Who manages, as the domain's rules ask it.
    pub(super) fn manager(&self) -> StreamAuthority<'_, TenantAuthority> {
        match self {
            Self::Person(authority) => StreamAuthority::Person(authority),
            Self::Receiver(receiver) => StreamAuthority::Receiver(receiver),
        }
    }
}

/// The receiver of the stream `caller` names, once the key it presented is
/// that stream's.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the key is malformed, the stream is
///   unknown, or the key is not its own.
/// - `AppError::Internal` when the stream cannot be read.
async fn signed_in_receiver(
    receivers: ReceiverSignIn<'_>,
    caller: &ReceiverCaller,
) -> Result<StreamReceiver, AppError> {
    validate_token("receiver_key", caller.key.expose()).map_err(|_| AppError::Unauthenticated)?;
    let stream = receivers
        .streams
        .find_by_id(&caller.tenant, &caller.stream_id)
        .await
        .or_internal()?
        .ok_or(AppError::Unauthenticated)?;
    let presented = receivers.keys.hash_presented(&caller.key);
    stream
        .sign_in_receiver(&presented)
        .map_err(|_| AppError::Unauthenticated)
}
