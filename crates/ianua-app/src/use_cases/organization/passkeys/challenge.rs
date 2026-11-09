//! The challenge a member's passkey ceremony begins with, and the ceremony
//! for nobody the sign-ins open when no single member is named.

use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::types::{CeremonyId, Lifetime};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::organization::OrgPasskeyCeremonyStore;

/// The challenge a passkey ceremony on the organization plane begins
/// with: adding a passkey, or signing in with one.
pub struct OrgPasskeyStarted {
    /// Names the ceremony the server keeps for this challenge. The client
    /// returns it to finish; it is the only handle they get.
    pub ceremony_id: CeremonyId,
    /// The `WebAuthn` options for the browser.
    pub challenge: Vec<u8>,
}

/// Opens and keeps a sign-in ceremony for nobody, lasting `ttl`, whose
/// answering passkey names its member, and hands back its challenge.
///
/// # Errors
///
/// - `AppError::Internal` when the challenge cannot be made or the
///   ceremony cannot be kept.
pub(in crate::use_cases::organization::passkeys) async fn opened_for_nobody(
    verifier: &dyn PasskeyVerifier,
    ceremonies: &dyn OrgPasskeyCeremonyStore,
    ttl: Lifetime,
) -> Result<OrgPasskeyStarted, AppError> {
    let started = verifier
        .start_discoverable_authentication()
        .await
        .or_internal()?;
    let ceremony = OrgPasskeyCeremony::open_discoverable(started.server_state, ttl);
    ceremonies.save(&ceremony).await.or_internal()?;
    Ok(OrgPasskeyStarted {
        ceremony_id: *ceremony.id(),
        challenge: started.client_payload,
    })
}
