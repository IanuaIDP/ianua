//! The roots every key is derived from, and every seal and digest built
//! from the right one.
//!
//! Two roots, kept apart. The shared root (`HMAC_SECRET`) is held by the
//! gateway too, so whatever both planes must compute the same comes from
//! it: the digests of handed-out secrets, the app sign-in and approval
//! request seals, and the data plane's own seals, which the control
//! plane checks. The control
//! plane's root (`EVENT_SIGNING_SECRET`) is never given to the gateway, so
//! whatever the gateway must not be able to forge or work out comes from
//! it: the seals on events, live updates, delivery receipts and the audit
//! chain, the passkey ceremony state, the export file links and the SAML
//! pairwise ids. Every control plane replica holds the same control root,
//! so each still derives the same as the others.

use std::sync::Arc;

use ianua_boot::foundation::CryptoConfig;
use ianua_infra::crypto::{
    AuditChainSeals, BroadcastCheck, BroadcastSeal, EventCheck, EventSeal, HmacApiKeyGenerator,
    HmacClientSecretGenerator, HmacClientSecretVerifier, HmacCodeHasher, HmacConnectionSecrets,
    HmacConnectorCodeGenerator, HmacConsumerKeyGenerator, HmacReceiverKeys,
    HmacRecoveryCodeGenerator, HmacRefreshTokenGenerator, HmacRequestSeal, HmacScimTokenGenerator,
    HmacSentCodeGenerator, HmacServiceAccountSecrets, HmacWorkflowTriggerSecretGenerator,
    ReceiptSeal, RootSecret,
};
use ianua_infra::saml::HmacSamlNameIds;

/// The roots and the seals made from them.
#[derive(Debug, Clone)]
pub struct Keys {
    /// The root the gateway holds too. Build from it only what both planes
    /// compute alike.
    pub shared_root: RootSecret,
    /// The control plane's own root, which the gateway never holds: the
    /// passkey ceremony state and the export file links are made from it,
    /// beside the seals here and the SAML pairwise ids.
    pub control_root: RootSecret,
    /// The control plane's seal on every event the outbox relays.
    pub event_seal: EventSeal,
    /// The data plane's seal, which the inbox drain checks every event
    /// the gateway kept with before it reaches the trail.
    pub data_plane_seal: EventSeal,
    /// The check every consumer, and the store caches' follower, makes on
    /// an event before acting on it: the control plane's seal for any
    /// event, the data plane's for the few it raises.
    pub event_check: EventCheck,
    /// The control plane's seal on the live updates the API and the worker
    /// broadcast.
    pub broadcast_seal: BroadcastSeal,
    /// The check the API's live update subscribers make.
    pub broadcast_check: BroadcastCheck,
    /// The seals on audit chain heads, anchors and verdicts.
    pub audit_chain_seals: AuditChainSeals,
    /// The seal on the agent message plane's delivery receipts.
    pub receipt_seal: ReceiptSeal,
    /// The seal on app sign-in requests between the gateway and the API.
    pub request_seal: Arc<HmacRequestSeal>,
    /// The seal on the gateway's questions about agent approvals, under a
    /// key of that channel alone.
    pub approval_request_seal: Arc<HmacRequestSeal>,
}

/// The keyed digests the platform makes: of every secret it hands out,
/// from the shared root so the gateway's digests match, and the SAML
/// pairwise ids, from the control root, which the gateway has no use for.
#[derive(Debug, Clone)]
pub struct Digests {
    /// API keys of tenants, organizations and operators.
    pub api_keys: Arc<HmacApiKeyGenerator>,
    /// The API keys consumers present at the gateway, made.
    pub consumer_keys: Arc<HmacConsumerKeyGenerator>,
    /// OAuth client secrets, made.
    pub client_secrets: Arc<HmacClientSecretGenerator>,
    /// OAuth client secrets, checked.
    pub client_secret_verifier: Arc<HmacClientSecretVerifier>,
    /// Authorization and device codes.
    pub codes: Arc<HmacCodeHasher>,
    /// One-time codes sent by mail or text.
    pub sent_codes: Arc<HmacSentCodeGenerator>,
    /// MFA recovery codes.
    pub recovery_codes: Arc<HmacRecoveryCodeGenerator>,
    /// Generates and hashes credentials used to renew access tokens.
    pub refresh_tokens: Arc<HmacRefreshTokenGenerator>,
    /// SCIM bearer tokens.
    pub scim_tokens: Arc<HmacScimTokenGenerator>,
    /// The secrets that start a workflow from its webhook.
    pub workflow_triggers: Arc<HmacWorkflowTriggerSecretGenerator>,
    /// The states and one-time codes of account connections by signing in.
    pub connections: Arc<HmacConnectionSecrets>,
    /// The codes a private network connector enrolls with.
    pub connector_codes: Arc<HmacConnectorCodeGenerator>,
    /// The secrets LDAP service accounts bind with.
    pub service_accounts: Arc<HmacServiceAccountSecrets>,
    /// The keys signal receivers present.
    pub receiver_keys: Arc<HmacReceiverKeys>,
    /// The pairwise `NameID`s SAML apps are sent, from the control root.
    pub saml_name_ids: Arc<HmacSamlNameIds>,
}

/// The roots and their seals.
#[must_use]
pub(super) fn keys(crypto: &CryptoConfig) -> Keys {
    let shared = &crypto.shared.shared_root;
    let control = &crypto.control_root;
    Keys {
        event_seal: EventSeal::control_plane(control),
        data_plane_seal: EventSeal::data_plane(shared),
        event_check: EventCheck::new(
            EventSeal::control_plane(control),
            EventSeal::data_plane(shared),
        ),
        broadcast_seal: BroadcastSeal::control_plane(control),
        broadcast_check: BroadcastCheck::new(
            BroadcastSeal::control_plane(control),
            BroadcastSeal::data_plane(shared),
        ),
        audit_chain_seals: AuditChainSeals::new(control),
        receipt_seal: ReceiptSeal::new(control),
        request_seal: Arc::new(HmacRequestSeal::new(shared)),
        approval_request_seal: Arc::new(HmacRequestSeal::approvals(shared)),
        shared_root: shared.clone(),
        control_root: control.clone(),
    }
}

/// The digests, from the shared root but for the SAML pairwise ids.
#[must_use]
pub(super) fn digests(keys: &Keys) -> Digests {
    let root = &keys.shared_root;
    Digests {
        saml_name_ids: Arc::new(HmacSamlNameIds::new(&keys.control_root)),
        api_keys: Arc::new(HmacApiKeyGenerator::new(root)),
        consumer_keys: Arc::new(HmacConsumerKeyGenerator::new(root)),
        client_secrets: Arc::new(HmacClientSecretGenerator::new(root)),
        client_secret_verifier: Arc::new(HmacClientSecretVerifier::new(root)),
        codes: Arc::new(HmacCodeHasher::new(root)),
        sent_codes: Arc::new(HmacSentCodeGenerator::new(root)),
        recovery_codes: Arc::new(HmacRecoveryCodeGenerator::new(root)),
        refresh_tokens: Arc::new(HmacRefreshTokenGenerator::new(root)),
        scim_tokens: Arc::new(HmacScimTokenGenerator::new(root)),
        workflow_triggers: Arc::new(HmacWorkflowTriggerSecretGenerator::new(root)),
        connections: Arc::new(HmacConnectionSecrets::new(root)),
        connector_codes: Arc::new(HmacConnectorCodeGenerator::new(root)),
        service_accounts: Arc::new(HmacServiceAccountSecrets::new(root)),
        receiver_keys: Arc::new(HmacReceiverKeys::new(root)),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::time::Duration;

    use ianua_boot::foundation::{HashSettings, SharedKeys};
    use ianua_infra::crypto::{Argon2Settings, SealingKey};

    use super::*;

    fn crypto() -> CryptoConfig {
        let root = |byte: u8| RootSecret::parse(&format!("{byte:064x}")).unwrap();
        CryptoConfig {
            shared: SharedKeys {
                shared_root: root(1),
                sealing_key: SealingKey::new("k1", [3; 32]).unwrap(),
                retired_keys: Vec::new(),
            },
            control_root: root(2),
            hashing: HashSettings {
                argon2: Argon2Settings::default(),
                concurrency: NonZeroUsize::MIN,
                wait: Duration::from_millis(1),
            },
        }
    }

    /// A tenant-deletion event sealed with the shared root fails the
    /// control plane's event check.
    #[test]
    fn the_event_seal_is_not_made_from_the_shared_root() {
        let keys = keys(&crypto());
        let forged = EventSeal::control_plane(&keys.shared_root)
            .seal("ianua.tenant.x.tenant.deleted", b"{}");

        let holds = keys
            .event_check
            .holds("ianua.tenant.x.tenant.deleted", b"{}", &forged);

        assert!(!holds);
    }

    /// The wired SAML pairwise identifier differs from one computed with
    /// the shared root for the same person and application.
    #[test]
    fn the_saml_pairwise_ids_are_not_made_from_the_shared_root() {
        use ianua_app::ports::federation::SamlNameIds as _;
        use ianua_domain::types::{SamlServiceProviderId, UserId};

        let keys = keys(&crypto());
        let digests = digests(&keys);
        let (app, ann) = (SamlServiceProviderId::new(), UserId::new());

        let made = digests.saml_name_ids.pairwise(&app, &ann).unwrap();
        let guessed = HmacSamlNameIds::new(&keys.shared_root)
            .pairwise(&app, &ann)
            .unwrap();

        assert_ne!(made, guessed);
    }

    /// An event the control plane sealed holds under the check.
    #[test]
    fn an_event_the_control_plane_sealed_holds() {
        let keys = keys(&crypto());
        let subject = "ianua.tenant.x.tenant.deleted";
        let seal = keys.event_seal.seal(subject, b"{}");

        assert!(keys.event_check.holds(subject, b"{}", &seal));
    }

    /// The gateway, holding the shared root, seals an approval question the
    /// API opens; a captured sign-in request does not open as one, nor the
    /// reverse.
    #[test]
    fn the_approval_seal_is_shared_and_apart_from_the_sign_in_seal() {
        use ianua_app::ports::authentication::RequestSeal as _;

        let keys = keys(&crypto());
        let body = br#"{"ask":"spend"}"#;
        let from_the_gateway = HmacRequestSeal::approvals(&crypto().shared.shared_root).seal(body);

        assert!(keys.approval_request_seal.verifies(body, &from_the_gateway));
        assert!(!keys.request_seal.verifies(body, &from_the_gateway));
        assert!(
            !keys
                .approval_request_seal
                .verifies(body, &keys.request_seal.seal(body))
        );
    }
}
