//! The federation use cases the API serves: a tenant's connections to
//! identity providers and what they let a provider do, an account's links
//! to them, the tenant's SCIM switch, the tenant as identity provider to its
//! SAML apps, and single logout both ways.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::use_cases::federation::logout::messages::{LogoutSigner, SessionEnding};
use ianua_app::use_cases::federation::{connections, idp, links, logout, scim, service_providers};
use ianua_domain::types::{HttpsUrl, Lifetime};

use crate::deps::{Adapters, Settings};

/// How long an assertion this platform issues to a SAML app is good for:
/// five minutes, long enough for the browser to post it.
const ASSERTION_LIFETIME: Lifetime = Lifetime::from_secs(NonZeroU32::MIN.saturating_add(299));

/// The federation use cases, and the base URL this platform's SAML
/// endpoints are named under.
#[derive(Clone)]
pub struct FederationState {
    pub app_base_url: HttpsUrl,
    pub connections: ConnectionsState,
    pub links: LinksState,
    pub scim: ScimSwitchState,
    pub idp: IdpState,
    pub apps: SamlAppsState,
    pub logout: LogoutState,
}

/// The use cases over a tenant's connections.
#[derive(Clone)]
pub struct ConnectionsState {
    pub create: Arc<connections::CreateUseCase>,
    pub list: Arc<connections::ListUseCase>,
    pub get: Arc<connections::GetUseCase>,
    pub update: Arc<connections::UpdateUseCase>,
    pub activate: Arc<connections::ActivateUseCase>,
    pub disable: Arc<connections::DisableUseCase>,
    pub delete: Arc<connections::DeleteUseCase>,
    pub discover: Arc<connections::DiscoverUseCase>,
    pub sp_metadata: Arc<connections::SpMetadataUseCase>,
    pub map_groups: Arc<connections::MapProviderGroupsUseCase>,
    pub stop_mapping_groups: Arc<connections::StopMappingGroupsUseCase>,
    pub roll_over_certificate: Arc<connections::RollOverCertificateUseCase>,
    pub require_encrypted_assertions: Arc<connections::RequireEncryptedAssertionsUseCase>,
    pub accept_readable_assertions: Arc<connections::AcceptReadableAssertionsUseCase>,
}

/// The use cases over an account's links to providers.
#[derive(Clone)]
pub struct LinksState {
    pub list: Arc<links::ListUserUseCase>,
    pub reconfirm: Arc<links::ReconfirmUseCase>,
    pub unlink: Arc<links::UnlinkAccountUseCase>,
}

/// The use cases over the tenant's SCIM endpoint.
#[derive(Clone)]
pub struct ScimSwitchState {
    pub get: Arc<scim::GetUseCase>,
    pub enable: Arc<scim::EnableUseCase>,
    pub disable: Arc<scim::DisableUseCase>,
    pub rotate_token: Arc<scim::RotateTokenUseCase>,
    pub update_settings: Arc<scim::UpdateSettingsUseCase>,
}

/// The tenant as identity provider: its metadata, the sign-in requests its
/// SAML apps send, and its answers to them.
#[derive(Clone)]
pub struct IdpState {
    pub metadata: Arc<idp::GetMetadataUseCase>,
    pub receive: Arc<idp::ReceiveSignInUseCase>,
    pub answer: Arc<idp::BuildSamlResponseUseCase>,
    pub assertion_lifetime: Lifetime,
}

/// The use cases over the tenant's SAML apps.
#[derive(Clone)]
pub struct SamlAppsState {
    pub create: Arc<service_providers::CreateUseCase>,
    pub list: Arc<service_providers::ListUseCase>,
    pub get: Arc<service_providers::GetUseCase>,
    pub update: Arc<service_providers::UpdateUseCase>,
    pub change_status: Arc<service_providers::ChangeStatusUseCase>,
    pub delete: Arc<service_providers::DeleteUseCase>,
}

/// Single logout, both ways.
#[derive(Clone)]
pub struct LogoutState {
    pub start: Arc<logout::StartSingleUseCase>,
    pub answer_app: Arc<logout::AnswerAppUseCase>,
    pub answer_provider: Arc<logout::AnswerProviderUseCase>,
    pub take_response: Arc<logout::TakeResponseUseCase>,
}

/// Builds the federation use cases over `a`, naming this platform's SAML
/// endpoints under the base URL `s` gives.
pub fn build(a: &Adapters, s: &Settings) -> FederationState {
    FederationState {
        app_base_url: s.app_base_url.clone(),
        connections: connections_state(a),
        links: links_state(a),
        scim: scim_state(a),
        idp: idp_state(a),
        apps: apps_state(a),
        logout: logout_state(a),
    }
}

/// Builds the connection use cases over `a`.
fn connections_state(a: &Adapters) -> ConnectionsState {
    ConnectionsState {
        create: create_connection(a),
        list: Arc::new(connections::ListUseCase::new(connections::ListPorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(connections::GetUseCase::new(connections::GetPorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: update_connection(a),
        activate: activate_connection(a),
        disable: disable_connection(a),
        delete: delete_connection(a),
        discover: discover_connection(a),
        sp_metadata: sp_metadata(a),
        map_groups: map_groups(a),
        stop_mapping_groups: stop_mapping_groups(a),
        roll_over_certificate: roll_over_certificate(a),
        require_encrypted_assertions: require_encrypted_assertions(a),
        accept_readable_assertions: accept_readable_assertions(a),
    }
}

/// Creates connections with provider validation, domain checks and plan enforcement.
fn create_connection(a: &Adapters) -> Arc<connections::CreateUseCase> {
    Arc::new(connections::CreateUseCase::new(connections::CreatePorts {
        connection_store: a.connection_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_store: a.tenant_store.clone(),
        domain_store: a.registered_domain_store.clone(),
        oidc_validator: a.oidc_validator.clone(),
        metadata_reader: a.saml_metadata_reader.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// Activates a connection through tenant authority checks.
fn activate_connection(a: &Adapters) -> Arc<connections::ActivateUseCase> {
    Arc::new(connections::ActivateUseCase::new(
        connections::ActivatePorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Disables a connection through tenant authority checks.
fn disable_connection(a: &Adapters) -> Arc<connections::DisableUseCase> {
    Arc::new(connections::DisableUseCase::new(
        connections::DisablePorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Deletes a connection through tenant authority checks.
fn delete_connection(a: &Adapters) -> Arc<connections::DeleteUseCase> {
    Arc::new(connections::DeleteUseCase::new(connections::DeletePorts {
        connection_store: a.connection_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// Discovers configured providers through the connection store.
fn discover_connection(a: &Adapters) -> Arc<connections::DiscoverUseCase> {
    Arc::new(connections::DiscoverUseCase::new(
        connections::DiscoverPorts {
            connection_store: a.connection_store.clone(),
        },
    ))
}

/// Stops provider-group mapping through tenant authority checks.
fn stop_mapping_groups(a: &Adapters) -> Arc<connections::StopMappingGroupsUseCase> {
    Arc::new(connections::StopMappingGroupsUseCase::new(
        connections::StopMappingGroupsPorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Rolls over provider certificates through tenant authority checks.
fn roll_over_certificate(a: &Adapters) -> Arc<connections::RollOverCertificateUseCase> {
    Arc::new(connections::RollOverCertificateUseCase::new(
        connections::RollOverCertificatePorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Allows readable assertions through tenant authority checks.
fn accept_readable_assertions(a: &Adapters) -> Arc<connections::AcceptReadableAssertionsUseCase> {
    Arc::new(connections::AcceptReadableAssertionsUseCase::new(
        connections::AcceptReadableAssertionsPorts {
            connection_store: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Builds the use case changing a connection's settings over `a`.
fn update_connection(a: &Adapters) -> Arc<connections::UpdateUseCase> {
    Arc::new(connections::UpdateUseCase::new(connections::UpdatePorts {
        connection_store: a.connection_store.clone(),
        role_store: a.role_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_store: a.tenant_store.clone(),
        domain_store: a.registered_domain_store.clone(),
        oidc_validator: a.oidc_validator.clone(),
        metadata_reader: a.saml_metadata_reader.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// Builds the use case writing a connection's service provider metadata
/// over `a`.
fn sp_metadata(a: &Adapters) -> Arc<connections::SpMetadataUseCase> {
    Arc::new(connections::SpMetadataUseCase::new(
        connections::SpMetadataPorts {
            connection_store: a.connection_store.clone(),
            key_store: a.signing_key_store.clone(),
            certificates: a.signing_certificate_issuer.clone(),
            messages: a.saml_service_provider_messages.clone(),
        },
    ))
}

/// Builds the use case mapping a provider's groups over `a`.
fn map_groups(a: &Adapters) -> Arc<connections::MapProviderGroupsUseCase> {
    Arc::new(connections::MapProviderGroupsUseCase::new(
        connections::MapProviderGroupsPorts {
            connection_store: a.connection_store.clone(),
            access: a.access_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Builds the use case making a connection take only sealed assertions
/// over `a`.
fn require_encrypted_assertions(
    a: &Adapters,
) -> Arc<connections::RequireEncryptedAssertionsUseCase> {
    Arc::new(connections::RequireEncryptedAssertionsUseCase::new(
        connections::RequireEncryptedAssertionsPorts {
            connection_store: a.connection_store.clone(),
            encryption_keys: a.saml_encryption_keys.clone(),
            encryptor: a.secret_encryptor.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        },
    ))
}

/// Builds the link use cases over `a`.
fn links_state(a: &Adapters) -> LinksState {
    LinksState {
        list: Arc::new(links::ListUserUseCase::new(links::ListUserPorts {
            links: a.federated_link_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reconfirm: Arc::new(links::ReconfirmUseCase::new(links::ReconfirmPorts {
            links: a.federated_link_store.clone(),
            connections: a.connection_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            fresh_proofs: a.fresh_proofs.clone(),
        })),
        unlink: Arc::new(links::UnlinkAccountUseCase::new(
            links::UnlinkAccountPorts {
                links: a.federated_link_store.clone(),
                connections: a.connection_store.clone(),
                users: a.user_store.clone(),
                access_records: a.access_record_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Builds the SCIM switch use cases over `a`.
fn scim_state(a: &Adapters) -> ScimSwitchState {
    ScimSwitchState {
        get: Arc::new(scim::GetUseCase::new(scim::GetPorts {
            scim_store: a.scim_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        enable: Arc::new(scim::EnableUseCase::new(scim::EnablePorts {
            scim_store: a.scim_store.clone(),
            token_generator: a.scim_token_generator.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        disable: Arc::new(scim::DisableUseCase::new(scim::DisablePorts {
            scim_store: a.scim_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        rotate_token: Arc::new(scim::RotateTokenUseCase::new(scim::RotateTokenPorts {
            scim_store: a.scim_store.clone(),
            token_generator: a.scim_token_generator.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_settings: Arc::new(scim::UpdateSettingsUseCase::new(
            scim::UpdateSettingsPorts {
                scim_store: a.scim_store.clone(),
                role_store: a.role_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Builds the identity provider use cases over `a`.
fn idp_state(a: &Adapters) -> IdpState {
    IdpState {
        metadata: Arc::new(idp::GetMetadataUseCase::new(idp::GetMetadataPorts {
            key_store: a.signing_key_store.clone(),
            certificates: a.signing_certificate_issuer.clone(),
        })),
        answer: Arc::new(answer_sign_in(a)),
        receive: Arc::new(idp::ReceiveSignInUseCase::new(idp::ReceiveSignInPorts {
            held: a.held_saml_sign_in_store.clone(),
        })),
        assertion_lifetime: ASSERTION_LIFETIME,
    }
}

/// Answers held sign-ins with scoped claims, application sessions and signed assertions.
fn answer_sign_in(a: &Adapters) -> idp::BuildSamlResponseUseCase {
    idp::BuildSamlResponseUseCase::new(idp::BuildSamlResponsePorts {
        tenant_authorities: a.tenant_authorities.clone(),
        app_sessions: a.saml_app_session_store.clone(),
        held: a.held_saml_sign_in_store.clone(),
        provider: idp::SamlProviderPorts {
            service_providers: a.saml_service_provider_store.clone(),
            message_reader: a.saml_message_reader.clone(),
            name_ids: a.saml_name_ids.clone(),
        },
        claims: idp::SamlClaimPorts {
            roles: a.role_store.clone(),
            memberships: a.group_membership_store.clone(),
            groups: a.group_store.clone(),
        },
        signing: idp::SamlSigningPorts {
            key_store: a.signing_key_store.clone(),
            xml_signer: a.xml_signer.clone(),
            encrypter: a.assertion_encrypter.clone(),
        },
    })
}

/// Builds the SAML app use cases over `a`.
fn apps_state(a: &Adapters) -> SamlAppsState {
    let apps = || a.saml_service_provider_store.clone();
    let authorities = || a.tenant_authorities.clone();
    SamlAppsState {
        create: Arc::new(create_app(a)),
        list: Arc::new(service_providers::ListUseCase::new(
            service_providers::ListPorts {
                service_providers: apps(),
                tenant_authorities: authorities(),
            },
        )),
        get: Arc::new(service_providers::GetUseCase::new(
            service_providers::GetPorts {
                service_providers: apps(),
                tenant_authorities: authorities(),
            },
        )),
        update: Arc::new(service_providers::UpdateUseCase::new(
            service_providers::UpdatePorts {
                service_providers: apps(),
                tenant_authorities: authorities(),
            },
        )),
        change_status: Arc::new(change_app_status(a)),
        delete: Arc::new(service_providers::DeleteUseCase::new(
            service_providers::DeletePorts {
                service_providers: apps(),
                tenant_authorities: authorities(),
            },
        )),
    }
}

/// Creates SAML applications under tenant authority and plan limits.
fn create_app(a: &Adapters) -> service_providers::CreateUseCase {
    service_providers::CreateUseCase::new(service_providers::CreatePorts {
        service_providers: a.saml_service_provider_store.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes a SAML application's availability under tenant authority.
fn change_app_status(a: &Adapters) -> service_providers::ChangeStatusUseCase {
    service_providers::ChangeStatusUseCase::new(service_providers::ChangeStatusPorts {
        service_providers: a.saml_service_provider_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Builds the single logout use cases over `a`.
fn logout_state(a: &Adapters) -> LogoutState {
    LogoutState {
        start: Arc::new(start_logout(a)),
        answer_app: Arc::new(answer_app_logout(a)),
        answer_provider: Arc::new(logout::AnswerProviderUseCase::new(
            logout::AnswerProviderPorts {
                tenant_authorities: a.tenant_authorities.clone(),
                connections: a.connection_store.clone(),
                message_reader: a.saml_message_reader.clone(),
                provider_sessions: a.provider_session_store.clone(),
                logout_ledger: a.saml_logout_ledger.clone(),
                ending: session_ending(a),
                signer: logout_signer(a),
            },
        )),
        take_response: Arc::new(logout::TakeResponseUseCase::new(
            logout::TakeResponsePorts {
                message_reader: a.saml_message_reader.clone(),
                service_providers: a.saml_service_provider_store.clone(),
                connections: a.connection_store.clone(),
                sent_requests: a.sent_logout_request_store.clone(),
            },
        )),
    }
}

/// Starts signed logout requests for application and provider sessions.
fn start_logout(a: &Adapters) -> logout::StartSingleUseCase {
    logout::StartSingleUseCase::new(logout::StartSinglePorts {
        tenant_authorities: a.tenant_authorities.clone(),
        app_sessions: a.saml_app_session_store.clone(),
        provider_sessions: a.provider_session_store.clone(),
        service_providers: a.saml_service_provider_store.clone(),
        connections: a.connection_store.clone(),
        sent_requests: a.sent_logout_request_store.clone(),
        signer: logout_signer(a),
    })
}

/// Answers application logout with replay tracking and session termination.
fn answer_app_logout(a: &Adapters) -> logout::AnswerAppUseCase {
    logout::AnswerAppUseCase::new(logout::AnswerAppPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        service_providers: a.saml_service_provider_store.clone(),
        message_reader: a.saml_message_reader.clone(),
        app_sessions: a.saml_app_session_store.clone(),
        logout_ledger: a.saml_logout_ledger.clone(),
        ending: session_ending(a),
        signer: logout_signer(a),
    })
}

/// What signs the logout messages this platform sends, over `a`.
fn logout_signer(a: &Adapters) -> LogoutSigner {
    LogoutSigner {
        key_store: a.signing_key_store.clone(),
        xml_signer: a.xml_signer.clone(),
    }
}

/// What ends a session a peer's logout names, over `a`.
fn session_ending(a: &Adapters) -> SessionEnding {
    SessionEnding {
        sessions: a.session_store.clone(),
    }
}
