//! The OAuth use cases the API serves: a tenant's clients, API keys and
//! initial access tokens, apps registering and managing themselves, the
//! browser and device flows, signing out through an app, `userinfo`, and
//! the token endpoint with introspection and revocation beside it.
//!
//! Expiring device requests and API keys, stamping a key's last use and
//! telling apps of a sign-out over the back channel run elsewhere: on the
//! server's worker and in the auth middleware.

use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::oauth::presented::PresentedTokenPorts;
use ianua_app::use_cases::oauth::registration::managed::SelfManagementPorts;
use ianua_app::use_cases::oauth::sender::SenderProofPorts;
use ianua_app::use_cases::oauth::token::client_auth::ClientAuthPorts;
use ianua_app::use_cases::oauth::token::issuing::{IssuedTokens, IssuingPorts};
use ianua_app::use_cases::oauth::token::refusal::TokenError;
use ianua_app::use_cases::oauth::{api_keys, clients, flows, registration, token};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::types::HttpsUrl;

use crate::deps::{Adapters, Settings};

/// The OAuth use cases, and the base URL a tenant's issuer is named under.
#[derive(Clone)]
pub struct OAuthState {
    pub app_base_url: HttpsUrl,
    pub clients: ClientUseCases,
    pub api_keys: ApiKeyUseCases,
    pub browser: BrowserUseCases,
    pub device: DeviceUseCases,
    pub tokens: TokenUseCases,
    pub registration: RegistrationUseCases,
}

/// A tenant's OAuth clients, and the apps a person authorized.
#[derive(Clone)]
pub struct ClientUseCases {
    pub create: Arc<clients::CreateUseCase>,
    pub list: Arc<clients::ListUseCase>,
    pub get: Arc<clients::GetUseCase>,
    pub update: Arc<clients::UpdateUseCase>,
    pub revoke: Arc<clients::RevokeUseCase>,
    pub rotate_secret: Arc<clients::RotateSecretUseCase>,
    pub revoke_consent: Arc<clients::RevokeConsentUseCase>,
    pub list_my_apps: Arc<clients::ListMyAppsUseCase>,
}

/// A tenant's API keys.
#[derive(Clone)]
pub struct ApiKeyUseCases {
    pub create: Arc<api_keys::CreateUseCase>,
    pub list: Arc<api_keys::ListUseCase>,
    pub get: Arc<api_keys::GetUseCase>,
    pub update: Arc<api_keys::UpdateUseCase>,
    pub revoke: Arc<api_keys::RevokeUseCase>,
    pub pause: Arc<api_keys::PauseUseCase>,
    pub resume: Arc<api_keys::ResumeUseCase>,
    pub record_use: Arc<api_keys::RecordUseUseCase>,
}

/// The browser's flows: screening and pushing an authorization request,
/// the consent step, and signing out through an app.
#[derive(Clone)]
pub struct BrowserUseCases {
    pub screen: Arc<flows::ScreenAuthorizationUseCase>,
    pub authorize: Arc<flows::AuthorizeUseCase>,
    pub push: Arc<flows::PushAuthorizationRequestUseCase>,
    pub end_session: Arc<flows::EndSessionUseCase>,
}

/// The device flow: the device asking for its codes, and the person
/// answering it on another screen.
#[derive(Clone)]
pub struct DeviceUseCases {
    pub request_code: Arc<flows::RequestDeviceCodeUseCase>,
    pub approve: Arc<flows::ApproveDeviceUseCase>,
    pub deny: Arc<flows::DenyDeviceUseCase>,
}

/// The token endpoint, the endpoints beside it, and `userinfo`.
#[derive(Clone)]
pub struct TokenUseCases {
    pub grants: TokenGrants,
    pub introspect: Arc<token::IntrospectUseCase>,
    pub revoke: Arc<token::RevokeUseCase>,
    pub userinfo: Arc<flows::UserInfoUseCase>,
}

/// Apps registering and managing themselves, and the initial access tokens
/// that let them.
#[derive(Clone)]
pub struct RegistrationUseCases {
    pub register: Arc<registration::RegisterClientUseCase>,
    pub read: Arc<registration::ReadUseCase>,
    pub update: Arc<registration::UpdateUseCase>,
    pub delete: Arc<registration::DeleteUseCase>,
    pub issue_token: Arc<registration::IssueInitialAccessTokenUseCase>,
    pub list_tokens: Arc<registration::ListInitialAccessTokensUseCase>,
    pub revoke_token: Arc<registration::RevokeInitialAccessTokenUseCase>,
}

/// One use case per grant the token endpoint answers.
#[derive(Clone)]
pub struct TokenGrants {
    code: Arc<token::RedeemCodeUseCase>,
    refresh: Arc<token::RefreshTokensUseCase>,
    client_credentials: Arc<token::ClientCredentialsUseCase>,
    device_code: Arc<token::CollectDeviceTokensUseCase>,
    exchange: Arc<token::ExchangeUseCase>,
}

/// A request at the token endpoint, by the `grant_type` it named.
pub enum TokenGrant {
    /// Redeems a browser authorization with its bound redirect and PKCE proof.
    AuthorizationCode(token::CodeGrant),
    /// Exchanges an existing credential for fresh tokens.
    RefreshToken(token::RefreshGrant),
    /// Issues tokens for the authenticated application acting in its own name.
    ClientCredentials(token::ClientCredentialsGrant),
    /// `urn:ietf:params:oauth:grant-type:device_code`.
    DeviceCode(token::DeviceCodeGrant),
    /// `urn:ietf:params:oauth:grant-type:token-exchange`.
    TokenExchange(token::ExchangeGrant),
}

/// What the token endpoint hands out, and whether it answered an exchange,
/// whose answer names the kind of token issued (RFC 8693 2.2.1).
pub enum IssuedGrant {
    /// Tokens for any grant but an exchange.
    Granted(IssuedTokens),
    /// The access token a token exchange issued.
    Exchanged(IssuedTokens),
}

impl TokenGrants {
    /// The tokens `grant` is answered with in `tenant`, its events recorded
    /// through `auditor`.
    ///
    /// # Errors
    ///
    /// - The [`TokenError`] the grant's use case answers.
    pub async fn issue(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: TokenGrant,
    ) -> Result<IssuedGrant, TokenError> {
        let granted = match grant {
            TokenGrant::AuthorizationCode(grant) => {
                self.code.execute(tenant, auditor, grant).await?
            }
            TokenGrant::RefreshToken(grant) => self.refresh.execute(tenant, auditor, grant).await?,
            TokenGrant::ClientCredentials(grant) => {
                self.client_credentials
                    .execute(tenant, auditor, grant)
                    .await?
            }
            TokenGrant::DeviceCode(grant) => {
                self.device_code.execute(tenant, auditor, grant).await?
            }
            TokenGrant::TokenExchange(grant) => {
                let exchanged = self.exchange.execute(tenant, auditor, grant).await?;
                return Ok(IssuedGrant::Exchanged(exchanged));
            }
        };
        Ok(IssuedGrant::Granted(granted))
    }
}

/// Builds the OAuth use cases over `a`, with the token terms, device code
/// timing and addresses `s` gives.
pub fn build(a: &Adapters, s: &Settings) -> OAuthState {
    OAuthState {
        app_base_url: s.app_base_url.clone(),
        clients: client_use_cases(a),
        api_keys: api_key_use_cases(a),
        browser: browser_use_cases(a),
        device: device_use_cases(a, s),
        tokens: token_use_cases(a, s.tunables.token_terms),
        registration: registration_use_cases(a),
    }
}

/// The client use cases over `a`.
fn client_use_cases(a: &Adapters) -> ClientUseCases {
    ClientUseCases {
        create: Arc::new(create_client(a)),
        list: Arc::new(clients::ListUseCase::new(clients::ListPorts {
            client_store: a.o_auth_client_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(clients::GetUseCase::new(clients::GetPorts {
            client_store: a.o_auth_client_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(clients::UpdateUseCase::new(clients::UpdatePorts {
            client_store: a.o_auth_client_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        revoke: Arc::new(clients::RevokeUseCase::new(clients::RevokePorts {
            client_store: a.o_auth_client_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        rotate_secret: Arc::new(rotate_client_secret(a)),
        revoke_consent: Arc::new(revoke_consent(a)),
        list_my_apps: Arc::new(clients::ListMyAppsUseCase::new(clients::ListMyAppsPorts {
            consent_store: a.o_auth_consent_store.clone(),
            client_store: a.o_auth_client_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Creates tenant clients with generated secrets and plan enforcement.
fn create_client(a: &Adapters) -> clients::CreateUseCase {
    clients::CreateUseCase::new(clients::CreatePorts {
        client_store: a.o_auth_client_store.clone(),
        secret_generator: a.client_secret_generator.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Rotates client secrets under the caller's tenant authority.
fn rotate_client_secret(a: &Adapters) -> clients::RotateSecretUseCase {
    clients::RotateSecretUseCase::new(clients::RotateSecretPorts {
        client_store: a.o_auth_client_store.clone(),
        secret_generator: a.client_secret_generator.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Withdraws consent together with its access and refresh credentials.
fn revoke_consent(a: &Adapters) -> clients::RevokeConsentUseCase {
    clients::RevokeConsentUseCase::new(clients::RevokeConsentPorts {
        client_store: a.o_auth_client_store.clone(),
        consent_store: a.o_auth_consent_store.clone(),
        access_token_store: a.access_token_store.clone(),
        refresh_token_store: a.refresh_token_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The API key use cases over `a`.
fn api_key_use_cases(a: &Adapters) -> ApiKeyUseCases {
    ApiKeyUseCases {
        create: Arc::new(create_api_key(a)),
        list: Arc::new(api_keys::ListUseCase::new(api_keys::ListPorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(api_keys::GetUseCase::new(api_keys::GetPorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(api_keys::UpdateUseCase::new(api_keys::UpdatePorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        revoke: Arc::new(api_keys::RevokeUseCase::new(api_keys::RevokePorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        pause: Arc::new(api_keys::PauseUseCase::new(api_keys::PausePorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        resume: Arc::new(api_keys::ResumeUseCase::new(api_keys::ResumePorts {
            key_store: a.api_key_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        record_use: Arc::new(record_api_key_use(a)),
    }
}

/// Stamps a key used, and records a country it never signed in from.
fn record_api_key_use(a: &Adapters) -> api_keys::RecordUseUseCase {
    api_keys::RecordUseUseCase::new(api_keys::RecordUsePorts {
        key_store: a.api_key_store.clone(),
        geolocator: a.geolocator.clone(),
    })
}

/// Issues API keys under tenant authority and the plan's resource limit.
fn create_api_key(a: &Adapters) -> api_keys::CreateUseCase {
    api_keys::CreateUseCase::new(api_keys::CreatePorts {
        key_store: a.api_key_store.clone(),
        key_generator: a.api_key_generator.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The browser flow use cases over `a`.
fn browser_use_cases(a: &Adapters) -> BrowserUseCases {
    BrowserUseCases {
        screen: Arc::new(flows::ScreenAuthorizationUseCase::new(
            flows::ScreenAuthorizationPorts {
                client_store: a.o_auth_client_store.clone(),
                pushed_store: a.pushed_request_store.clone(),
            },
        )),
        authorize: Arc::new(authorize(a)),
        push: Arc::new(flows::PushAuthorizationRequestUseCase::new(
            flows::PushAuthorizationRequestPorts {
                client_auth: client_auth(a),
                pushed_store: a.pushed_request_store.clone(),
            },
        )),
        end_session: Arc::new(flows::EndSessionUseCase::new(flows::EndSessionPorts {
            client_store: a.o_auth_client_store.clone(),
            hint_verifier: a.id_token_hint_verifier.clone(),
            key_store: a.signing_key_store.clone(),
            session_store: a.session_store.clone(),
            refresh_token_store: a.refresh_token_store.clone(),
            auth_code_store: a.auth_code_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Authorizes browser requests using stored consent, pushed requests and token hints.
fn authorize(a: &Adapters) -> flows::AuthorizeUseCase {
    flows::AuthorizeUseCase::new(flows::AuthorizePorts {
        client_store: a.o_auth_client_store.clone(),
        auth_code_store: a.auth_code_store.clone(),
        consent_store: a.o_auth_consent_store.clone(),
        code_hasher: a.code_hasher.clone(),
        pushed_store: a.pushed_request_store.clone(),
        hint_verifier: a.id_token_hint_verifier.clone(),
        key_store: a.signing_key_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The device flow use cases over `a`, sending people where `s` says.
fn device_use_cases(a: &Adapters, s: &Settings) -> DeviceUseCases {
    DeviceUseCases {
        request_code: Arc::new(flows::RequestDeviceCodeUseCase::new(
            flows::RequestDeviceCodePorts {
                client_auth: client_auth(a),
                device_auth_store: a.device_auth_store.clone(),
                code_hasher: a.code_hasher.clone(),
            },
            s.device_verification_uri.clone(),
            s.tunables.device_code,
        )),
        approve: Arc::new(flows::ApproveDeviceUseCase::new(
            flows::ApproveDevicePorts {
                device_auth_store: a.device_auth_store.clone(),
                audit_label_resolver: a.audit_label_resolver.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        deny: Arc::new(flows::DenyDeviceUseCase::new(flows::DenyDevicePorts {
            device_auth_store: a.device_auth_store.clone(),
            audit_label_resolver: a.audit_label_resolver.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The token endpoint's use cases over `a`, issuing on the platform's
/// `terms` for every client without its own.
fn token_use_cases(a: &Adapters, terms: TokenTerms) -> TokenUseCases {
    TokenUseCases {
        grants: token_grants(a, terms),
        introspect: Arc::new(token::IntrospectUseCase::new(token::IntrospectPorts {
            client_auth: client_auth(a),
            presented: presented(a),
            users: a.user_store.clone(),
        })),
        revoke: Arc::new(token::RevokeUseCase::new(token::RevokePorts {
            client_auth: client_auth(a),
            presented: presented(a),
            refresh_token_store: a.refresh_token_store.clone(),
        })),
        userinfo: Arc::new(flows::UserInfoUseCase::new(flows::UserInfoPorts {
            presented: presented(a),
            client_store: a.o_auth_client_store.clone(),
            users: a.user_store.clone(),
            roles: a.role_store.clone(),
            sender: sender(a),
        })),
    }
}

/// One use case per grant over `a`, on the platform's `terms`.
fn token_grants(a: &Adapters, terms: TokenTerms) -> TokenGrants {
    TokenGrants {
        code: Arc::new(redeem_code(a, terms)),
        refresh: Arc::new(refresh_tokens(a, terms)),
        client_credentials: Arc::new(token::ClientCredentialsUseCase::new(
            terms,
            token::ClientCredentialsPorts {
                client_auth: client_auth(a),
                issuing: issuing(a),
            },
        )),
        device_code: Arc::new(token::CollectDeviceTokensUseCase::new(
            terms,
            token::CollectDeviceTokensPorts {
                client_auth: client_auth(a),
                issuing: issuing(a),
                device_auth_store: a.device_auth_store.clone(),
            },
        )),
        exchange: Arc::new(token::ExchangeUseCase::new(
            terms,
            token::ExchangePorts {
                client_auth: client_auth(a),
                issuing: issuing(a),
                presented: presented(a),
            },
        )),
    }
}

/// Redeems authorization codes with client authentication, PKCE and session checks.
fn redeem_code(a: &Adapters, terms: TokenTerms) -> token::RedeemCodeUseCase {
    token::RedeemCodeUseCase::new(
        terms,
        token::RedeemCodePorts {
            client_auth: client_auth(a),
            issuing: issuing(a),
            auth_code_store: a.auth_code_store.clone(),
            pkce_verifier: a.pkce_verifier.clone(),
            session_store: a.session_store.clone(),
        },
    )
}

/// Refreshes client credentials while checking the backing session.
fn refresh_tokens(a: &Adapters, terms: TokenTerms) -> token::RefreshTokensUseCase {
    token::RefreshTokensUseCase::new(
        terms,
        token::RefreshTokensPorts {
            client_auth: client_auth(a),
            issuing: issuing(a),
            session_store: a.session_store.clone(),
        },
    )
}

/// The registration use cases over `a`.
fn registration_use_cases(a: &Adapters) -> RegistrationUseCases {
    RegistrationUseCases {
        register: Arc::new(register_client(a)),
        read: Arc::new(registration::ReadUseCase::new(self_management(a))),
        update: Arc::new(registration::UpdateUseCase::new(self_management(a))),
        delete: Arc::new(registration::DeleteUseCase::new(self_management(a))),
        issue_token: Arc::new(registration::IssueInitialAccessTokenUseCase::new(
            registration::IssueInitialAccessTokenPorts {
                token_store: a.initial_access_token_store.clone(),
                code_hasher: a.code_hasher.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list_tokens: Arc::new(registration::ListInitialAccessTokensUseCase::new(
            registration::ListInitialAccessTokensPorts {
                token_store: a.initial_access_token_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        revoke_token: Arc::new(registration::RevokeInitialAccessTokenUseCase::new(
            registration::RevokeInitialAccessTokenPorts {
                token_store: a.initial_access_token_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// Registers clients using initial access tokens and the tenant's plan limits.
fn register_client(a: &Adapters) -> registration::RegisterClientUseCase {
    registration::RegisterClientUseCase::new(registration::RegisterClientPorts {
        token_store: a.initial_access_token_store.clone(),
        client_store: a.o_auth_client_store.clone(),
        code_hasher: a.code_hasher.clone(),
        secret_generator: a.client_secret_generator.clone(),
        plan_limits: a.plan_limits_source.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
    })
}

/// How a client proves itself where tokens are handed out or checked.
fn client_auth(a: &Adapters) -> ClientAuthPorts {
    ClientAuthPorts {
        client_store: a.o_auth_client_store.clone(),
        secret_verifier: a.client_secret_verifier.clone(),
        assertion_verifier: a.client_assertion_verifier.clone(),
        replay_guard: a.client_assertion_replay_guard.clone(),
    }
}

/// How the tokens a grant hands out are made and kept.
fn issuing(a: &Adapters) -> IssuingPorts {
    IssuingPorts {
        code_hasher: a.code_hasher.clone(),
        access_token_store: a.access_token_store.clone(),
        refresh_token_store: a.refresh_token_store.clone(),
        key_store: a.signing_key_store.clone(),
        jwt_signer: a.jwt_signer.clone(),
        at_hash: a.at_hash_calculator.clone(),
        users: a.user_store.clone(),
        roles: a.role_store.clone(),
        stream_routes: a.stream_route_store.clone(),
        sender: sender(a),
    }
}

/// How what a request proves about its holder is checked.
fn sender(a: &Adapters) -> SenderProofPorts {
    SenderProofPorts {
        dpop_verifier: a.dpop_proof_verifier.clone(),
        dpop_replays: a.dpop_replay_guard.clone(),
    }
}

/// How a presented access token's record is found.
fn presented(a: &Adapters) -> PresentedTokenPorts {
    PresentedTokenPorts {
        access_token_store: a.access_token_store.clone(),
        code_hasher: a.code_hasher.clone(),
        key_store: a.verifying_key_store.clone(),
        jwt_verifier: a.access_token_jwt_verifier.clone(),
    }
}

/// How an app proves it manages its own registration.
fn self_management(a: &Adapters) -> SelfManagementPorts {
    SelfManagementPorts {
        client_store: a.o_auth_client_store.clone(),
        code_hasher: a.code_hasher.clone(),
    }
}
