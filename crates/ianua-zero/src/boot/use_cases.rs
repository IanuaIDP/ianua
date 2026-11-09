//! The application's use cases the gateway runs, each built once over the
//! gateway's stores and the adapters it holds.
//!
//! Every decision about a request is one of these: who the caller is, what
//! the route and the tenant's policy allow, whether an agent's action may
//! go ahead, whether a device is healthy, whether a stream connection may
//! open. The gateway only enforces what they answer.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::acting::consumer::{ConsumerActing, ConsumerActingPorts};
use ianua_app::ports::agents::ApprovalBroker;
use ianua_app::ports::authentication::{AppSignInBroker, PresentedTokens};
use ianua_app::ports::proxy::PostureProvider;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::agents::approvals::{GateActionPorts, GateActionUseCase};
use ianua_app::use_cases::agents::enforcement::{
    AdmitActionPorts, AdmitActionUseCase, AgentAuthorityPorts, CheckAgentAuthorityUseCase,
    RecordStolenBindingPorts, RecordStolenBindingUseCase,
};
use ianua_app::use_cases::authentication::sessions::{WatchUsePorts, WatchUseUseCase};
use ianua_app::use_cases::crypto::assertions::{
    GetPublishedPorts, GetPublishedUseCase, SignPorts, SignUseCase,
};
use ianua_app::use_cases::oauth::flows::{ResolveAccessTokenPorts, ResolveAccessTokenUseCase};
use ianua_app::use_cases::oauth::presented::PresentedTokenPorts;
use ianua_app::use_cases::oauth::sender::SenderProofPorts;
use ianua_app::use_cases::proxy::credentials::{
    AgentPorts, AuthenticatePorts, AuthenticateUseCase, ConsumerPorts, PersonPorts,
};
use ianua_app::use_cases::proxy::log_shipping::{
    ShipRequestRecordsPorts, ShipRequestRecordsUseCase,
};
use ianua_app::use_cases::proxy::{
    CheckDevicePosturePorts, CheckDevicePostureUseCase, DecideAccessPorts, DecideAccessUseCase,
    ExchangeTokenPorts, ExchangeTokenUseCase, RecheckConnectionChecks, RecheckConnectionUseCase,
};
use ianua_app::use_cases::routing::stream_routes::{
    AdmitStreamConnectionPorts, AdmitStreamConnectionUseCase, IdentifyStreamCallerPorts,
    IdentifyStreamCallerUseCase,
};
use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
use ianua_infra::cache::{
    CacheAlertThrottle, CacheConsumerQuotaCounter, CacheDpopReplayGuard, CacheEventDispatcher,
};
use ianua_infra::crypto::{
    HmacCodeHasher, HmacConsumerKeyDigests, JwkConsumerTokenVerifier, JwkDpopProofVerifier,
    Pkcs8AccessTokenJwtVerifier, Pkcs8AssertionSigner, Pkcs8PresentedTokens, Pkcs8PublicKeyDecoder,
};
use ianua_infra::http::{
    HttpAppSignInBroker, HttpApprovalBroker, HttpLogShipper, HttpPostureProvider,
    HttpPublishedKeys, NoApprovalBroker, NoPostureProvider,
};
use ianua_infra::inbox::InboxEventDispatcher;
use ianua_infra::postgres::authentication::PgDeviceStandings;
use ianua_infra::proofs::KeyKeeping;
use ianua_infra::runtime::LocalTimeZones;

use crate::boot::foundation::Foundation;
use crate::boot::stores::Stores;
use crate::config::Config;
use crate::config::app_sign_in::ApiChannel;
use crate::config::credentials::PostureService;
use crate::error::PlatformError;

/// How many consumers' issuers' key sets are kept at once.
const MOST_KEY_SOURCES: usize = 256;

/// The longest one batch of request records may take to reach a tenant's
/// log store.
const SHIP_TIMEOUT: Duration = Duration::from_secs(10);

/// Every use case the gateway runs.
pub(crate) struct UseCases {
    /// Who the caller is, from the one credential a request presents.
    pub authenticate: Arc<AuthenticateUseCase>,
    /// Whether the caller's device is healthy, as the device service says.
    pub posture: Arc<CheckDevicePostureUseCase>,
    /// Mints the narrowed token a route's `TokenExchange` stage forwards.
    pub exchange: Arc<ExchangeTokenUseCase>,
    /// What the route and the tenant's policy allow.
    pub decide_access: Arc<DecideAccessUseCase>,
    /// Whether an agent's action may go ahead.
    pub admit_action: Arc<AdmitActionUseCase>,
    /// Whether an agent's authority still holds while its tunnel is open.
    pub agent_authority: Arc<CheckAgentAuthorityUseCase>,
    /// Whether a person may still hold their tunnel open.
    pub recheck_connection: Arc<RecheckConnectionUseCase>,
    /// Records an agent's key-bound token presented without its key's
    /// proof.
    pub stolen_tokens: Arc<RecordStolenBindingUseCase>,
    /// Holds each session's uses against where it was last used.
    pub watch_session: Arc<WatchUseUseCase>,
    /// Whether a stream connection may open.
    pub admit_stream: Arc<AdmitStreamConnectionUseCase>,
    /// Who a stream connection's credential names.
    pub identify_stream: Arc<IdentifyStreamCallerUseCase>,
    /// Signs the identity an upstream is handed.
    pub sign_assertion: Arc<SignUseCase>,
    /// The tenant's published assertion keys.
    pub published_keys: Arc<GetPublishedUseCase>,
    /// Ships request records to the tenants' log stores.
    pub shipping: Arc<ShipRequestRecordsUseCase>,
    /// Relays app sign-in to the API, when its address is set.
    pub sign_in: Option<Arc<dyn AppSignInBroker>>,
    /// The gateway's inbox, the only place its events go.
    pub inbox: Arc<dyn EventDispatcher>,
    /// Reads the run passes the workflow listener takes, to find the
    /// tenant and route each names.
    pub passes: Arc<dyn PresentedTokens>,
    /// The issuer each tenant's tokens name, for the follower's snapshots.
    pub issuers: TenantIssuers,
}

/// Shared operations built before assembling the remaining use cases.
struct SharedOperations {
    issuers: TenantIssuers,
    authenticate: Arc<AuthenticateUseCase>,
    gate: Arc<GateActionUseCase>,
}

impl UseCases {
    /// Every use case, over `stores` and `foundation`, as `config` says.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] when an outbound client cannot be built.
    pub(crate) fn new(
        foundation: &Foundation,
        stores: &Stores,
        config: &Config,
    ) -> Result<Self, PlatformError> {
        let issuers = issuers(stores, config);
        let authenticate = Arc::new(authenticate(foundation, stores, config, issuers.clone())?);
        let gate = Arc::new(GateActionUseCase::new(GateActionPorts {
            broker: approvals(config.app_sign_in.api.as_ref(), foundation)?,
        }));
        Self::assemble(
            foundation,
            stores,
            config,
            SharedOperations {
                issuers,
                authenticate,
                gate,
            },
        )
    }

    /// Wires each operation to its gateway stores and the shared authentication operations.
    // The complete use-case inventory is flat dependency wiring after shared operations are built.
    #[allow(clippy::too_many_lines)]
    fn assemble(
        foundation: &Foundation,
        stores: &Stores,
        config: &Config,
        shared: SharedOperations,
    ) -> Result<Self, PlatformError> {
        let SharedOperations {
            issuers,
            authenticate,
            gate,
        } = shared;
        let decide_access = Arc::new(DecideAccessUseCase::new(DecideAccessPorts {
            route_store: Arc::clone(&stores.routes),
            policy_decisions: Arc::clone(&stores.policy_decisions),
            access_records: Arc::clone(&stores.access_records),
            member_standings: Arc::clone(&stores.member_standings),
            policy_store: Arc::clone(&stores.policies),
            time_zones: Arc::new(LocalTimeZones),
        }));
        Ok(Self {
            posture: Arc::new(CheckDevicePostureUseCase::new(CheckDevicePosturePorts {
                posture_provider: posture(config.credentials.posture.as_ref())?,
                device_standings: Arc::new(PgDeviceStandings::new(Arc::clone(
                    &foundation.databases,
                ))),
            })),
            exchange: Arc::new(ExchangeTokenUseCase::new(ExchangeTokenPorts {
                keys: Arc::clone(&stores.assertion_signing_keys),
                signer: Arc::new(Pkcs8AssertionSigner),
            })),
            recheck_connection: Arc::new(RecheckConnectionUseCase::new(RecheckConnectionChecks {
                credentials: Arc::clone(&authenticate),
                access: Arc::clone(&decide_access),
            })),
            decide_access,
            admit_action: Arc::new(AdmitActionUseCase::new(
                AdmitActionPorts {
                    exposure: Arc::clone(&stores.agent_exposure),
                },
                gate,
            )),
            agent_authority: Arc::new(CheckAgentAuthorityUseCase::new(AgentAuthorityPorts {
                standings: Arc::clone(&stores.agent_standings),
                revocations: Arc::clone(&stores.delegation_revocations),
            })),
            stolen_tokens: Arc::new(RecordStolenBindingUseCase::new(RecordStolenBindingPorts {
                agents: Arc::clone(&stores.agents),
                attacks: Arc::new(CacheAlertThrottle::new(Arc::clone(
                    &foundation.shared_state,
                ))),
            })),
            watch_session: Arc::new(WatchUseUseCase::new(WatchUsePorts {
                session_store: Arc::clone(&stores.sessions),
                geolocator: Arc::clone(&stores.geolocator),
                factors: Arc::clone(&stores.factor_standing),
                users: Arc::clone(&stores.users),
            })),
            admit_stream: Arc::new(AdmitStreamConnectionUseCase::new(
                AdmitStreamConnectionPorts {
                    stream_route_store: Arc::clone(&stores.stream_routes),
                    policy_decisions: Arc::clone(&stores.policy_decisions),
                },
            )),
            identify_stream: Arc::new(IdentifyStreamCallerUseCase::new(
                IdentifyStreamCallerPorts {
                    stream_route_store: Arc::clone(&stores.stream_routes),
                    consumer_store: Arc::clone(&stores.consumers),
                    issuers: issuers.clone(),
                    credentials: Arc::clone(&authenticate),
                },
            )),
            sign_assertion: Arc::new(SignUseCase::new(SignPorts {
                keys: Arc::clone(&stores.assertion_signing_keys),
                signer: Arc::new(Pkcs8AssertionSigner),
            })),
            published_keys: Arc::new(GetPublishedUseCase::new(
                GetPublishedPorts {
                    keys: Arc::clone(&stores.assertion_keys),
                    decoder: Arc::new(Pkcs8PublicKeyDecoder),
                },
                KeyRotationSchedule::FOR_ASSERTION_KEYS.overlap(),
            )),
            shipping: Arc::new(shipping(foundation, stores, config)?),
            sign_in: sign_in(config.app_sign_in.api.as_ref(), foundation)?,
            inbox: Arc::new(CacheEventDispatcher::new(
                Arc::new(InboxEventDispatcher::new(
                    Arc::clone(&foundation.databases),
                    foundation.keys.data_plane_seal.clone(),
                )),
                Arc::clone(&foundation.store_caches),
            )),
            passes: Arc::new(Pkcs8PresentedTokens::new(
                Arc::clone(&stores.verifying_keys),
                config.credentials.key_grace,
            )),
            authenticate,
            issuers,
        })
    }
}

/// The issuer each tenant's tokens name.
fn issuers(stores: &Stores, config: &Config) -> TenantIssuers {
    TenantIssuers::new(
        Arc::clone(&stores.tenants),
        Arc::clone(&stores.organizations),
        config.deployment.app_base_url.clone(),
    )
}

/// The proof of the caller from the one credential a request presents:
/// a person's token or app session, an agent's task token, a consumer's
/// key, token or certificate.
fn authenticate(
    foundation: &Foundation,
    stores: &Stores,
    config: &Config,
    issuers: TenantIssuers,
) -> Result<AuthenticateUseCase, PlatformError> {
    let grants = access_grants(foundation, stores, config);
    Ok(AuthenticateUseCase::new(AuthenticatePorts {
        tokens: Arc::new(Pkcs8PresentedTokens::new(
            Arc::clone(&stores.verifying_keys),
            config.credentials.key_grace,
        )),
        access_records: Arc::clone(&stores.access_records),
        people: PersonPorts {
            user_store: Arc::clone(&stores.users),
            app_sessions: Arc::clone(&stores.app_sessions),
            grants: Arc::new(grants),
        },
        agents: AgentPorts {
            standings: Arc::clone(&stores.agent_standings),
            revocations: Arc::clone(&stores.delegation_revocations),
            sender: sender(foundation),
        },
        consumers: consumers(foundation, stores, config, issuers)?,
    }))
}

/// OAuth access tokens share the gateway's token stores and sender-proof checks.
fn access_grants(
    foundation: &Foundation,
    stores: &Stores,
    config: &Config,
) -> ResolveAccessTokenUseCase {
    ResolveAccessTokenUseCase::new(ResolveAccessTokenPorts {
        presented: PresentedTokenPorts {
            access_token_store: Arc::clone(&stores.access_tokens),
            code_hasher: Arc::new(HmacCodeHasher::new(&foundation.keys.shared_root)),
            key_store: Arc::clone(&stores.verifying_keys),
            jwt_verifier: Arc::new(Pkcs8AccessTokenJwtVerifier::new(
                config.credentials.key_grace,
            )),
        },
        client_store: Arc::clone(&stores.oauth_clients),
        user_store: Arc::clone(&stores.users),
        sender: sender(foundation),
    })
}

/// DPoP verification uses the fleet's shared replay guard.
fn sender(foundation: &Foundation) -> SenderProofPorts {
    SenderProofPorts {
        dpop_verifier: Arc::new(JwkDpopProofVerifier),
        dpop_replays: Arc::new(CacheDpopReplayGuard::new(Arc::clone(
            &foundation.shared_state,
        ))),
    }
}

/// Consumers present keys or issuer tokens and use the same holdings and quota stores.
fn consumers(
    foundation: &Foundation,
    stores: &Stores,
    config: &Config,
    issuers: TenantIssuers,
) -> Result<ConsumerPorts, PlatformError> {
    Ok(ConsumerPorts {
        keys: Arc::new(HmacConsumerKeyDigests::new(&foundation.keys.shared_root)),
        verifier: Arc::new(JwkConsumerTokenVerifier::new(Arc::new(
            consumer_issuer_keys(config)?,
        ))),
        consumer_store: Arc::clone(&stores.consumers),
        authorities: Arc::new(ConsumerActing::new(ConsumerActingPorts {
            consumer_store: Arc::clone(&stores.consumers),
            access_records: Arc::clone(&stores.access_records),
            issuers,
            quota_counter: Arc::new(CacheConsumerQuotaCounter::new(Arc::clone(
                &foundation.shared_state,
            ))),
        })),
    })
}

/// The key sets consumers' own token issuers publish, fetched only from
/// the networks upstreams may reach.
fn consumer_issuer_keys(config: &Config) -> Result<HttpPublishedKeys, PlatformError> {
    let keys = config.credentials.consumer_issuer_keys;
    HttpPublishedKeys::new(
        keys.timeout,
        config.forward.upstream_networks.clone(),
        KeyKeeping {
            keep_for: keys.keep_for,
            renew_after: keys.renew_after,
        },
        MOST_KEY_SOURCES,
    )
    .map_err(PlatformError::of("the consumers' issuers' published keys"))
}

/// Where a device's posture is asked: the device service the settings
/// name, or none, which answers every question with an error.
fn posture(service: Option<&PostureService>) -> Result<Arc<dyn PostureProvider>, PlatformError> {
    let Some(service) = service else {
        return Ok(Arc::new(NoPostureProvider));
    };
    let provider = HttpPostureProvider::new(
        service.endpoint.clone(),
        service.token.clone(),
        service.timeout,
    )
    .map_err(PlatformError::of("the device service"))?;
    Ok(Arc::new(provider))
}

/// Where an agent's approvals are asked: the API over its sealed channel,
/// or nowhere, which refuses every action waiting for one.
fn approvals(
    api: Option<&ApiChannel>,
    foundation: &Foundation,
) -> Result<Arc<dyn ApprovalBroker>, PlatformError> {
    let Some(api) = api else {
        return Ok(Arc::new(NoApprovalBroker));
    };
    let broker = HttpApprovalBroker::new(
        &api.url,
        api.timeout,
        &foundation.keys.shared_root,
        &api.link,
    )
    .map_err(PlatformError::of("the approval broker"))?;
    Ok(Arc::new(broker))
}

/// Where app sign-in is relayed: the API over its sealed channel, when its
/// address is set.
fn sign_in(
    api: Option<&ApiChannel>,
    foundation: &Foundation,
) -> Result<Option<Arc<dyn AppSignInBroker>>, PlatformError> {
    let Some(api) = api else {
        return Ok(None);
    };
    let broker = HttpAppSignInBroker::new(
        &api.url,
        api.timeout,
        &foundation.keys.shared_root,
        &api.link,
    )
    .map_err(PlatformError::of("the app sign-in broker"))?;
    Ok(Some(Arc::new(broker)))
}

/// Ships request records to the log stores tenants set up, only to the
/// networks upstreams may reach.
fn shipping(
    foundation: &Foundation,
    stores: &Stores,
    config: &Config,
) -> Result<ShipRequestRecordsUseCase, PlatformError> {
    let shipper = HttpLogShipper::new(config.forward.upstream_networks.clone(), SHIP_TIMEOUT)
        .map_err(PlatformError::of("the log shipper"))?;
    Ok(ShipRequestRecordsUseCase::new(ShipRequestRecordsPorts {
        log_shipping_store: Arc::clone(&stores.log_shipping),
        shipper: Arc::new(shipper),
        encryptor: Arc::clone(&foundation.encryptor),
    }))
}
