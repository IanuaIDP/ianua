//! The five stage groups, built once over the use cases and adapters they
//! call, handed to the dispatcher that runs a pipeline's stages.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::runtime::FleetCounters;
use ianua_infra::cache::{
    CacheBudgetCounter, CacheFleetCounters, CacheResponseCache, ResponseRoom, SharedState,
};
use ianua_infra::crypto::{AssertionKeyMessageSigner, HmacRedactionDigest, RootSecret};
use ianua_infra::reading::DocumentGraphQlAnalyzer;

use crate::boot::stage_ports::{FleetTokenLedger, InboxCanaryAlarm};
use crate::boot::stores::Stores;
use crate::boot::use_cases::UseCases;
use crate::config::Config;
use crate::config::listen::MainTransport;
use crate::fleet::FleetPublisher;
use crate::pipeline::executor::{StageDispatch, StageGroups};
use crate::pipeline::stages::checks::{CheckStages, CheckStagesParts};
use crate::pipeline::stages::counters::{CounterLimits, CounterPorts, CounterStages, HeldVerdicts};
use crate::pipeline::stages::identity::{IdentityStages, IdentityStagesParts};
use crate::pipeline::stages::policy::{PolicyStages, PolicyStagesParts};
use crate::pipeline::stages::response::{ResponseLimits, ResponseStages, ResponseStagesParts};
use crate::request::Scheme;
use crate::wasm::WasmRuntime;

/// The longest a decoy hit's record may take to reach the inbox.
const RECORD_TIMEOUT: Duration = Duration::from_secs(2);

/// How many requests the recon stage may slow down at once.
const TARPITS: usize = 256;

/// The longest a country lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(200);

/// What the stage groups are built from beyond the stores and use cases.
pub(crate) struct StageInputs<'a> {
    /// The state every gateway shares, the counters live in.
    pub shared_state: Arc<dyn SharedState>,
    /// The shared root, which redacted values' digests are keyed from, so
    /// every gateway digests a value alike.
    pub shared_root: &'a RootSecret,
    /// The persistence ports supplying current tenant policy and security records.
    pub stores: &'a Stores,
    /// The application operations invoked when stages need governed domain decisions.
    pub use_cases: &'a UseCases,
    /// The sandbox `Custom` stages run modules in.
    pub wasm: Arc<WasmRuntime>,
    /// This instance's copy of the fleet's blocks and flags.
    pub held: Arc<HeldVerdicts>,
    /// Where blocks and flags raised here go to the other instances.
    pub publisher: FleetPublisher,
}

/// The dispatcher over every stage group, as `config` bounds them.
pub(crate) fn dispatch(inputs: StageInputs<'_>, config: &Config) -> StageDispatch {
    let fleet: Arc<dyn FleetCounters> =
        Arc::new(CacheFleetCounters::new(Arc::clone(&inputs.shared_state)));
    StageDispatch::new(groups(inputs, config, fleet))
}

/// Wires each stage group to its use cases, shared adapters and configured limits.
// The complete StageGroups literal is one wiring operation and keeps every pipeline group visible.
#[allow(clippy::too_many_lines)]
fn groups(inputs: StageInputs<'_>, config: &Config, fleet: Arc<dyn FleetCounters>) -> StageGroups {
    let StageInputs {
        shared_state,
        shared_root: redaction_root,
        stores,
        use_cases,
        wasm,
        held,
        publisher,
    } = inputs;
    let call_timeout = config.limits.pipeline_timeout;
    StageGroups {
        identity: IdentityStages::new(IdentityStagesParts {
            authenticate: Arc::clone(&use_cases.authenticate),
            posture: Arc::clone(&use_cases.posture),
            exchange: Arc::clone(&use_cases.exchange),
            stolen_tokens: Arc::clone(&use_cases.stolen_tokens),
            watch_session: Arc::clone(&use_cases.watch_session),
            record_timeout: RECORD_TIMEOUT,
        }),
        policy: PolicyStages::new(PolicyStagesParts {
            decide_access: Arc::clone(&use_cases.decide_access),
            admit_action: Arc::clone(&use_cases.admit_action),
            classifications: Arc::clone(&stores.classifications),
            events: Arc::clone(&use_cases.inbox),
            call_timeout,
        }),
        counters: CounterStages::new(
            CounterPorts {
                fleet: Arc::clone(&fleet),
                budgets: Arc::new(CacheBudgetCounter::new(Arc::clone(&shared_state))),
                events: Arc::clone(&use_cases.inbox),
                held,
                publisher: Some(publisher),
            },
            CounterLimits {
                counter_timeout: config.limits.counter_timeout,
                record_timeout: RECORD_TIMEOUT,
                tarpits: TARPITS,
            },
        ),
        checks: CheckStages::new(CheckStagesParts {
            geolocator: Arc::clone(&stores.geolocator),
            graphql: Arc::new(DocumentGraphQlAnalyzer),
            wasm,
            lookup_timeout: LOOKUP_TIMEOUT,
        }),
        response: ResponseStages::new(ResponseStagesParts {
            signer: Arc::new(AssertionKeyMessageSigner::new(Arc::clone(
                &stores.assertion_signing_keys,
            ))),
            classifications: Arc::clone(&stores.classifications),
            redaction: Arc::new(HmacRedactionDigest::new(redaction_root)),
            cache: Arc::new(CacheResponseCache::new(
                Arc::clone(&shared_state),
                response_room(config),
            )),
            canary_alarm: Arc::new(InboxCanaryAlarm::new(Arc::clone(&use_cases.inbox))),
            tokens: Arc::new(FleetTokenLedger::new(fleet)),
            limits: ResponseLimits {
                call_timeout,
                cache_max_body: config.limits.response_cache.largest_body,
            },
        }),
    }
}

/// How much the response cache keeps, as the settings bound it.
fn response_room(config: &Config) -> ResponseRoom {
    let cache = &config.limits.response_cache;
    ResponseRoom {
        largest_entry: usize::try_from(cache.largest_body.get()).unwrap_or(usize::MAX),
        entries: u64::try_from(cache.entries).unwrap_or(u64::MAX),
    }
}

/// How clients reach the gateway, as a `DPoP` proof names it: https
/// wherever the main listener ends TLS, plain HTTP only where it serves
/// plain HTTP in development.
#[must_use]
pub(crate) fn scheme(config: &Config) -> Scheme {
    match config.listen.transport {
        MainTransport::Tls { .. } => Scheme::Https,
        MainTransport::PlainInDevelopment => Scheme::Http,
    }
}
