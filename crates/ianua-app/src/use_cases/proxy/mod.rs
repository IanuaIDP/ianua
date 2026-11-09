//! Proxy use cases: pipeline configuration and evaluation, device posture,
//! the credentials a request presents, the access decision on each request,
//! the narrowed token exchanged for an upstream, the request log, its
//! retention and log shipping, and the threats the gateway sees in
//! traffic.

pub(crate) mod check_device_posture;
pub mod credentials;
pub(crate) mod decide_access;
pub(crate) mod evaluate_pipeline;
pub(crate) mod exchange_token;
pub(crate) mod forget_old_records;
pub mod log_shipping;
mod lookup;
mod pipeline_changes;
pub mod pipelines;
pub(crate) mod recheck_connection;
pub(crate) mod record_turned_away;
pub(crate) mod search_request_records;
pub mod stages;
pub mod threats;

pub use check_device_posture::{CheckDevicePosturePorts, CheckDevicePostureUseCase, PostureCheck};
pub use decide_access::{DecideAccessPorts, DecideAccessRequest, DecideAccessUseCase};
pub use evaluate_pipeline::{
    EvaluatePipelinePorts, EvaluatePipelineUseCase, PipelineResult, PipelineVerdict,
};
pub use exchange_token::{
    ExchangeTokenPorts, ExchangeTokenUseCase, ExchangedForUpstream, TokenExchangeRequest,
};
pub use forget_old_records::{ForgetOldRecordsPorts, ForgetOldRecordsUseCase, ForgetReport};
pub use recheck_connection::{
    ConnectionHolder, ConnectionStanding, RecheckConnectionChecks, RecheckConnectionRequest,
    RecheckConnectionUseCase,
};
pub use record_turned_away::RecordTurnedAwayUseCase;
pub use search_request_records::{
    SearchRequestRecordsPorts, SearchRequestRecordsRequest, SearchRequestRecordsUseCase,
};
