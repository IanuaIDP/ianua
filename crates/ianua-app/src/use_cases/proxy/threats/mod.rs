//! Threats the gateway sees in traffic, recorded for the tenant's threat
//! dashboard.
//!
//! These run in the gateway, and what they record goes through its inbox,
//! which takes only the events the data plane raises: of the proxy's
//! threat events, a honeypot hit, automation caught, and a canary token
//! presented or leaking.

pub(crate) mod record_canary_leak;
pub(crate) mod record_canary_triggered;
pub(crate) mod record_honeypot_hit;

pub use record_canary_leak::{RecordCanaryLeakRequest, RecordCanaryLeakUseCase};
pub use record_canary_triggered::{RecordCanaryTriggeredRequest, RecordCanaryTriggeredUseCase};
pub use record_honeypot_hit::{RecordHoneypotHitRequest, RecordHoneypotHitUseCase};
