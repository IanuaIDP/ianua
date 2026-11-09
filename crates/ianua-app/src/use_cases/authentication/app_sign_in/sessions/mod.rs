//! The session the app's domain holds: handed over, carried across hosts, ended.

pub(super) mod across;
pub(super) mod across_tokens;
pub(super) mod hand_over;
pub(super) mod issue_hop;
pub(super) mod issue_token;
pub(super) mod log_out;

pub use across::{AcrossHosts, AcrossHostsPorts};
pub use hand_over::{AppHandOverRequest, HandOverAppSessionUseCase};
pub use issue_hop::{AppIssueHopRequest, AppIssueHopUseCase};
pub use issue_token::{AppIssueTokenRequest, AppIssueTokenUseCase};
pub use log_out::AppLogOutUseCase;
