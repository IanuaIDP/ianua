//! Records sent to a tenant's own tools: its gateway's request records to
//! a log destination, and its audit records to a security team's stream.

mod shipping;
mod streams;

pub use shipping::HttpLogShipper;
pub use streams::HttpAuditStreamSender;
