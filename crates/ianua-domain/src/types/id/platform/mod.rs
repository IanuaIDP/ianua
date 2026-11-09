//! Ids of the platform itself: operators, processes, jobs, the audit trail and data classification.

/// Id of an export of the audit log.
pub(crate) mod audit_export;
/// Id of an audit record.
pub(crate) mod audit_record;
/// Id of a tenant's stream of audit records to a SIEM.
pub(crate) mod audit_stream;
/// Id of one data-classification rule.
pub(crate) mod classification_rule;
/// Id of a tenant's set of data-classification rules.
pub(crate) mod classification_rule_set;
/// Id that ties together everything one request caused.
pub(crate) mod correlation;
/// Id of an audit evidence record.
pub(crate) mod evidence;
/// Id of an operator's grant to act as a tenant user.
pub(crate) mod impersonation_grant;
/// Id of a scheduled background job.
pub(crate) mod job;
/// Id of one running process in the deployment.
pub(crate) mod node;
/// Id of a platform operator.
pub(crate) mod operator;

pub use audit_export::AuditExportId;
pub use audit_record::AuditRecordId;
pub use audit_stream::AuditStreamId;
pub use classification_rule::ClassificationRuleId;
pub use classification_rule_set::ClassificationRuleSetId;
pub use correlation::CorrelationId;
pub use evidence::EvidenceId;
pub use impersonation_grant::ImpersonationGrantId;
pub use job::JobId;
pub use node::NodeId;
pub use operator::OperatorId;
