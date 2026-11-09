//! The company steps about the platform itself: an app's recent requests,
//! closing an app to workflows, attack mode, searching the audit trail,
//! making a sealed audit pack, classifying a field and hiding sensitive
//! fields.

use std::sync::Arc;

use ianua_domain::domains::audit::export::filter::{
    AuditExportFilter, AuditExportFilterParts, AuditExportFormat, EventTypePrefix,
};
use ianua_domain::domains::data_classification::classification::RedactionStrategy;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::metrics::window::MetricsWindow;
use ianua_domain::domains::routing::route::{
    AttackLength, AttackMode, LONGEST_ATTACK_MINUTES, SHORTEST_ATTACK_MINUTES, WorkflowUse,
};
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::{
    APP_INPUT, DATA_INPUT, FIELD_INPUT, FORMAT_INPUT, LEVEL_INPUT, MINUTES_INPUT, SINCE_INPUT,
    WHAT_INPUT,
};
use ianua_domain::domains::workflows::redaction::{FieldDigest, Hiding, hidden};
use ianua_domain::shared::clock;
use ianua_domain::types::{FieldPath, RouteId, TenantId};

use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::audit::{AuditLogEntry, AuditLogFilter};
use crate::ports::data_classification::RedactionDigest;
use crate::ports::workflows::CompanyCall;
use crate::use_case::{Command as _, Query as _};
use crate::use_cases::audit::exports::{RequestForTenantUseCase, Selection};
use crate::use_cases::audit::{ListForOrgRequest, ListForTenantUseCase};
use crate::use_cases::data_classification::{
    AddClassificationRuleRequest, AddClassificationRuleUseCase, GetClassificationUseCase,
};
use crate::use_cases::routing::routes::{
    AttackChange, GetTrafficRequest, GetTrafficUseCase, SetAttackModeRequest, SetAttackModeUseCase,
    SetWorkflowUseRequest, SetWorkflowUseUseCase,
};
use crate::use_cases::workflows::executions::answers::{data, failed, moment_text};
use crate::use_cases::workflows::executions::company::inputs::{
    id, optional_text, since, text, value, whole_number,
};
use crate::use_cases::workflows::executions::company::people::count;
use crate::use_cases::workflows::executions::company::{succeeded, unmade};

/// The most apps traffic is read for, busiest first.
const APPS_READ: u32 = 100;

/// The most audit records one search returns, newest first.
const RECORDS_READ: u32 = 50;

/// The dashboard's actions on apps, the audit trail and classification.
pub struct PlatformActions {
    /// Reads the tenant's traffic, app by app.
    pub traffic: Arc<GetTrafficUseCase>,
    /// Opens or closes an app to workflows.
    pub workflow_use: Arc<SetWorkflowUseUseCase>,
    /// Starts or ends an app's attack mode.
    pub attack_mode: Arc<SetAttackModeUseCase>,
    /// Searches the tenant's audit trail.
    pub audit: Arc<ListForTenantUseCase>,
    /// Asks for a sealed export of the tenant's audit trail.
    pub pack: Arc<RequestForTenantUseCase>,
    /// Adds a classification rule.
    pub classify: Arc<AddClassificationRuleUseCase>,
    /// Reads the tenant's classification rules.
    pub classification: Arc<GetClassificationUseCase>,
    /// The keyed digest a hashed field is replaced with, the gateway's own.
    pub digest: Arc<dyn RedactionDigest>,
}

impl PlatformActions {
    /// Reads how many requests reached the app the step names since when it
    /// says, and how many were refused.
    pub(super) async fn requests(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let route_id = id(step.call, APP_INPUT, RouteId::from_uuid)?;
        let now = clock::now();
        let window = MetricsWindow::new(now - since(step.call, SINCE_INPUT)?.span(), now)
            .map_err(|_| failed("the step's time window does not read"))?;
        let request = GetTrafficRequest {
            window,
            limit: APPS_READ,
        };
        let apps = self
            .traffic
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        let read_all = apps.len() < APPS_READ as usize;
        let seen = apps.iter().find(|app| app.route_id == route_id);
        let (requests, denied, errors) = match (seen, read_all) {
            (Some(app), _) => (app.request_count, app.denied_count, app.server_error_count),
            (None, true) => (0, 0, 0),
            (None, false) => return Err(failed("the app is not among the busiest hundred")),
        };
        let output = data(vec![
            ("requests", big_count(requests)),
            ("denied", big_count(denied)),
            ("server_errors", big_count(errors)),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Closes the app the step names to workflows.
    pub(super) async fn close_app(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let route_id = id(step.call, APP_INPUT, RouteId::from_uuid)?;
        let request = SetWorkflowUseRequest {
            route_id,
            workflow_use: WorkflowUse::Closed,
        };
        self.workflow_use
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("app", FlowData::text(route_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Puts the app the step names in attack mode for the minutes it says,
    /// from 5 to 1440.
    pub(super) async fn attack_mode(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let route_id = id(step.call, APP_INPUT, RouteId::from_uuid)?;
        let minutes = whole_number(
            step.call,
            MINUTES_INPUT,
            SHORTEST_ATTACK_MINUTES,
            LONGEST_ATTACK_MINUTES,
        )?;
        let length =
            AttackLength::minutes(minutes).map_err(|_| failed("the step's minutes do not read"))?;
        let request = SetAttackModeRequest {
            route_id,
            change: AttackChange::Start(length),
        };
        let mode = self
            .attack_mode
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let AttackMode::Until(until) = mode else {
            return Err(failed("attack mode did not start"));
        };
        let output = data(vec![("until", moment_text(until))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Reads the newest audit records of the kind the step names, since
    /// when it says.
    pub(super) async fn search_audit(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request = ListForOrgRequest {
            filter: AuditLogFilter {
                event_type: optional_text(step.call, WHAT_INPUT)?.map(str::to_owned),
                after: Some(clock::now() - since(step.call, SINCE_INPUT)?.span()),
                ..AuditLogFilter::default()
            },
            sort: SortOrder::default(),
            page: PageRequest::first(Limit::internal(RECORDS_READ)),
        };
        let page = self
            .audit
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        let records = page
            .items
            .iter()
            .map(record_data)
            .collect::<Result<Vec<_>, _>>()?;
        let total = records.len();
        let list =
            FlowData::list(records).map_err(|_| failed("the records do not fit workflow data"))?;
        let output = data(vec![("records", Ok(list)), ("count", count(total))])?;
        Ok(succeeded(step, output, DataClassLevel::Confidential))
    }

    /// Asks for an export of the tenant's audit trail, as the dashboard's
    /// export does: the records of the event type the step names, since
    /// when it says, in its format. The worker writes and seals the file;
    /// the step hands on the export's id to fetch it by once ready.
    pub(super) async fn make_audit_pack(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let event_type = optional_text(step.call, WHAT_INPUT)?
            .map(EventTypePrefix::new)
            .transpose()
            .map_err(|_| failed("the step's event type is not one an export can name"))?;
        let parts = AuditExportFilterParts {
            event_type,
            after: Some(clock::now() - since(step.call, SINCE_INPUT)?.span()),
            ..AuditExportFilterParts::default()
        };
        let selection = Selection {
            filter: AuditExportFilter::new(parts)
                .map_err(|_| failed("the step names no records an export can hold"))?,
            format: pack_format(optional_text(step.call, FORMAT_INPUT)?)?,
        };
        let export = self
            .pack
            .execute(step.caller, step.auditor, selection)
            .await
            .map_err(unmade)?;
        let output = data(vec![
            ("export_id", FlowData::text(export.to_string())),
            ("status", FlowData::text("pending")),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Classifies the field the step names at its level; the gateway masks
    /// it from then on.
    pub(super) async fn classify(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request = AddClassificationRuleRequest {
            field_path: FieldPath::new(text(step.call, FIELD_INPUT)?)
                .map_err(|_| failed("the step's field is not a field path"))?,
            level: DataClassLevel::parse(text(step.call, LEVEL_INPUT)?)
                .map_err(|_| failed("the step's level is not a classification level"))?,
            redaction: RedactionStrategy::Mask,
        };
        let rule = self
            .classify
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("rule_id", FlowData::text(rule.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// The data the step is given, with every field the tenant classifies
    /// at the level it names or above hidden as its rule says; confidential
    /// and above when it names none. Field paths are read from the data's
    /// own root, as from an app's answer. The data counts as sensitive as
    /// it came: what is left may hold what no rule names.
    pub(super) async fn hide_fields(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let given = value(step.call, DATA_INPUT)?;
        let min = match optional_text(step.call, LEVEL_INPUT)? {
            None => DataClassLevel::Confidential,
            Some(level) => DataClassLevel::parse(level)
                .map_err(|_| failed("the step's level is not a classification level"))?,
        };
        let rules = self
            .classification
            .execute(step.caller, ())
            .await
            .map_err(unmade)?;
        let Some(rules) = rules else {
            return answer(step, given.clone(), 0);
        };
        let digest = TenantDigest {
            digest: self.digest.as_ref(),
            tenant: step.caller.tenant_id(),
        };
        let hiding = Hiding {
            rules: &rules,
            min,
            digest: &digest,
        };
        let result =
            hidden(given, "", &hiding).map_err(|_| failed("the data could not be hidden"))?;
        answer(step, result.data, result.count)
    }
}

/// The gateway's keyed digest, for one tenant's fields.
struct TenantDigest<'a> {
    digest: &'a dyn RedactionDigest,
    tenant: TenantId,
}

impl FieldDigest for TenantDigest<'_> {
    fn digest(&self, value: &str) -> String {
        self.digest.digest(&self.tenant, value.as_bytes())
    }
}

/// The step's answer: the data with its fields hidden, and how many were,
/// as sensitive as the data it was given.
fn answer(
    step: &CompanyCall<'_>,
    hidden_data: FlowData,
    hidden_count: usize,
) -> Result<ActionOutcome, ActionOutcome> {
    let output = data(vec![
        ("data", Ok(hidden_data)),
        ("hidden", count(hidden_count)),
    ])?;
    Ok(succeeded(step, output, DataClassLevel::Public))
}

/// One audit record as workflow data: its id, kind, actor and moment.
fn record_data(record: &AuditLogEntry) -> Result<FlowData, ActionOutcome> {
    data(vec![
        ("record_id", FlowData::text(record.id.to_string())),
        ("event_type", FlowData::text(record.event_type.as_str())),
        ("actor", FlowData::text(record.actor_display.as_str())),
        ("occurred_at", moment_text(record.occurred_at)),
    ])
}

/// The format an audit pack is written in: CSV when the step names none.
fn pack_format(named: Option<&str>) -> Result<AuditExportFormat, ActionOutcome> {
    match named {
        None | Some("csv") => Ok(AuditExportFormat::Csv),
        Some("json") => Ok(AuditExportFormat::Json),
        Some(_) => Err(failed("the step's format is neither csv nor json")),
    }
}

/// A count that may pass what a whole number in workflow data holds
/// exactly, as text when it does.
fn big_count(how_many: u64) -> Result<FlowData, ianua_domain::shared::errors::DomainError> {
    match u32::try_from(how_many) {
        Ok(fits) => FlowData::number(f64::from(fits)),
        Err(_) => FlowData::text(how_many.to_string()),
    }
}
