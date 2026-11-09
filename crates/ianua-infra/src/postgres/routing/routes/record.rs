//! A route as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::route::{AttackMode, Route, RouteRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ActionClass, DeclaredAction, HttpMethod, Label, PipelineId, RouteId, ServiceId, UrlPath,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::routing::hosts::{hosts_column, hosts_from};

const ROUTE: Stored = Stored("route");

const POLICY: Kept = Kept {
    entity: ROUTE.0,
    column: "policy",
    shape: 1,
};

const CONDITIONS: Kept = Kept {
    entity: ROUTE.0,
    column: "conditions",
    shape: 1,
};

const PATH_REWRITE: Kept = Kept {
    entity: ROUTE.0,
    column: "path_rewrite",
    shape: 1,
};

const PARAMETER_RULES: Kept = Kept {
    entity: ROUTE.0,
    column: "parameter_rules",
    shape: 1,
};

/// A route as it is read. The store's checked queries fill it.
pub(super) struct RouteRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) path_pattern: String,
    pub(super) methods: Vec<String>,
    pub(super) service_id: Uuid,
    pub(super) policy: Value,
    pub(super) hosts: Option<Vec<String>>,
    pub(super) conditions: Value,
    pub(super) pipeline_id: Uuid,
    pub(super) path_rewrite: Value,
    pub(super) status: String,
    pub(super) priority: i32,
    pub(super) data_class: String,
    pub(super) action_class: Option<String>,
    pub(super) reach: String,
    pub(super) parameter_rules: Value,
    pub(super) workflow_use: String,
    pub(super) attack_mode_until: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl RouteRecord {
    /// The route the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the route
    /// keeps.
    pub(super) fn into_route(self) -> Result<Route<ResolvedTenant>, DomainError> {
        Route::reconstitute(RouteRow {
            id: RouteId::from_uuid(self.id),
            name: ROUTE.value("name", Label::new("name", self.name))?,
            path_pattern: ROUTE.value("path pattern", UrlPath::new(self.path_pattern))?,
            methods: methods_from(&self.methods)?,
            service_id: ServiceId::from_uuid(self.service_id),
            policy: POLICY.open(self.policy)?,
            hosts: hosts_from(ROUTE, self.hosts)?,
            conditions: CONDITIONS.open(self.conditions)?,
            pipeline_id: PipelineId::from_uuid(self.pipeline_id),
            path_rewrite: PATH_REWRITE.open(self.path_rewrite)?,
            status: ROUTE.choice(&self.status)?,
            priority: u16::try_from(self.priority)
                .map_err(|_| DomainError::corrupt_row(ROUTE.0, "a priority out of range"))?,
            data_class: DataClassLevel::from_stored(&self.data_class)?,
            action_class: action_class_from(self.action_class.as_deref())?,
            reach: RouteReach::from_stored(&self.reach)?,
            parameter_rules: PARAMETER_RULES.open(self.parameter_rules)?,
            workflow_use: ROUTE.choice(&self.workflow_use)?,
            attack_mode: self
                .attack_mode_until
                .map_or(AttackMode::Off, AttackMode::Until),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A route's columns, as they are written.
pub(super) struct RouteColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) path_pattern: &'a str,
    pub(super) methods: Vec<String>,
    pub(super) service_id: &'a Uuid,
    pub(super) policy: Value,
    pub(super) hosts: Option<Vec<String>>,
    pub(super) conditions: Value,
    pub(super) pipeline_id: &'a Uuid,
    pub(super) path_rewrite: Value,
    pub(super) status: &'static str,
    pub(super) priority: i32,
    pub(super) data_class: &'static str,
    pub(super) action_class: Option<&'static str>,
    pub(super) reach: &'static str,
    pub(super) parameter_rules: Value,
    pub(super) workflow_use: &'static str,
    pub(super) attack_mode_until: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> RouteColumns<'a> {
    /// The columns `route` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value cannot be written
    /// out as JSON.
    pub(super) fn of(route: &'a Route<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: route.id().as_uuid(),
            name: route.name().as_str(),
            path_pattern: route.path_pattern().as_str(),
            methods: methods_column(route.methods()),
            service_id: route.service_id().as_uuid(),
            policy: POLICY.seal(route.policy())?,
            hosts: hosts_column(route.hosts()),
            conditions: CONDITIONS.seal(route.conditions())?,
            pipeline_id: route.pipeline_id().as_uuid(),
            path_rewrite: PATH_REWRITE.seal(route.path_rewrite())?,
            status: route.status().word(),
            priority: i32::from(route.priority()),
            data_class: route.data_class().as_str(),
            action_class: route
                .declared_action_class()
                .stored()
                .map(ActionClass::as_str),
            reach: route.reach().as_str(),
            parameter_rules: PARAMETER_RULES.seal(route.parameter_rules())?,
            workflow_use: route.workflow_use().word(),
            attack_mode_until: match route.attack_mode() {
                AttackMode::Off => None,
                AttackMode::Until(until) => Some(until),
            },
            created_at: route.created_at(),
            updated_at: route.updated_at(),
        })
    }
}

/// Writes the route's validated method names in the order supplied by the domain.
fn methods_column(methods: &[HttpMethod]) -> Vec<String> {
    methods
        .iter()
        .map(|method| method.as_str().to_owned())
        .collect()
}

/// The methods a stored route matches, each as sent on the wire.
fn methods_from(stored: &[String]) -> Result<Vec<HttpMethod>, DomainError> {
    stored
        .iter()
        .map(|method| {
            HttpMethod::parse(method)
                .ok_or_else(|| DomainError::corrupt_row(ROUTE.0, "an unknown method"))
        })
        .collect()
}

/// The action class a stored route declares, or none.
fn action_class_from(stored: Option<&str>) -> Result<DeclaredAction, DomainError> {
    let class = stored.map(ActionClass::from_stored).transpose()?;
    Ok(DeclaredAction::from_stored(class))
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::routing::matching::parameter::{ParameterLocation, ParameterRule};
    use ianua_domain::domains::routing::matching::path_rewrite::{PathRewrite, PathTemplate};
    use ianua_domain::domains::routing::matching::request_match::{
        MatchSubject, RequestCondition, RouteConditions, ValueMatch,
    };
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::types::{DomainName, HeaderName};
    use serde_json::json;

    use super::*;

    /// The policy is written in the shape pinned here, and a row in that
    /// shape reads back.
    #[test]
    fn the_policy_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": "Authenticated"});

        assert_eq!(POLICY.seal(&RoutePolicy::Authenticated).unwrap(), stored);
        assert_eq!(
            POLICY.open::<RoutePolicy>(stored).unwrap(),
            RoutePolicy::Authenticated
        );
    }

    /// The header and cookie conditions are written in the shape pinned
    /// here, and a row in that shape reads back.
    #[test]
    fn the_conditions_are_stored_in_their_pinned_shape() {
        let conditions = RouteConditions::new(vec![RequestCondition::new(
            MatchSubject::Header(HeaderName::new("x-env").unwrap()),
            ValueMatch::Present,
        )])
        .unwrap();
        let stored = json!({"v": 1, "value": [
            {"subject": {"header": "x-env"}, "value": "present"}
        ]});

        assert_eq!(CONDITIONS.seal(&conditions).unwrap(), stored);
        assert_eq!(
            CONDITIONS.open::<RouteConditions>(stored).unwrap(),
            conditions
        );
    }

    /// The path rewrite is written in the shape pinned here, and a row in
    /// that shape reads back.
    #[test]
    fn the_path_rewrite_is_stored_in_its_pinned_shape() {
        let rewrite = PathRewrite::Template(PathTemplate::new("/internal/{id}").unwrap());
        let stored = json!({"v": 1, "value": {"Template": "/internal/{id}"}});

        assert_eq!(PATH_REWRITE.seal(&rewrite).unwrap(), stored);
        assert_eq!(PATH_REWRITE.open::<PathRewrite>(stored).unwrap(), rewrite);
    }

    /// The parameter rules are written in the shape pinned here, and a row
    /// in that shape reads back.
    #[test]
    fn the_parameter_rules_are_stored_in_their_pinned_shape() {
        let rules = vec![
            ParameterRule::new(
                "url",
                ParameterLocation::Query,
                vec![DomainName::new("api.example.com").unwrap()],
            )
            .unwrap(),
        ];
        let stored = json!({"v": 1, "value": [
            {"name": "url", "location": "query", "allowed_hosts": ["api.example.com"]}
        ]});

        assert_eq!(PARAMETER_RULES.seal(&rules).unwrap(), stored);
        assert_eq!(
            PARAMETER_RULES.open::<Vec<ParameterRule>>(stored).unwrap(),
            rules
        );
    }
}
