//! What a route declares about the data and actions behind it, which an
//! agent's checks are judged against.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use crate::domains::routing::route::Route;
use crate::domains::routing::route::rules::ensure_ruled_once;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::{ActionClass, DeclaredAction};

impl<T: TenantScope> Route<T> {
    /// The most sensitive data this route serves or accepts.
    ///
    /// It decides how data may flow between agents. An agent that has touched
    /// data of some class may reach only routes cleared at least that high.
    /// Touching this route raises the agent to this class.
    #[must_use]
    pub fn data_class(&self) -> DataClassLevel {
        self.data_class
    }

    /// Declares the most sensitive data this route serves or accepts.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn declare_data_class(
        &mut self,
        data_class: DataClassLevel,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.data_class = data_class;
        self.record_update();
        Ok(())
    }

    /// What kind of action this route takes.
    ///
    /// An agent's intent is checked against this instead of a guess from the
    /// path. `DeclaredAction::Undeclared` falls back to the guess. An
    /// open-ended route counts as communicating, unless what was declared is
    /// riskier still.
    #[must_use]
    pub fn action_class(&self) -> DeclaredAction {
        match (self.reach, self.action_class) {
            (RouteReach::OpenEnded, DeclaredAction::Declared(declared))
                if declared.is_high_risk() =>
            {
                DeclaredAction::Declared(declared)
            }
            (RouteReach::OpenEnded, _) => DeclaredAction::Declared(ActionClass::Communicate),
            (RouteReach::Fixed, declared) => declared,
        }
    }

    /// The action class as the operator declared it, before the route's
    /// reach is taken into account. This is what storage keeps.
    #[must_use]
    pub fn declared_action_class(&self) -> DeclaredAction {
        self.action_class
    }

    /// Declares what kind of action this route takes.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn declare_action_class(
        &mut self,
        action_class: DeclaredAction,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.action_class = action_class;
        self.record_update();
        Ok(())
    }

    /// Whether the service goes only where it was built to, or where it is
    /// told.
    #[must_use]
    pub fn reach(&self) -> RouteReach {
        self.reach
    }

    /// Declares the service's reach.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn declare_reach(
        &mut self,
        reach: RouteReach,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.reach = reach;
        self.record_update();
        Ok(())
    }

    /// Which hosts the route's URL parameters may name.
    #[must_use]
    pub fn parameter_rules(&self) -> &[ParameterRule] {
        &self.parameter_rules
    }

    /// Replaces the parameter rules.
    ///
    /// Raises `routing.route_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] when two rules name the same parameter
    ///   in the same place, in any spelling a server reads as one name. Only
    ///   the first would be applied, so the second's hosts would mean nothing.
    pub fn replace_parameter_rules(
        &mut self,
        rules: Vec<ParameterRule>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        ensure_ruled_once(&rules)?;
        self.parameter_rules = rules;
        self.record_update();
        Ok(())
    }

    /// Whether every call an agent makes here needs a person's approval.
    ///
    /// That is so for an open-ended route with no parameter rules. Without
    /// approval, it would take the agent anywhere it names.
    #[must_use]
    pub fn needs_approval_for_agents(&self) -> bool {
        crate::domains::routing::matching::parameter::needs_approval_for_agents(
            self.reach,
            &self.parameter_rules,
        )
    }
}
