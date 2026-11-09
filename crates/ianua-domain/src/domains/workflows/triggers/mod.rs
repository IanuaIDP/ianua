//! What starts a workflow: a person, a schedule, a call to its webhook, an
//! event in the tenant, or an event an integration's service sends. Also
//! the secret its webhook is called with, the registration a service's
//! events arrive through, and the input a tenant event starts it with.

pub mod before;
pub mod channel;
pub mod event_input;
pub mod secret;
pub mod subscription;

use std::ops::RangeInclusive;

use time::PrimitiveDateTime;

use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::integration::events::{ServiceEventKey, ServiceEventSpec};
use crate::domains::workflows::integration::{InputNeed, IntegrationKey};
use crate::domains::workflows::triggers::before::GuardedChange;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{EventType, IntegrationAccountId};

/// A five-field cron schedule: minute, hour, day of month, month, day of
/// week.
///
/// Each field is `*`, a number or a range `a-b`. Any of these may take a
/// step `/n`, and a field may list several, separated by commas. The
/// schedule is read in the tenant's timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSchedule(String);

/// The values each of the five fields may take, in order.
const FIELD_RANGES: [(&str, RangeInclusive<u32>); 5] = [
    ("minute", 0..=59),
    ("hour", 0..=23),
    ("day of month", 1..=31),
    ("month", 1..=12),
    ("day of week", 0..=6),
];

impl CronSchedule {
    /// Reads a schedule.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it does not have five fields.
    /// - [`DomainError::Validation`] when a field holds something other than
    ///   the forms above, or a step of 0.
    /// - [`DomainError::Validation`] when a value is outside its field's
    ///   range, or a range runs backwards.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let fields: Vec<&str> = text.split_whitespace().collect();
        if fields.len() != FIELD_RANGES.len() {
            return Err(DomainError::invalid(message!(
                "workflows-a-schedule-has-five-fields-minute",
                "a schedule has five fields: minute, hour, day of month, month and day of week"
            )));
        }
        for (field, (name, range)) in fields.iter().zip(FIELD_RANGES) {
            field
                .split(',')
                .try_for_each(|part| Self::check_part(part, name, &range))?;
        }
        Ok(Self(fields.join(" ")))
    }

    fn check_part(part: &str, name: &str, range: &RangeInclusive<u32>) -> Result<(), DomainError> {
        let values = match part.split_once('/') {
            Some((values, step)) => {
                Self::check_step(step, name)?;
                values
            }
            None => part,
        };
        if values == "*" {
            return Ok(());
        }
        let (low, high) = values.split_once('-').unwrap_or((values, values));
        let (low, high) = (Self::number(low, name)?, Self::number(high, name)?);
        if !range.contains(&low) || !range.contains(&high) || low > high {
            return Err(DomainError::invalid(message!(
                "workflows-the-field-takes-values-from-to",
                format!(
                    "the {name} field takes values from {} to {}",
                    range.start(),
                    range.end()
                )
            )));
        }
        Ok(())
    }

    fn check_step(step: &str, name: &str) -> Result<(), DomainError> {
        if Self::number(step, name)? == 0 {
            return Err(DomainError::invalid(message!(
                "workflows-a-step-in-the-field-must",
                format!("a step in the {name} field must be at least 1")
            )));
        }
        Ok(())
    }

    fn number(text: &str, name: &str) -> Result<u32, DomainError> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DomainError::invalid(message!(
                "workflows-the-field-holds-something-that-is",
                format!("the {name} field holds something that is not a number, a range or `*`")
            )));
        }
        text.parse().map_err(|_| {
            DomainError::invalid(message!(
                "workflows-a-number-in-the-field-is",
                format!("a number in the {name} field is too large")
            ))
        })
    }

    /// The schedule, as five fields separated by single spaces.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the schedule fires in the minute `at` falls in, `at` read as
    /// the wall clock shows it in the tenant's timezone.
    ///
    /// The minute, hour and month must each match. The day matches as cron
    /// reads it: when both the day of month and the day of week are
    /// restricted, either one matching is enough; when one of them is `*`
    /// or a step over `*`, the other alone decides.
    #[must_use]
    pub fn fires_at(&self, at: PrimitiveDateTime) -> bool {
        let [minutes, hours, days, months, weekdays] = FIELD_RANGES.map(|(_, range)| range);
        let mut fields = self.0.split(' ');
        let (Some(minute), Some(hour), Some(day), Some(month), Some(weekday)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return false;
        };
        let day_fits = field_matches(day, u32::from(at.day()), &days);
        let weekday_fits = field_matches(
            weekday,
            u32::from(at.weekday().number_days_from_sunday()),
            &weekdays,
        );
        let day_open = day.starts_with('*') || weekday.starts_with('*');
        let day_matches = match day_open {
            true => day_fits && weekday_fits,
            false => day_fits || weekday_fits,
        };
        field_matches(minute, u32::from(at.minute()), &minutes)
            && field_matches(hour, u32::from(at.hour()), &hours)
            && field_matches(month, u32::from(u8::from(at.month())), &months)
            && day_matches
    }
}

/// Whether `value` is one `field` takes, its values running over `range`.
fn field_matches(field: &str, value: u32, range: &RangeInclusive<u32>) -> bool {
    field
        .split(',')
        .any(|part| part_matches(part, value, range))
}

/// Whether `value` is one `part` of a field takes: `*`, a number or a range,
/// each perhaps stepped. A stepped single number runs to the field's end, as
/// `5/15` in the minute field means 5, 20, 35 and 50.
fn part_matches(part: &str, value: u32, range: &RangeInclusive<u32>) -> bool {
    let (low, high) = bounds_of(part, range);
    if value < low || value > high {
        return false;
    }
    let step = part
        .split_once('/')
        .and_then(|(_, step)| step.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    value
        .checked_sub(low)
        .and_then(|offset| offset.checked_rem(step))
        .is_some_and(|rest| rest == 0)
}

/// The values `part` runs over within `range`: all of it for `*`, a range
/// as written, or a single number, which runs to the end of the range when
/// it is stepped.
fn bounds_of(part: &str, range: &RangeInclusive<u32>) -> (u32, u32) {
    let (values, stepped) = match part.split_once('/') {
        Some((values, _)) => (values, Stepped::Yes),
        None => (part, Stepped::No),
    };
    if values == "*" {
        return (*range.start(), *range.end());
    }
    let number = |text: &str| text.parse::<u32>().unwrap_or(u32::MAX);
    match (values.split_once('-'), stepped) {
        (Some((low, high)), Stepped::Yes | Stepped::No) => (number(low), number(high)),
        (None, Stepped::Yes) => (number(values), *range.end()),
        (None, Stepped::No) => (number(values), number(values)),
    }
}

/// Whether a part of a schedule's field takes a step.
#[derive(Clone, Copy)]
enum Stepped {
    /// It does, as `5/15`.
    Yes,
    /// It does not, as `5`.
    No,
}

/// What starts a workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// A person starts it.
    Manual,
    /// It starts on a schedule.
    Schedule(CronSchedule),
    /// It starts when its webhook is called with the secret its publisher
    /// issued, a
    /// [`WorkflowTriggerSecret`](crate::domains::workflows::triggers::secret::WorkflowTriggerSecret).
    Webhook,
    /// It starts when an event happens in the tenant.
    Event(EventTrigger),
    /// It starts when an integration's service sends an event, such as an
    /// issue opened at GitHub, through a registration made with one of the
    /// tenant's accounts.
    Service(ServiceTrigger),
    /// It starts before a change happens, and decides it: every way through
    /// it ends in Allow or Refuse.
    Before(GuardedChange),
}

text_value! {
    /// The value of one filter of a service event, such as the repository
    /// `acme/web` it watches.
    pub struct FilterValue;
}

impl TextValue for FilterValue {
    const FIELD: &'static str = "filter";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=512).no_control_chars()
    }
}

/// One filter a service trigger gives its event, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFilter {
    name: FieldName,
    value: FilterValue,
}

impl EventFilter {
    /// The filter `name` set to `value`.
    #[must_use]
    pub fn new(name: FieldName, value: FilterValue) -> Self {
        Self { name, value }
    }

    /// The service filter key to apply when registering the event subscription.
    #[must_use]
    pub fn name(&self) -> &FieldName {
        &self.name
    }

    /// The typed criterion supplied for this service filter.
    #[must_use]
    pub fn value(&self) -> &FilterValue {
        &self.value
    }
}

/// The service event a workflow starts on: which integration, which event,
/// the account the registration at the service is made through, and the
/// event's filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTrigger {
    integration: IntegrationKey,
    event: ServiceEventKey,
    account: IntegrationAccountId,
    filters: Vec<EventFilter>,
}

impl ServiceTrigger {
    /// A trigger on `spec`'s event, registered through `account`, filtered
    /// by `filters`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a filter is one the event does not
    ///   take, is given twice, or one the event requires is left out.
    pub fn new(
        spec: &ServiceEventSpec,
        account: IntegrationAccountId,
        filters: Vec<EventFilter>,
    ) -> Result<Self, DomainError> {
        let trigger = Self {
            integration: spec.integration().clone(),
            event: spec.event().clone(),
            account,
            filters,
        };
        trigger.ensure_fits(spec)?;
        Ok(trigger)
    }

    /// A trigger as a person names it in a draft. Whether it fits its
    /// event, as the integration offers it, is asked when the draft is
    /// published, against the catalog as it stands then.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names one filter twice.
    pub fn drafted(
        integration: IntegrationKey,
        event: ServiceEventKey,
        account: IntegrationAccountId,
        filters: Vec<EventFilter>,
    ) -> Result<Self, DomainError> {
        if let Some(twice) = first_repeat(filters.iter().map(EventFilter::name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-filter-is-given-twice",
                format!("the filter {twice} is given twice")
            )));
        }
        Ok(Self {
            integration,
            event,
            account,
            filters,
        })
    }

    /// A trigger read back from storage as it was written. Whether it
    /// still fits its event is asked again at publish.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored filters name one
    ///   filter twice, which no trigger was ever built with.
    pub fn from_stored(
        integration: IntegrationKey,
        event: ServiceEventKey,
        account: IntegrationAccountId,
        filters: Vec<EventFilter>,
    ) -> Result<Self, DomainError> {
        if first_repeat(filters.iter().map(EventFilter::name)).is_some() {
            return Err(DomainError::corrupt_row(
                "service trigger",
                "a filter given twice",
            ));
        }
        Ok(Self {
            integration,
            event,
            account,
            filters,
        })
    }

    /// Refuses this trigger when `spec` no longer describes it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `spec` is another event, a filter
    ///   is one it does not take or is given twice, or a filter it requires
    ///   is left out.
    pub fn ensure_fits(&self, spec: &ServiceEventSpec) -> Result<(), DomainError> {
        if &self.integration != spec.integration() || &self.event != spec.event() {
            return Err(DomainError::invalid(message!(
                "workflows-the-trigger-is-another-event",
                format!(
                    "the trigger is on {}.{}, not {}.{}",
                    self.integration,
                    self.event,
                    spec.integration(),
                    spec.event()
                )
            )));
        }
        if let Some(twice) = first_repeat(self.filters.iter().map(EventFilter::name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-filter-is-given-twice",
                format!("the filter {twice} is given twice")
            )));
        }
        self.ensure_filters_known(spec)?;
        self.ensure_required_filters_given(spec)
    }

    fn ensure_filters_known(&self, spec: &ServiceEventSpec) -> Result<(), DomainError> {
        let unknown = self.filters.iter().find(|filter| {
            !spec
                .filters()
                .iter()
                .any(|taken| taken.name() == filter.name())
        });
        let Some(unknown) = unknown else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "workflows-the-event-takes-no-filter",
            format!("{} takes no filter {}", spec.event(), unknown.name())
        )))
    }

    fn ensure_required_filters_given(&self, spec: &ServiceEventSpec) -> Result<(), DomainError> {
        let missing = spec.filters().iter().find(|taken| {
            taken.need() == InputNeed::Required
                && !self
                    .filters
                    .iter()
                    .any(|filter| filter.name() == taken.name())
        });
        let Some(missing) = missing else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "workflows-the-event-needs-the-filter",
            format!("{} needs the filter {}", spec.event(), missing.name())
        )))
    }

    /// The integration whose service sends the event.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The service occurrence that the remote registration should deliver.
    #[must_use]
    pub fn event(&self) -> &ServiceEventKey {
        &self.event
    }

    /// The account the registration is made through.
    #[must_use]
    pub fn account(&self) -> IntegrationAccountId {
        self.account
    }

    /// The event's filters.
    #[must_use]
    pub fn filters(&self) -> &[EventFilter] {
        &self.filters
    }
}

/// The event a workflow starts on, never one of a workflow's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventTrigger(EventType);

impl EventTrigger {
    /// A trigger on `event`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a workflow's own events. A workflow
    ///   that starts when a workflow runs could start itself without end.
    pub fn new(event: EventType) -> Result<Self, DomainError> {
        if matches!(event, EventType::Workflows(_)) {
            return Err(DomainError::invalid(message!(
                "workflows-a-workflow-cannot-start-on-a",
                "a workflow cannot start on a workflow's own events"
            )));
        }
        Ok(Self(event))
    }

    /// The domain occurrence permitted to start an execution.
    #[must_use]
    pub fn event(self) -> EventType {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::{IdentityEvent, WorkflowsEvent};

    /// Weekdays at nine, every fifteen minutes, the first of each quarter
    /// and Sundays at half past two are all read as valid schedules.
    #[test]
    fn common_schedules_are_read() {
        for text in [
            "0 9 * * 1-5",
            "*/15 * * * *",
            "0 0 1 1,4,7,10 *",
            "30 2 * * 0",
        ] {
            assert!(CronSchedule::parse(text).is_ok(), "{text}");
        }
    }

    /// A schedule typed with extra spaces, ` 0  9 * *  1`, is kept as
    /// `0 9 * * 1`.
    #[test]
    fn a_schedule_is_kept_with_single_spaces() {
        assert_eq!(
            CronSchedule::parse(" 0  9 * *  1").unwrap().as_str(),
            "0 9 * * 1"
        );
    }

    /// Minute 60, hour 24, day 0, month 13, weekday 7, a backwards range, a
    /// step of 0, four fields, a letter and `1--` are each refused.
    #[test]
    fn a_schedule_out_of_range_or_malformed_is_refused() {
        for text in [
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 7",
            "5-1 * * * *",
            "*/0 * * * *",
            "* * * *",
            "a * * * *",
            "1-- * * * *",
        ] {
            assert!(CronSchedule::parse(text).is_err(), "{text}");
        }
    }

    /// Monday 2026-10-26 at `hour`:`minute`, as a tenant's clock shows it.
    fn monday_at(hour: u8, minute: u8) -> PrimitiveDateTime {
        let date = time::Date::from_calendar_date(2026, time::Month::October, 26).unwrap();
        PrimitiveDateTime::new(date, time::Time::from_hms(hour, minute, 0).unwrap())
    }

    fn fires(text: &str, at: PrimitiveDateTime) -> bool {
        CronSchedule::parse(text).unwrap().fires_at(at)
    }

    /// Weekdays at nine fire on Monday at nine, and not at ten past.
    #[test]
    fn weekdays_at_nine_fire_on_monday_at_nine_only() {
        assert!(fires("0 9 * * 1-5", monday_at(9, 0)));
        assert!(!fires("0 9 * * 1-5", monday_at(9, 10)));
        assert!(!fires("0 9 * * 0", monday_at(9, 0)));
    }

    /// Every fifteen minutes fires at a quarter past and not at twenty
    /// past; `5/15` fires at five and twenty past.
    #[test]
    fn steps_fire_on_their_multiples() {
        assert!(fires("*/15 * * * *", monday_at(3, 15)));
        assert!(!fires("*/15 * * * *", monday_at(3, 20)));
        assert!(fires("5/15 * * * *", monday_at(3, 20)));
        assert!(!fires("5/15 * * * *", monday_at(3, 15)));
    }

    /// The first of the month or a Monday, both restricted, fires on any
    /// Monday, as cron reads it.
    #[test]
    fn a_restricted_day_and_weekday_fire_on_either() {
        assert!(fires("0 0 1 * 1", monday_at(0, 0)));
        assert!(!fires("0 0 2 * 2", monday_at(0, 0)));
    }

    /// October's schedule fires in October, and a quarterly one not then.
    #[test]
    fn the_month_must_match() {
        assert!(fires("0 9 * 10 *", monday_at(9, 0)));
        assert!(!fires("0 9 * 1,4,7 *", monday_at(9, 0)));
    }

    /// A trigger on a user registering is allowed. A trigger on a workflow
    /// run starting is refused, since the workflow could start itself
    /// without end.
    #[test]
    fn a_workflow_cannot_start_on_a_workflows_own_events() {
        assert!(EventTrigger::new(EventType::Identity(IdentityEvent::UserRegistered)).is_ok());
        assert!(EventTrigger::new(EventType::Workflows(WorkflowsEvent::ExecutionStarted)).is_err());
    }

    /// GitHub's "an issue is opened", watching a repository and taking a
    /// label to narrow it.
    fn issue_opened() -> ServiceEventSpec {
        ServiceEventSpec::new(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            vec![
                crate::domains::workflows::integration::InputSpec::new(
                    FieldName::new("repository").unwrap(),
                    InputNeed::Required,
                ),
                crate::domains::workflows::integration::InputSpec::new(
                    FieldName::new("label").unwrap(),
                    InputNeed::Optional,
                ),
            ],
        )
        .unwrap()
    }

    fn filter(name: &str, value: &str) -> EventFilter {
        EventFilter::new(
            FieldName::new(name).unwrap(),
            FilterValue::new(value).unwrap(),
        )
    }

    /// Ann's workflow starts when an issue is opened in `acme/web`, through
    /// her team's GitHub account; the label is left out, as it may be.
    #[test]
    fn a_service_trigger_names_its_event_account_and_filters() {
        let account = IntegrationAccountId::new();

        let trigger = ServiceTrigger::new(
            &issue_opened(),
            account,
            vec![filter("repository", "acme/web")],
        )
        .unwrap();

        assert_eq!(trigger.event().as_str(), "issue-opened");
        assert_eq!(trigger.account(), account);
        assert_eq!(trigger.filters()[0].value().as_str(), "acme/web");
    }

    /// Service triggers reject a missing required repository, an unknown
    /// filter and a repository filter supplied twice.
    #[test]
    fn a_service_trigger_that_does_not_fit_its_event_is_refused() {
        for filters in [
            vec![filter("label", "bug")],
            vec![filter("repository", "acme/web"), filter("branch", "main")],
            vec![
                filter("repository", "acme/web"),
                filter("repository", "acme/api"),
            ],
        ] {
            assert!(
                ServiceTrigger::new(&issue_opened(), IntegrationAccountId::new(), filters).is_err()
            );
        }
    }

    /// A service filter value cannot contain a line break.
    #[test]
    fn a_filter_value_with_a_control_character_is_refused() {
        assert!(FilterValue::new("acme/web\nevil").is_err());
    }
}
