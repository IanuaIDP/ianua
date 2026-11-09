//! How an execution starts: by hand, as a test, on an event, a schedule, a
//! webhook or a service's event, before a change it decides, and the
//! planning and jobs that start them from the worker.

pub(crate) mod as_test;
pub(crate) mod before;
pub(crate) mod by_hand;
pub(crate) mod event_job;
pub(crate) mod fire_schedules;
pub(crate) mod on_event;
pub(crate) mod on_service_event;
pub(crate) mod on_trigger;
pub(crate) mod on_webhook;
pub(crate) mod plan_events;
pub(crate) mod schedule_job;
pub(super) mod triggered;

pub use as_test::{StartTestPorts, StartTestRequest, StartTestUseCase};
pub use before::DecideBeforeUseCase;
pub use by_hand::{StartByHandPorts, StartByHandRequest, StartByHandUseCase};
pub use event_job::{EventStarts, START_ON_EVENT_JOB, StartOnEventHandler};
pub use fire_schedules::{FireSchedulesPorts, FireSchedulesUseCase};
pub use on_event::{StartOnEventPorts, StartOnEventRequest, StartOnEventUseCase};
pub use on_service_event::{
    DeliveredTo, ServiceEventAnswer, ServiceEventRequest, StartOnServiceEventPorts,
    StartOnServiceEventUseCase,
};
pub use on_trigger::{
    StartOnTriggerRequest, StartOnTriggerUseCase, TriggerStartPorts, TriggeredStart,
};
pub use on_webhook::{StartOnWebhookPorts, StartOnWebhookRequest, StartOnWebhookUseCase};
pub use plan_events::{PlanEventStartsPorts, PlanEventStartsUseCase};
pub use schedule_job::{START_SCHEDULED_JOB, ScheduledStarts, StartScheduledHandler};
