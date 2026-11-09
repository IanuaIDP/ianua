//! Records: commands that change what is stored and say nothing of it.
//!
//! A command calls a domain change that raises events, then writes to a
//! store through a `*Store` port (`save`, `insert`, `update`, `delete` and
//! the like). A path through it that does both, then hands back `Ok` (or a
//! value that may be `Ok`) without dispatching any event, drops what the
//! change raised: the change is kept, and is missing from the audit trail
//! and from everything that listens. A write after nothing that raises,
//! such as a counter or a sweep that found nothing, owes no event. The
//! question is asked of the command's flow (see
//! [`crate::model::facts::flow`]): a path through a not-read point might
//! dispatch there, so it is not reported, and is counted instead.
//!
//! The commands the app's conventions list as recording nothing on purpose
//! (`SILENT_COMMANDS_ALLOWED` and `UNRECORDED_SAVES_ALLOWED` in
//! `crates/ianua-audit/src/conventions/app/security.rs`, read as text) are left
//! alone: the list is read, not copied.

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::Model;
use crate::model::facts::flow::{Answer, owed, succeeds_without};
use crate::model::facts::{Facts, UseCaseFacts};
use crate::source::Place;

/// Every records finding.
pub(crate) fn run(model: &Model, facts: &Facts) -> Found {
    let mut found = Found::default();
    let commands = facts
        .use_cases
        .iter()
        .filter(|found| found.kind == "command")
        .filter(|found| !silent_on_purpose(model, found));
    for use_case in commands {
        let answer = succeeds_without(&use_case.flow, owed(use_case), &use_case.end);
        match answer {
            Answer::No => {}
            Answer::Unknown(unread) => found.leave_unsaid(Unsaid::new(
                Check::SuccessWithoutEvent,
                subject(use_case),
                unread.place,
                unread.what,
            )),
            Answer::Yes(places) => found.findings.push(finding(use_case, &places)),
        }
    }
    found
}

/// Whether the app's conventions list `use_case` as recording nothing on
/// purpose.
fn silent_on_purpose(model: &Model, use_case: &UseCaseFacts) -> bool {
    let Some(file) = use_case.place.file.strip_prefix(APP_SOURCE) else {
        return false;
    };
    model
        .app
        .silent_commands
        .contains(&(file.to_owned(), use_case.name.clone()))
}

/// Where the app's files sit, from the workspace root.
const APP_SOURCE: &str = "crates/ianua-app/src/";

fn finding(use_case: &UseCaseFacts, places: &[Place]) -> Finding {
    let saved = places
        .first()
        .cloned()
        .unwrap_or_else(|| use_case.place.clone());
    let message = format!(
        "`{}` ({}) has a path that saves a change that raised events and succeeds without dispatching any",
        use_case.name, use_case.context
    );
    let mut detail = vec![format!("write:   {}  the store write", location(&saved))];
    if let Some(exit) = places.get(1) {
        detail.push(format!(
            "returns: {}  hands back Ok with nothing dispatched on the way",
            location(exit)
        ));
    }
    let command = location(&use_case.place);
    detail.push(format!("command: {command}  {}", use_case.name));
    detail.push(
        "why: a change no event records is missing from the audit trail, and nothing that listens learns of it".to_owned(),
    );
    detail.push(
        "fix: raise the event in the domain change and dispatch what `take_events` hands back after the write, on every path that succeeds".to_owned(),
    );
    Finding::new(
        Check::SuccessWithoutEvent,
        saved,
        subject(use_case),
        message,
    )
    .with_detail(detail)
}

/// What a records finding is about: `context::UseCase`.
fn subject(use_case: &UseCaseFacts) -> String {
    format!("{}::{}", use_case.context, use_case.name)
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::facts::planted::{PORTS, SUBSCRIPTION, model};
    use crate::source::planted::{app, domain, workspace};

    fn found(body: &str) -> Found {
        found_with(&format!("{PAUSE} {body}"), &[])
    }

    /// Pausing the subscription raises `WebhookSubscriptionPaused`.
    const PAUSE: &str = "subscription.pause(&control).map_err(AppError::from_domain)?;";

    #[test]
    fn a_save_of_what_raised_nothing_owes_no_dispatch() {
        let found = found_with(
            "self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
             Ok(())",
            &[],
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    fn found_with(body: &str, silent: &[(&str, &str)]) -> Found {
        let command = format!(
            "pub struct TouchPorts {{ pub webhook_store: Arc<dyn WebhookStore> }}
             pub struct TouchUseCase {{ ports: TouchPorts }}
             impl Command for TouchUseCase {{
                 async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, id: WebhookSubscriptionId) -> Result<(), AppError> {{
                     let mut subscription: WebhookSubscription<ResolvedTenant> = self.ports.webhook_store.find_by_id(&tenant, &id).await.or_internal()?;
                     {body}
                 }}
             }}"
        );
        let ws = workspace(vec![
            domain("domains/webhooks/subscription.rs", SUBSCRIPTION),
            app("ports/webhooks.rs", PORTS),
            app("use_cases/webhooks/touch.rs", &command),
        ]);
        let mut model = model(&ws);
        model.app.silent_commands = silent
            .iter()
            .map(|(file, name)| ((*file).to_owned(), (*name).to_owned()))
            .collect();
        let facts = Facts::build(&ws, &model);
        run(&model, &facts)
    }

    #[test]
    fn a_command_the_conventions_list_as_silent_stays_quiet() {
        let found = found_with(
            "self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()",
            &[("use_cases/webhooks/touch.rs", "TouchUseCase")],
        );

        assert!(found.findings.is_empty());
    }

    #[test]
    fn the_silent_commands_are_read_from_the_app_conventions() {
        let text = r#"
            const GIVEN_UP: &str = "why";
            const SILENT_COMMANDS_ALLOWED: &[Exception] = &[
                ("use_cases/a.rs", "AUseCase", GIVEN_UP),
            ];
            const UNRECORDED_SAVES_ALLOWED: &[Exception] = &[
                ("use_cases/b.rs", "BUseCase::execute", "why"),
            ];
        "#;

        let read = crate::model::app::silent_commands(text);

        assert!(read.contains(&("use_cases/a.rs".to_owned(), "AUseCase".to_owned())));
        assert!(read.contains(&("use_cases/b.rs".to_owned(), "BUseCase".to_owned())));
    }

    #[test]
    fn a_save_then_ok_without_a_dispatch_is_reported() {
        let found = found(
            "self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
             Ok(())",
        );

        let finding = &found.findings[0];
        assert_eq!(finding.subject, "webhooks::TouchUseCase");
        assert!(
            finding.detail[1]
                .starts_with("returns: crates/ianua-app/src/use_cases/webhooks/touch.rs:")
        );
    }

    #[test]
    fn a_save_followed_by_a_dispatch_on_every_path_stays_quiet() {
        let found = found(
            "self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
             auditor.dispatch_by(&caller.actor(), subscription.take_events(&tenant)).await.or_internal()",
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    /// The webhook ports with a listing, a write that says whether it
    /// wrote, and a unit of work.
    const SWEEP_PORTS: &str = r"
        pub trait WebhookStore: Send + Sync {
            async fn find_by_id(&self, tenant: &ScopedTenant, id: &WebhookSubscriptionId)
                -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError>;
            async fn list(&self, tenant: &ScopedTenant) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError>;
            async fn save(&self, tenant: &ScopedTenant, subscription: &WebhookSubscription<ResolvedTenant>)
                -> Result<(), DomainError>;
            async fn remove_paused(&self, tenant: &ScopedTenant, subscription: &WebhookSubscription<ResolvedTenant>)
                -> Result<bool, DomainError>;
        }
        pub trait UnitOfWork: Send + Sync {
            async fn run(&self, work: UnitWork<'_>) -> Result<(), DomainError>;
        }
    ";

    /// Pauses `subscription`, saves it, then dispatches what it raised.
    const TOUCHED: &str = "
        async fn touched(&self, auditor: &RequestAuditor, mut subscription: WebhookSubscription<ResolvedTenant>)
            -> Result<(), AppError> {
            subscription.pause(&control).map_err(AppError::from_domain)?;
            self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
            auditor.dispatch_by(&ActorRef::System, subscription.take_events(&tenant)).await.or_internal()
        }";

    /// A sweep over every subscription, with `free` beside it, running
    /// `body` once it listed them.
    fn swept(free: &str, body: &str) -> Found {
        let command = format!(
            "pub struct SweepPorts {{ pub webhook_store: Arc<dyn WebhookStore>, pub unit: Arc<dyn UnitOfWork> }}
             pub struct SweepUseCase {{ ports: SweepPorts }}
             impl SweepUseCase {{ {TOUCHED} }}
             impl Command for SweepUseCase {{
                 async fn execute(&self, caller: &(), auditor: &RequestAuditor, (): ()) -> Result<u64, AppError> {{
                     let listed = self.ports.webhook_store.list(&tenant).await.or_internal()?;
                     let mut count = 0;
                     {body}
                     Ok(count)
                 }}
             }}
             {free}"
        );
        let ws = workspace(vec![
            domain("domains/webhooks/subscription.rs", SUBSCRIPTION),
            app("ports/webhooks.rs", SWEEP_PORTS),
            app("use_cases/webhooks/sweep.rs", &command),
        ]);
        let model = model(&ws);
        run(&model, &Facts::build(&ws, &model))
    }

    /// The sweep logs a subscription it could not touch and goes on. One
    /// saved whose dispatch then failed is kept, and never recorded.
    #[test]
    fn a_helper_failing_after_its_save_and_logged_by_a_match_is_reported() {
        let found = swept(
            "",
            "for subscription in listed {
                 match self.touched(auditor, subscription).await {
                     Ok(()) => count += 1,
                     Err(error) => tracing::warn!(%error, \"left for the next sweep\"),
                 }
             }",
        );

        assert_eq!(found.findings.len(), 1);
        assert!(found.unsaid.is_empty());
    }

    #[test]
    fn a_helper_failing_after_its_save_and_recovered_by_unwrap_or_else_is_reported() {
        let found = swept(
            "",
            "for subscription in listed {
                 self.touched(auditor, subscription).await.unwrap_or_else(|error| {
                     tracing::warn!(%error, \"left for the next sweep\");
                 });
             }",
        );

        assert_eq!(found.findings.len(), 1);
    }

    /// The touch is made first and run inside a unit of work: a failure
    /// drops the save with it.
    #[test]
    fn work_bound_first_and_run_in_a_unit_drops_its_save_when_it_fails() {
        let found = swept(
            "",
            "for subscription in listed {
                 let work = self.touched(auditor, subscription);
                 kept_together(self.ports.unit.as_ref(), work).await?;
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// The touch is handed to a helper that runs it in a unit and counts
    /// what went through: the helper runs it there.
    #[test]
    fn work_handed_to_a_helper_that_runs_it_in_a_unit_is_read_there() {
        let found = swept(
            "async fn swept(unit: &dyn UnitOfWork, work: impl Future<Output = Result<(), AppError>>) -> u64 {
                 match kept_together(unit, work).await {
                     Ok(()) => 1,
                     Err(_) => 0,
                 }
             }",
            "for subscription in listed {
                 let work = self.touched(auditor, subscription);
                 count += swept(self.ports.unit.as_ref(), work).await;
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// A save that fails keeps nothing: its error arm owes no record.
    #[test]
    fn a_save_whose_own_call_failed_owes_nothing_on_its_error_arm() {
        let found = swept(
            "",
            "for mut subscription in listed {
                 subscription.pause(&control).map_err(AppError::from_domain)?;
                 match self.ports.webhook_store.save(&tenant, &subscription).await {
                     Ok(()) => auditor.dispatch_by(&ActorRef::System, subscription.take_events(&tenant)).await.or_internal()?,
                     Err(error) => tracing::warn!(%error, \"not saved\"),
                 }
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// The paused subscription is never saved; another value is.
    #[test]
    fn a_save_of_another_value_than_the_one_that_raised_owes_nothing() {
        let found = swept(
            "",
            "for mut subscription in listed {
                 subscription.pause(&control).map_err(AppError::from_domain)?;
                 let Some(fresh) = self.ports.webhook_store.find_by_id(&tenant, &id).await.or_internal()? else {
                     continue;
                 };
                 self.ports.webhook_store.save(&tenant, &fresh).await.or_internal()?;
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// The write says whether it removed anything, and the sweep goes on
    /// without a record when it did not: what the answer means is not read.
    #[test]
    fn a_write_that_answers_whether_it_wrote_leaves_the_answer_unsaid() {
        let found = swept(
            "",
            "for mut subscription in listed {
                 subscription.pause(&control).map_err(AppError::from_domain)?;
                 if !self.ports.webhook_store.remove_paused(&tenant, &subscription).await.or_internal()? {
                     continue;
                 }
                 auditor.dispatch_by(&ActorRef::System, subscription.take_events(&tenant)).await.or_internal()?;
             }",
        );

        assert!(found.findings.is_empty());
        assert!(
            found.unsaid[0]
                .why
                .ends_with("hands back whether it wrote anything, and the paths that branch on it are not told apart")
        );
    }

    /// A failure counted on a subscription, which raises an event and says
    /// what it did.
    const COUNTED_FAILURE: &str = "
            pub enum FailureOutcome { Counted, Disabled }
            impl<T: TenantScope> WebhookSubscription<T> {
                pub fn record_failure(&mut self) -> FailureOutcome {
                    self.raised.raise(WebhookSubscriptionPaused { at: now() });
                    FailureOutcome::Disabled
                }
            }";

    /// A command that counts a failure and dispatches only when it switched
    /// the subscription off.
    const COUNT_COMMAND: &str = "
            pub struct CountPorts { pub webhook_store: Arc<dyn WebhookStore> }
            pub struct CountUseCase { ports: CountPorts }
            impl Command for CountUseCase {
                async fn execute(&self, caller: &(), auditor: &RequestAuditor, (): ()) -> Result<(), AppError> {
                    let mut subscription: WebhookSubscription<ResolvedTenant> = loaded();
                    let outcome = subscription.record_failure();
                    self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
                    if outcome != FailureOutcome::Disabled { return Ok(()); }
                    auditor.dispatch(&subscription.take_events(&tenant)).await.or_internal()
                }
            }";

    /// Counting a failure raises an event only when it switches the
    /// subscription off, and says which it did: the reader does not tie the
    /// answer to the event, so it does not conclude.
    #[test]
    fn a_change_that_answers_what_it_did_leaves_its_events_unsaid() {
        let ws = workspace(vec![
            domain("domains/webhooks/subscription.rs", SUBSCRIPTION),
            domain("domains/webhooks/failures.rs", COUNTED_FAILURE),
            app("ports/webhooks.rs", SWEEP_PORTS),
            app("use_cases/webhooks/count.rs", COUNT_COMMAND),
        ]);
        let model = model(&ws);

        let found = run(&model, &Facts::build(&ws, &model));

        assert!(found.findings.is_empty());
        assert!(
            found.unsaid[0]
                .why
                .contains("hands back a `FailureOutcome`")
        );
    }

    /// A helper that saves and hands back an error value: the command wraps
    /// it in `Err`, so the path fails, whatever the helper hands back.
    #[test]
    fn a_helper_wrapped_in_err_does_not_hand_back_its_own_exits() {
        let found = swept(
            "async fn refused(mut subscription: WebhookSubscription<ResolvedTenant>, store: &dyn WebhookStore) -> AppError {
                 subscription.pause(&control);
                 if store.save(&tenant, &subscription).await.is_err() {
                     return AppError::Internal(\"lost\".into());
                 }
                 AppError::Conflict(\"paused\".into())
             }",
            "for subscription in listed {
                 return Err(refused(subscription, self.ports.webhook_store.as_ref()).await);
             }",
        );

        assert!(found.findings.is_empty());
    }

    #[test]
    fn a_not_read_point_after_the_save_keeps_it_quiet_and_is_counted() {
        let found = found(
            "self.ports.webhook_store.save(&tenant, &subscription).await.or_internal()?;
             external::record(auditor, ()).await?;
             Ok(())",
        );

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::SuccessWithoutEvent), Some(&1));
        assert_eq!(
            found.unsaid[0].why,
            "`external::record(..)`: it is handed `auditor`, and the reader does not follow it"
        );
    }
}
