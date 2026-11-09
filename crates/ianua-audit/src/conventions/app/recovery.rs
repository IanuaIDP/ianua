//! Background work is picked up again after a crash, and picking it up
//! never writes a false record. Each rule here stands for a mistake that
//! was made once:
//!
//! - **Every multi-step process is picked up by the reconcile sweep.** A
//!   process whose steps are queued as `StepJobs` (a tenant's setup, its
//!   teardown) must also be begun or resumed by the sweep, through a
//!   `*Start` of its own, or a lost event or a lost job leaves it half done
//!   for ever. And the sweep's tests name its step job, so the case is
//!   tried.
//! - **The sweep records nothing.** It queues the work again and never
//!   raises an event to restart it: a second `tenant.provisioned` or
//!   `tenant.deleted` is a false record, and tells every watcher twice.
//! - **A tenant never announces itself again.** No method of the tenant
//!   context re-raises a lifecycle event for the sake of restarting work.
//! - **A sweep over every tenant reaches every tenant.** A sweep walking
//!   `TenantBatches` does not skip tenants by status: a deleted tenant
//!   keeps its audit trail, whose retention and chain checks must still
//!   run.

use std::fs;
use std::path::Path;

use crate::conventions::app::source::{Findings, SourceFile, app_files};

/// The reconcile sweep, under `src/`.
const SWEEP: &str = "use_cases/scheduling/reconcile.rs";

/// Where the step jobs themselves are defined.
const STEP_JOBS: &str = "use_cases/scheduling/steps.rs";

/// The code of `file` before its test module.
fn production(file: &SourceFile) -> String {
    file.code().to_owned()
}

/// The whole of `file`, its tests included.
fn whole(file: &SourceFile) -> String {
    file.lines().join("\n")
}

/// The names `marker` introduces in `code`: the word after each `marker`,
/// such as `SetupSteps` for `pub type SetupSteps = StepJobs<..>`.
fn named_after(code: &str, marker: &str) -> Vec<String> {
    code.match_indices(marker)
        .filter_map(|(at, _)| {
            let rest = &code[at + marker.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// Each step process the app runs: its folder, the alias of its step jobs,
/// and the job type it queues them under.
struct Process {
    folder: String,
    steps: String,
    job: Option<String>,
}

fn processes(files: &[SourceFile]) -> Vec<Process> {
    files
        .iter()
        .filter(|file| file.path.starts_with("use_cases/") && file.path != STEP_JOBS)
        .flat_map(|file| {
            let code = production(file);
            let job = named_after(&code, "pub const ")
                .into_iter()
                .find(|name| name.ends_with("_STEP_JOB"));
            let folder = file
                .path
                .rsplit_once('/')
                .map_or("", |(dir, _)| dir)
                .to_owned();
            named_after(&code, "pub type ")
                .into_iter()
                .filter(|name| code.contains(&format!("{name} = StepJobs<")))
                .map(|steps| Process {
                    folder: folder.clone(),
                    steps,
                    job: job.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Step processes the reconcile sweep does not begin or resume, or whose
/// case its tests never try.
fn processes_left_behind(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    let Some(sweep) = files.iter().find(|file| file.path == SWEEP) else {
        found.flag_at(SWEEP, 1, "the reconcile sweep is missing");
        return found;
    };
    for process in processes(files) {
        for gap in sweep_gaps(files, sweep, &process) {
            found.flag_at(SWEEP, 1, gap);
        }
    }
    found
}

/// What `sweep`, the reconcile sweep, leaves undone of `process`: not
/// queuing its steps, not beginning or resuming it, or no test naming its
/// job.
fn sweep_gaps(files: &[SourceFile], sweep: &SourceFile, process: &Process) -> Vec<String> {
    let sweep_code = production(sweep);
    let starts: Vec<String> = (files.iter())
        .filter(|file| file.path.starts_with(&format!("{}/", process.folder)))
        .flat_map(|file| named_after(&production(file), "pub(crate) struct "))
        .filter(|name| name.ends_with("Start"))
        .collect();
    let steps = &process.steps;
    let mut gaps = Vec::new();
    if !sweep_code.contains(steps) {
        gaps.push(format!(
            "does not queue `{steps}`; a lost event or job leaves it half done"
        ));
    }
    if !starts
        .iter()
        .any(|start| sweep_code.contains(start.as_str()))
    {
        gaps.push(format!(
            "does not begin or resume the process of `{steps}` through its `*Start`"
        ));
    }
    if let Some(job) = &process.job
        && !whole(sweep).contains(job.as_str())
    {
        gaps.push(format!("no test of the sweep names `{job}`"));
    }
    gaps
}

/// Ways of recording an event.
const RECORDING: &[&str] = &[".dispatch(", ".dispatch_by(", "announce_"];

/// The reconcile sweep recording an event.
fn sweep_records(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files.iter().filter(|file| file.path == SWEEP) {
        let code = production(file);
        for sign in RECORDING {
            if code.contains(sign) {
                found.flag_file(
                    file,
                    format!("records with `{sign}`; queue the work again instead"),
                );
            }
        }
    }
    found
}

/// Tenant sweeps that skip tenants by status.
fn sweeps_skipping_tenants(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files
        .iter()
        .filter(|file| file.path.starts_with("use_cases/"))
    {
        let code = production(file);
        if code.contains("TenantBatches") && code.contains("TenantStatus::") {
            found.flag_file(
                file,
                "walks every tenant but skips some by status; a deleted tenant keeps its audit trail",
            );
        }
    }
    found
}

/// Tenant methods that raise a lifecycle event again to restart work.
fn announcements_again() -> Vec<String> {
    let root =
        crate::conventions::crate_dir("ianua-app").join("../ianua-domain/src/domains/tenant");
    let mut found = Vec::new();
    collect_announcements(&root, &root, &mut found);
    found
}

fn collect_announcements(root: &Path, dir: &Path, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_dir() {
            collect_announcements(root, &path, found);
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let shown = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        found.extend(
            text.lines()
                .enumerate()
                .filter(|(_, line)| line.contains("fn announce_"))
                .map(|(at, _)| format!("{shown}:{}: announces itself again", at + 1)),
        );
    }
}

#[cfg_attr(test, test)]
pub(crate) fn every_step_process_is_picked_up_by_the_sweep() {
    processes_left_behind(&app_files()).assert_none("step processes the sweep leaves behind");
}

#[cfg_attr(test, test)]
pub(crate) fn the_sweep_records_nothing() {
    sweep_records(&app_files()).assert_none("the reconcile sweep recording events");
}

#[cfg_attr(test, test)]
pub(crate) fn sweeps_over_every_tenant_reach_every_tenant() {
    sweeps_skipping_tenants(&app_files()).assert_none("tenant sweeps skipping tenants");
}

#[cfg_attr(test, test)]
pub(crate) fn a_tenant_never_announces_itself_again() {
    let found = announcements_again();
    assert!(
        found.is_empty(),
        "announcements again:\n{}",
        found.join("\n")
    );
}

/// Each check, run over files that break it on purpose, finds the break.
#[cfg_attr(test, test)]
pub(crate) fn every_recovery_check_finds_its_planted_break() {
    let process = SourceFile::planted(
        "use_cases/tenant/planted/job.rs",
        "pub const PLANTED_STEP_JOB: &str = \"x\";\npub type PlantedSteps = StepJobs<Step>;",
    );
    let start = SourceFile::planted(
        "use_cases/tenant/planted/start.rs",
        "pub(crate) struct PlantedStart;",
    );
    let sweep = SourceFile::planted(
        SWEEP,
        "fn round() { auditor.dispatch(&events); tenant.announce_provisioning(); }",
    );
    let skipping = SourceFile::planted(
        "use_cases/planted_sweep.rs",
        "let batches = TenantBatches::over(store); if t.status() != TenantStatus::Deleted {}",
    );
    let files = [process, start, sweep, skipping];

    assert!(!processes_left_behind(&files).is_empty());
    assert!(!sweep_records(&files).is_empty());
    assert!(!sweeps_skipping_tenants(&files).is_empty());
}
