//! The shape every use case keeps, checked over the app's source so a file
//! that drifts fails the build instead of waiting for a reviewer.
//!
//! - A use case file holds one `Command` or `Query`, so one `execute`.
//! - No use case takes a bare id as its caller. An id is the caller's word,
//!   not a proof of who they are.
//! - Only `acting` turns a caller into the domain's proofs, and the test
//!   fakes in `test_support/acting.rs` stand in for it. A use case asks it,
//!   and never builds a `TenantAuthority`, an `OrgControl` or a sign-in
//!   itself.
//! - Only the workflow run driver makes a caller coming through a run, and
//!   only for the run it drives, so nothing else borrows a person's rights
//!   by naming a run.
//! - A use case asks `acting` through its traits, never through a concrete
//!   resolver, so its tests can say what a caller holds.
//! - A proof that skips its records, `assumed`, appears only in tests.
//! - No use case checks a permission by hand. What someone may do is the
//!   domain's to decide.
//! - No use case asks the old `Authorizer` port.
//! - A port never reaches into a use case for the types it carries.
//! - A port takes typed ids, hashes and keys, never a bare `Uuid` or a
//!   `&str` for a hash, prefix or token, and reports `DomainError`, never
//!   `AppError`. A port file is checked once its context is switched on.
//!
//! The layout of each use case file and its plan limits are checked in
//! [`shape`], the order of loads, rights, saves and records and the scoping
//! of store ports in [`security`], the code style the app shares with the
//! domain in [`style`], code written twice in [`duplicates`], and background
//! work picked up again after a crash, without false records, in
//! [`recovery`]. Areas switched off while they are moved to the new domain
//! are skipped.

pub(crate) mod duplicates;
pub(crate) mod events;
pub(crate) mod naming;
pub(crate) mod recovery;
pub(crate) mod security;
pub(crate) mod shape;
pub(crate) mod source;
pub(crate) mod style;

use source::{Check, Findings, SourceFile, app_files};
use syn::visit::Visit;

/// The caller types that are only someone's word for who they are.
const BARE_ID_CALLERS: &[&str] = &[
    "UserId",
    "OrgUserId",
    "OperatorId",
    "OrganizationId",
    "TenantId",
    "ActorRef",
];

/// Calls that build a proof of who is acting. Only `acting` makes them.
const PROOF_BUILDERS: &[&str] = &[
    ".authority_of(",
    "authority_of_key(",
    "authority_of_member_key(",
    "authority_in(",
    "OrgControl::new(",
    "OperatorAuthority::of",
    ".act_as(",
    ".signed_in(&",
    ".checked(&",
];

/// Ways of checking a permission by hand.
const HAND_CHECKS: &[&str] = &[
    "contains(&SystemPermission",
    "== SystemPermission",
    "has_permission(",
    ".list_permissions(",
];

fn use_case_files(files: &[SourceFile]) -> impl Iterator<Item = &SourceFile> {
    files
        .iter()
        .filter(|file| file.path.starts_with("use_cases/"))
}

/// Files holding more than one use case.
fn files_with_two_use_cases(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in use_case_files(files) {
        let count = file.use_case_impls().len();
        if count > 1 {
            found.flag_file(
                file,
                format!("{count} use cases in one file; give each its own"),
            );
        }
    }
    found
}

/// Use cases whose caller is a bare id.
fn bare_id_callers(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in use_case_files(files) {
        for caller in file.callers() {
            if BARE_ID_CALLERS.contains(&caller.as_str()) {
                found.flag_file(
                    file,
                    format!("takes `{caller}` as its caller; take a caller type"),
                );
            }
        }
    }
    found
}

/// Proofs built outside `acting`.
fn proofs_built_outside_acting(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files
        .iter()
        .filter(|file| !file.path.starts_with("acting/") && file.path != "test_support/acting.rs")
    {
        for builder in PROOF_BUILDERS {
            if file.code().contains(builder) {
                found.flag_file(
                    file,
                    format!("builds a proof with `{builder}`; ask `acting`"),
                );
            }
        }
    }
    found
}

/// The one file that makes a caller coming through a workflow run: the
/// run driver's company steps, for the run being driven.
const RUN_CALLER_MAKER: &str = "use_cases/workflows/executions/driving/company.rs";

/// Callers made as coming through a workflow run anywhere but the run
/// driver; matching on one is fine anywhere.
fn run_callers_made_elsewhere(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files.iter().filter(|file| file.path != RUN_CALLER_MAKER) {
        let Ok(code) = syn::parse_file(file.code()) else {
            continue;
        };
        let mut made = RunCallers::default();
        made.visit_file(&code);
        for call in made.found {
            found.flag(
                file,
                call,
                "makes a caller through a workflow run; only the run driver does, for the run it drives",
            );
        }
    }
    found
}

/// The calls making a `Credential::WorkflowRun`.
#[derive(Default)]
struct RunCallers<'ast> {
    found: Vec<&'ast syn::ExprCall>,
}

impl<'ast> Visit<'ast> for RunCallers<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if names_run_credential(&call.func) {
            self.found.push(call);
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Whether `func` is `Credential::WorkflowRun`, however it is reached.
fn names_run_credential(func: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = func else {
        return false;
    };
    let names: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    names.ends_with(&["Credential".to_owned(), "WorkflowRun".to_owned()])
}

/// The resolvers behind the `acting` traits.
const RESOLVERS: &[&str] = &[
    "TenantActing",
    "OrgActing",
    "OperatorActing",
    "AgentActing",
    "ConsumerActing",
    "ScimActing",
];

/// Use cases naming a concrete resolver instead of its trait.
fn resolvers_named_by_use_cases(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in use_case_files(files) {
        for resolver in RESOLVERS {
            let named = file
                .code()
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == *resolver);
            if named {
                found.flag_file(file, format!("names `{resolver}`; take its trait"));
            }
        }
    }
    found
}

/// Test-only proofs used outside tests.
fn assumed_outside_tests(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files
        .iter()
        .filter(|file| !file.path.starts_with("test_support/"))
    {
        if file.code().contains("::assumed(") {
            found.flag_file(file, "uses an `assumed` proof outside tests");
        }
    }
    found
}

/// Permissions checked by hand in a use case.
fn hand_written_checks(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in use_case_files(files) {
        for check in HAND_CHECKS {
            if file.code().contains(check) {
                found.flag_file(file, format!("checks a permission by hand with `{check}`"));
            }
        }
    }
    found
}

/// Signs of a port taking an untyped value or reporting an app error.
const UNTYPED_PORT_SIGNS: &[&str] = &[
    "&Uuid",
    ": Uuid",
    "<Uuid>",
    "hash: &str",
    "prefix: &str",
    "token: &str",
    "AppError",
];

/// Ports of switched-on contexts that take untyped values or report app
/// errors.
fn untyped_ports(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    let checked = crate::conventions::app::source::checked_port_files(files);
    for file in files.iter().filter(|file| checked.contains(&file.path)) {
        for sign in UNTYPED_PORT_SIGNS {
            if file.code().contains(sign) {
                found.flag_file(file, format!("`{sign}` in a port; take the typed value"));
            }
        }
    }
    found
}

/// Use cases or services asking the old `Authorizer` port.
fn authorizer_users(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files.iter().filter(|file| !file.path.starts_with("ports/")) {
        let names_it = file
            .code()
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|word| word == "Authorizer");
        if names_it {
            found.flag_file(
                file,
                "asks the `Authorizer` port; ask `acting` for the proof",
            );
        }
    }
    found
}

/// Ports that reach into a use case.
fn ports_reaching_into_use_cases(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files.iter().filter(|file| file.path.starts_with("ports/")) {
        if file.code().contains("crate::use_cases") {
            found.flag_file(
                file,
                "takes a type from a use case; the port owns its types",
            );
        }
    }
    found
}

#[cfg_attr(test, test)]
pub(crate) fn every_use_case_has_a_file_of_its_own() {
    files_with_two_use_cases(&app_files()).assert_none("files with two use cases");
}

#[cfg_attr(test, test)]
pub(crate) fn no_use_case_takes_a_bare_id_as_its_caller() {
    bare_id_callers(&app_files()).assert_none("use cases taking a bare id as caller");
}

#[cfg_attr(test, test)]
pub(crate) fn only_acting_builds_a_proof_of_who_acts() {
    proofs_built_outside_acting(&app_files()).assert_none("proofs built outside acting");
}

#[cfg_attr(test, test)]
pub(crate) fn only_the_run_driver_makes_a_run_caller() {
    run_callers_made_elsewhere(&app_files()).assert_none("run callers made outside the run driver");
}

#[cfg_attr(test, test)]
pub(crate) fn use_cases_ask_acting_through_its_traits() {
    resolvers_named_by_use_cases(&app_files()).assert_none("use cases naming a resolver");
}

#[cfg_attr(test, test)]
pub(crate) fn assumed_proofs_stay_in_tests() {
    assumed_outside_tests(&app_files()).assert_none("assumed proofs outside tests");
}

#[cfg_attr(test, test)]
pub(crate) fn no_use_case_checks_a_permission_by_hand() {
    hand_written_checks(&app_files()).assert_none("permissions checked by hand");
}

#[cfg_attr(test, test)]
pub(crate) fn nothing_asks_the_old_authorizer() {
    authorizer_users(&app_files()).assert_none("users of the Authorizer port");
}

#[cfg_attr(test, test)]
pub(crate) fn ports_take_typed_values() {
    untyped_ports(&app_files()).assert_none("untyped ports");
}

#[cfg_attr(test, test)]
pub(crate) fn ports_own_the_types_they_carry() {
    ports_reaching_into_use_cases(&app_files()).assert_none("ports reaching into use cases");
}

/// Each check, run over a file that breaks it on purpose, finds the break.
/// So a check that stops looking fails here instead of passing everything.
#[cfg_attr(test, test)]
pub(crate) fn every_check_finds_its_planted_break() {
    let planted = SourceFile::planted("use_cases/planted.rs", PLANTED);
    let ports = SourceFile::planted(
        "ports/planted.rs",
        "use crate::use_cases::x::Wire;\nasync fn find(&self, id: &Uuid);",
    );
    let files = [planted, ports];
    let checks: [(&str, Check); 10] = [
        ("two use cases", files_with_two_use_cases),
        ("bare id caller", bare_id_callers),
        ("proof outside acting", proofs_built_outside_acting),
        ("run caller made elsewhere", run_callers_made_elsewhere),
        ("resolver named", resolvers_named_by_use_cases),
        ("assumed outside tests", assumed_outside_tests),
        ("hand-written check", hand_written_checks),
        ("authorizer", authorizer_users),
        ("port into use case", ports_reaching_into_use_cases),
        ("untyped port", untyped_ports),
    ];
    let missed: Vec<&str> = checks
        .iter()
        .filter(|(_, check)| check(&files).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "checks that missed their planted break: {missed:?}"
    );
}

/// A file breaking every rule a use case file keeps.
const PLANTED: &str = r"
struct One;
struct Two;
impl Command for One {
    type Caller = UserId;
    type Input = ();
    type Output = ();
}
impl Query for Two {
    type Caller = OrgUserId;
    type Input = ();
    type Output = ();
}
fn build(access: &TenantAccess, authorizer: &dyn Authorizer, acting: &TenantActing) {
    let authority = access.authority_of(&user, &signed_in, now);
    let fake = TenantAuthority::assumed(who, tenant, &[], &[]);
    let held = permissions.contains(&SystemPermission::ManageUsers);
    let borrowed = Credential::WorkflowRun(someone_elses_run);
}
";
