//! Plan limits: paths that create the same thing and disagree on its limit.
//!
//! A use case that checks a plan limit for a `ResourceKind` and calls a
//! creator of one aggregate says that the limit guards that aggregate. One
//! that creates several aggregates says so only of the one whose name ends
//! in the kind's singular, `Group` for `Groups`, when exactly one does;
//! otherwise it is no example. Another use case that calls a creator of
//! the same aggregate (the same creator or another, such as an import, a
//! clone, a directory sync, a first sign-in through a federation or an
//! accepted invitation) and checks no limit for that kind lets a tenant
//! pass it. That use case is reported, with the checking one as the
//! example.
//!
//! A use case that does check the kind is also asked of its flow (see
//! [`crate::model::facts::flow`]): when some path calls the creator and
//! then stores what it made, or succeeds, without passing the check (the
//! check in one branch only, or after the save), it is reported too.
//!
//! A finding must be true, so a use case whose card lists anything not
//! read is not reported for a missing check, since the check may sit in
//! what was not read, and a path through a not-read point answers neither
//! way: both are counted as unsaid instead.

use std::collections::{BTreeMap, BTreeSet};

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::facts::flow::{Answer, Step, StepPicks, creates, is_store_write, kept_unchecked};
use crate::model::facts::{ChangeCall, Facts, LimitCheck, UseCaseFacts};
use crate::source::Place;

/// How many more checking use cases a finding names after its example.
const OTHERS_SHOWN: usize = 3;

/// A use case checking a limit for an aggregate it creates.
struct Example<'f> {
    use_case: &'f UseCaseFacts,
    limit: &'f LimitCheck,
    creates: &'f ChangeCall,
}

/// Every limit finding.
pub(crate) fn run(facts: &Facts) -> Found {
    let owners = owners(facts);
    let guarded = guarded(facts, &owners);
    let mut found = Found::default();
    for use_case in &facts.use_cases {
        skipped_checks(use_case, &owners, &mut found);
        for creation in creations(use_case) {
            let kinds = guarded
                .iter()
                .filter(|((owner, _), _)| *owner == creation.owner);
            for ((_, kind), examples) in kinds {
                let unlimited = Unlimited {
                    use_case,
                    creation,
                    kind,
                };
                judge(&unlimited, examples, &mut found);
            }
        }
    }
    found
}

/// Reports `unlimited` when others check the limit and it does not;
/// counts it when the check may sit in what was not read.
fn judge(unlimited: &Unlimited<'_>, examples: &[Example<'_>], found: &mut Found) {
    let (use_case, creation, kind) = (unlimited.use_case, unlimited.creation, unlimited.kind);
    if examples.is_empty() || checks(use_case, kind) {
        return;
    }
    if let Some(unread) = use_case.not_read.first() {
        found.leave_unsaid(Unsaid::new(
            Check::MissingLimitPath,
            unguarded(use_case, creation, kind),
            unread.place.clone(),
            format!("the check may sit in what was not read: {}", unread.what),
        ));
        return;
    }
    found.findings.extend(finding(unlimited, examples));
}

/// Reports each limit `use_case` checks for an aggregate it creates when
/// a path through no not-read point calls the creator and then stores what
/// it made, or succeeds, without passing the check; a value made in memory
/// before a check that comes before the store is fine. Counts it when a
/// path that might is not read.
fn skipped_checks(use_case: &UseCaseFacts, owners: &BTreeSet<&str>, found: &mut Found) {
    let created = creations(use_case);
    let mut kinds: Vec<&LimitCheck> = Vec::new();
    for limit in &use_case.limits {
        if !kinds.iter().any(|seen| seen.kind == limit.kind) {
            kinds.push(limit);
        }
    }
    for limit in kinds {
        let Some(creation) = guarded_by(&created, &limit.kind, owners) else {
            continue;
        };
        let picks = StepPicks {
            checked: |step: &Step| matches!(step, Step::Limit { kind } if *kind == limit.kind),
            made: |step: &Step| creates(step, &creation.owner, &creation.name),
            kept: is_store_write,
        };
        let answer = kept_unchecked(&use_case.flow, picks, &use_case.end);
        match answer {
            Answer::No => {}
            Answer::Unknown(unread) => found.leave_unsaid(Unsaid::new(
                Check::MissingLimitPath,
                format!("{} on a path", unguarded(use_case, creation, &limit.kind)),
                unread.place,
                unread.what,
            )),
            Answer::Yes(places) => found
                .findings
                .push(skipped(use_case, creation, limit, &places)),
        }
    }
}

/// What a limit finding is about: `Owner::create in context::UseCase
/// (Kind)`.
fn unguarded(use_case: &UseCaseFacts, creation: &ChangeCall, kind: &str) -> String {
    format!(
        "{} in {}::{} ({kind})",
        creation.subject(),
        use_case.context,
        use_case.name
    )
}

fn skipped(
    use_case: &UseCaseFacts,
    creation: &ChangeCall,
    limit: &LimitCheck,
    reached: &[Place],
) -> Finding {
    let kind = &limit.kind;
    let message = format!(
        "`{}` ({}) checks the `{kind}` limit, but a path calls `{}` and stores it or succeeds without passing the check",
        use_case.name,
        use_case.context,
        creation.subject()
    );
    let at = reached
        .first()
        .cloned()
        .unwrap_or_else(|| creation.place.clone());
    Finding::new(
        Check::MissingLimitPath,
        at,
        format!("{} on a path", unguarded(use_case, creation, kind)),
        message,
    )
    .with_detail(skipped_detail(use_case, creation, limit, reached))
}

/// Where the path calls `creation` and keeps it unchecked, beside where
/// `use_case` checks `limit` on its other paths.
fn skipped_detail(
    use_case: &UseCaseFacts,
    creation: &ChangeCall,
    limit: &LimitCheck,
    reached: &[Place],
) -> Vec<String> {
    let kind = &limit.kind;
    let mut detail = Vec::new();
    if let Some(made) = reached.first() {
        detail.push(format!(
            "unchecked: {}  a path calls {} with no {kind} check before",
            location(made),
            creation.subject()
        ));
    }
    if let Some(kept) = reached.get(1) {
        detail.push(format!(
            "kept:      {}  and stores it or hands back success here, still unchecked",
            location(kept)
        ));
    }
    detail.push(format!(
        "check:     {}  {} checks ResourceKind::{kind} by {}{}",
        location(&limit.place),
        use_case.name,
        limit.call,
        via(limit.via.as_deref())
    ));
    detail.push(format!(
        "why: a check on some paths only lets the others pass the plan's {kind} limit"
    ));
    detail.push(format!(
        "fix: check ResourceKind::{kind} on every path before the {} it makes is stored, at the top of `execute` or before the branch",
        creation.owner
    ));
    detail
}

/// For each aggregate and limit kind, the use cases that check the kind
/// and create that aggregate: the examples. A use case creating several
/// aggregates is an example only for the one its kind names, such as
/// `Group` for `Groups` beside a `GroupMembership`, when exactly one does.
fn guarded<'f>(
    facts: &'f Facts,
    owners: &BTreeSet<&str>,
) -> BTreeMap<(&'f str, &'f str), Vec<Example<'f>>> {
    let mut guarded: BTreeMap<(&str, &str), Vec<Example<'_>>> = BTreeMap::new();
    for use_case in &facts.use_cases {
        let created = creations(use_case);
        for limit in &use_case.limits {
            let Some(creates) = guarded_by(&created, &limit.kind, owners) else {
                continue;
            };
            let examples = guarded
                .entry((creates.owner.as_str(), limit.kind.as_str()))
                .or_default();
            if !examples
                .iter()
                .any(|seen| seen.use_case.place == use_case.place)
            {
                examples.push(Example {
                    use_case,
                    limit,
                    creates,
                });
            }
        }
    }
    guarded
}

/// The aggregate among `created` the limit `kind` guards: the only one
/// whose name ends in the kind's singular, `User` for `Users`; or, when no
/// aggregate of the domain, among `owners`, is named after the kind, the
/// only one created, when its name shares a word with the kind, as
/// `ApprovalRequest` does with `PendingApprovals`.
fn guarded_by<'f>(
    created: &[&'f ChangeCall],
    kind: &str,
    owners: &BTreeSet<&str>,
) -> Option<&'f ChangeCall> {
    let singular = singular(kind);
    let named_after = |owner: &str| owner.to_lowercase().ends_with(&singular);
    let named: Vec<&&ChangeCall> = created
        .iter()
        .filter(|creation| named_after(&creation.owner))
        .collect();
    if let [only] = named.as_slice() {
        return Some(only);
    }
    if owners.iter().any(|owner| named_after(owner)) {
        return None;
    }
    match created {
        [only] if shares_a_word(&only.owner, kind) => Some(only),
        _ => None,
    }
}

/// Whether the names `owner` and `kind` share a word, each word read
/// without its plural ending.
fn shares_a_word(owner: &str, kind: &str) -> bool {
    let kind_words = words(kind);
    words(owner).iter().any(|word| kind_words.contains(word))
}

/// The words of a `CamelCase` name in lower case, singular.
fn words(name: &str) -> BTreeSet<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for letter in name.chars() {
        if letter.is_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(letter);
    }
    words.push(current);
    words.iter().map(|word| singular(word)).collect()
}

/// Every type the domain offers a creator or change of.
fn owners(facts: &Facts) -> BTreeSet<&str> {
    facts
        .changes
        .iter()
        .map(|change| change.owner.as_str())
        .collect()
}

/// `kind` in lower case without its plural ending: `policy` for
/// `EgressPolicies`, `user` for `Users`.
fn singular(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if let Some(stem) = lower.strip_suffix("ies") {
        return format!("{stem}y");
    }
    lower.strip_suffix('s').unwrap_or(&lower).to_owned()
}

/// The first creator `use_case` calls of each aggregate.
fn creations(use_case: &UseCaseFacts) -> Vec<&ChangeCall> {
    let mut seen = BTreeSet::new();
    use_case
        .changes
        .iter()
        .filter(|change| change.kind == "create")
        .filter(|change| seen.insert(change.owner.as_str()))
        .collect()
}

/// Whether `use_case` checks the limit for `kind`.
fn checks(use_case: &UseCaseFacts, kind: &str) -> bool {
    use_case.limits.iter().any(|limit| limit.kind == kind)
}

/// A creation a use case makes with no check of a limit others check
/// before it: the use case, the creation, and the limit's kind.
struct Unlimited<'f> {
    use_case: &'f UseCaseFacts,
    creation: &'f ChangeCall,
    kind: &'f str,
}

/// The finding for `unlimited`, shown against the first of `examples`,
/// the use cases that check the limit; none when there are none.
fn finding(unlimited: &Unlimited<'_>, examples: &[Example<'_>]) -> Option<Finding> {
    let (example, others) = examples.split_first()?;
    let (use_case, creation, kind) = (unlimited.use_case, unlimited.creation, unlimited.kind);
    let owner = &creation.owner;
    let message = format!(
        "`{}` ({}) calls `{}` with no plan limit check for `{kind}`, while `{}` ({}) checks `{kind}` before it creates a `{owner}`",
        use_case.name,
        use_case.context,
        creation.subject(),
        example.use_case.name,
        example.use_case.context,
    );
    let mut detail = compared(unlimited, example);
    detail.extend(also_checked(others));
    detail.push(format!(
        "why: a plan limit holds only if every path that adds what it counts checks it; this path lets a tenant pass its plan's {kind} limit"
    ));
    detail.push(format!(
        "fix: check ResourceKind::{kind} before the create, as {} does by {}, or allow this path with the reason it needs no check",
        example.use_case.name, example.limit.call
    ));
    let finding = Finding::new(
        Check::MissingLimitPath,
        creation.place.clone(),
        unguarded(use_case, creation, kind),
        message,
    );
    Some(finding.with_detail(detail))
}

/// Where `unlimited` creates without the check, beside where `example`
/// checks before it creates.
fn compared(unlimited: &Unlimited<'_>, example: &Example<'_>) -> Vec<String> {
    let (use_case, creation, kind) = (unlimited.use_case, unlimited.creation, unlimited.kind);
    vec![
        format!(
            "unchecked: {}  {} calls {}{}",
            location(&creation.place),
            use_case.name,
            creation.subject(),
            via(creation.via.as_deref())
        ),
        format!(
            "checked:   {}  {} checks ResourceKind::{kind} by {}{}",
            location(&example.limit.place),
            example.use_case.name,
            example.limit.call,
            via(example.limit.via.as_deref())
        ),
        format!(
            "           {}  {} calls {}{}",
            location(&example.creates.place),
            example.use_case.name,
            example.creates.subject(),
            via(example.creates.via.as_deref())
        ),
    ]
}

/// The line naming the other use cases that check the limit, the first
/// few shown; none when there are none.
fn also_checked(others: &[Example<'_>]) -> Option<String> {
    let shown: Vec<String> = others
        .iter()
        .take(OTHERS_SHOWN)
        .map(|other| {
            format!(
                "{} ({}) at {}",
                other.use_case.name,
                other.use_case.context,
                location(&other.limit.place)
            )
        })
        .collect();
    if shown.is_empty() {
        return None;
    }
    let tail = match others.len().saturating_sub(OTHERS_SHOWN) {
        0 => String::new(),
        more => format!(" and {more} more"),
    };
    Some(format!("also checked by {}{tail}", shown.join(", ")))
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

fn via(through: Option<&str>) -> String {
    through.map_or_else(String::new, |through| format!(" via {through}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::facts::planted::model;
    use crate::source::planted::{app, domain, workspace};

    const USER: &str = r"
        pub struct User { id: UserId }
        impl User {
            pub fn create(params: NewUser, by: &TenantAuthority) -> Result<Self, DomainError> { make() }
            pub fn imported(params: ImportedUser, by: &TenantAuthority) -> Result<Self, DomainError> { make() }
            pub fn reconstitute(row: UserRow) -> Result<Self, DomainError> { make() }
        }
    ";

    const PORTS: &str = r"
        pub trait LimitEnforcer: Send + Sync {
            async fn check_tenant_limit(&self, kind: ResourceKind) -> Result<(), DomainError>;
        }
        pub trait UserStore { async fn save(&self, user: &User) -> Result<(), DomainError>; }
    ";

    const CREATE: &str = r"
        pub struct CreatePorts {
            pub limits: Arc<dyn LimitEnforcer>,
            pub users: Arc<dyn UserStore>,
        }
        pub struct CreateUseCase { ports: CreatePorts }
        impl Command for CreateUseCase {
            async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, input: NewUser) -> Result<(), AppError> {
                self.ports.limits.check_tenant_limit(ResourceKind::Users).await.or_internal()?;
                let user = User::create(input, &authority).map_err(AppError::from_domain)?;
                self.ports.users.save(&user).await.or_internal()
            }
        }
    ";

    /// An import that creates users through another creator, with `body`
    /// as its `execute`.
    fn import(body: &str) -> String {
        format!(
            "pub struct ImportPorts {{
                 pub limits: Arc<dyn LimitEnforcer>,
                 pub users: Arc<dyn UserStore>,
             }}
             pub struct ImportUseCase {{ ports: ImportPorts }}
             impl Command for ImportUseCase {{
                 async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, input: ImportedUser) -> Result<(), AppError> {{
                     {body}
                 }}
             }}"
        )
    }

    fn found(import_body: &str) -> Found {
        let ws = workspace(vec![
            domain("domains/identity/user.rs", USER),
            app("ports/identity.rs", PORTS),
            app("use_cases/identity/users/create.rs", CREATE),
            app("use_cases/identity/imports/run.rs", &import(import_body)),
        ]);
        run(&Facts::build(&ws, &model(&ws)))
    }

    #[test]
    fn a_path_creating_what_another_guards_without_the_check_is_reported() {
        let found = found(
            "let user = User::imported(input, &authority).map_err(AppError::from_domain)?;
             self.ports.users.save(&user).await.or_internal()",
        );

        let finding = &found.findings[0];
        assert_eq!(
            finding.subject,
            "User::imported in identity::ImportUseCase (Users)"
        );
        assert_eq!(
            finding.message,
            "`ImportUseCase` (identity) calls `User::imported` with no plan limit check for `Users`, while `CreateUseCase` (identity) checks `Users` before it creates a `User`"
        );
        assert!(
            finding.detail[0]
                .starts_with("unchecked: crates/ianua-app/src/use_cases/identity/imports/run.rs:")
        );
        assert!(
            finding.detail[1]
                .starts_with("checked:   crates/ianua-app/src/use_cases/identity/users/create.rs:")
        );
        assert!(finding.detail.iter().any(|line| line.starts_with("fix: ")));
    }

    #[test]
    fn a_path_that_checks_the_same_limit_stays_quiet() {
        let found = found(
            "self.ports.limits.check_tenant_limit(ResourceKind::Users).await.or_internal()?;
             let user = User::imported(input, &authority).map_err(AppError::from_domain)?;
             self.ports.users.save(&user).await.or_internal()",
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    /// The kind is bound to a name first, then handed to the check: it is
    /// read all the same.
    #[test]
    fn a_limit_bound_to_a_name_before_the_check_counts() {
        let found = found(
            "let kind = ResourceKind::Users;
             self.ports.limits.check_tenant_limit(kind).await.or_internal()?;
             User::imported(input, &authority).map_err(AppError::from_domain)?;
             Ok(())",
        );

        assert!(found.findings.is_empty());
    }

    /// The import checks a limit whose kind it works out at run time: the
    /// reader cannot say it is not `Users`, so it stays quiet and counts.
    #[test]
    fn a_limit_the_reader_did_not_read_keeps_it_quiet_and_is_counted() {
        let found = found(
            "let kind = match input.source { Source::Directory => ResourceKind::Users, _ => ResourceKind::Users };
             self.ports.limits.check_tenant_limit(kind).await.or_internal()?;
             User::imported(input, &authority).map_err(AppError::from_domain)?;
             Ok(())",
        );

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::MissingLimitPath), Some(&1));
    }

    const CHECK: &str =
        "self.ports.limits.check_tenant_limit(ResourceKind::Users).await.or_internal()?;";

    const IMPORTED: &str = "User::imported(input, &authority).map_err(AppError::from_domain)?;";

    fn on_a_path(found: &Found) -> Vec<&Finding> {
        found
            .findings
            .iter()
            .filter(|finding| finding.subject.ends_with("on a path"))
            .collect()
    }

    #[test]
    fn a_check_in_one_branch_only_leaves_a_path_to_the_create() {
        let found = found(&format!("if input.urgent {{ {CHECK} }} {IMPORTED} Ok(())"));

        let finding = on_a_path(&found)[0];
        assert_eq!(
            finding.message,
            "`ImportUseCase` (identity) checks the `Users` limit, but a path calls `User::imported` and stores it or succeeds without passing the check"
        );
    }

    /// The user is made in memory first, checked, then saved: every path
    /// that keeps it passed the check.
    #[test]
    fn a_value_made_before_its_check_and_saved_after_stays_quiet() {
        let found = found(&format!(
            "let user = User::imported(input, &authority).map_err(AppError::from_domain)?;
             {CHECK}
             self.ports.users.save(&user).await.or_internal()"
        ));

        assert!(on_a_path(&found).is_empty());
        assert!(found.silenced.is_empty());
    }

    #[test]
    fn a_check_before_the_create_on_every_path_stays_quiet() {
        let found = found(&format!("{CHECK} if input.urgent {{ {IMPORTED} }} Ok(())"));

        assert!(on_a_path(&found).is_empty());
        assert!(found.silenced.is_empty());
    }

    #[test]
    fn an_early_return_before_the_check_counts_only_when_it_reaches_the_create() {
        let leaves = found(&format!(
            "if input.skip {{ return Ok(()); }} {CHECK} {IMPORTED} Ok(())"
        ));
        let creates_first = found(&format!(
            "if input.skip {{ {IMPORTED} return Ok(()); }} {CHECK} {IMPORTED} Ok(())"
        ));

        assert!(on_a_path(&leaves).is_empty());
        assert_eq!(on_a_path(&creates_first).len(), 1);
    }

    #[test]
    fn a_not_read_point_on_the_way_keeps_the_path_question_quiet() {
        let found = found(&format!(
            "if input.urgent {{ {CHECK} }} else {{ external::prepare(&self.ports).await?; }} {IMPORTED} Ok(())"
        ));

        assert!(on_a_path(&found).is_empty());
        assert!(found.silenced.contains_key(&Check::MissingLimitPath));
    }

    #[test]
    fn a_kind_names_the_aggregate_it_guards_among_several() {
        let created = |owner: &str| ChangeCall {
            owner: owner.to_owned(),
            name: "create".to_owned(),
            kind: "create",
            place: Place {
                file: "a.rs".to_owned(),
                line: 1,
            },
            via: None,
            takes: Vec::new(),
            rights: Vec::new(),
            events: Vec::new(),
        };
        let group = created("Group");
        let membership = created("GroupMembership");
        let policy = created("EgressPolicy");
        let owners = BTreeSet::from(["Group", "GroupMembership", "EgressPolicy", "User"]);

        let together = [&group, &membership, &policy];

        assert_eq!(
            guarded_by(&together, "Groups", &owners).map(|found| found.owner.as_str()),
            Some("Group")
        );
        assert_eq!(
            guarded_by(&together, "EgressPolicies", &owners).map(|found| found.owner.as_str()),
            Some("EgressPolicy")
        );
        assert!(guarded_by(&together, "Users", &owners).is_none());
    }

    /// An import checks the `Users` limit and, as far as the reader sees,
    /// creates only role assignments. The domain has a `User`: the limit
    /// guards that, not the assignments. With no `Approval` in the domain,
    /// `PendingApprovals` guards the lone creation only when the names
    /// share a word.
    #[test]
    fn a_lone_creation_is_not_guarded_by_a_kind_named_after_another_aggregate() {
        let assignment = ChangeCall {
            owner: "RoleAssignment".to_owned(),
            name: "by_default".to_owned(),
            kind: "create",
            place: Place {
                file: "a.rs".to_owned(),
                line: 1,
            },
            via: None,
            takes: Vec::new(),
            rights: Vec::new(),
            events: Vec::new(),
        };
        let with_user = BTreeSet::from(["RoleAssignment", "User"]);
        let without = BTreeSet::from(["RoleAssignment"]);

        assert!(guarded_by(&[&assignment], "Users", &with_user).is_none());
        assert!(guarded_by(&[&assignment], "PendingApprovals", &without).is_none());
        assert!(guarded_by(&[&assignment], "Roles", &without).is_some());
    }

    /// A call the reader cannot follow is handed the ports; the check may
    /// sit there.
    #[test]
    fn a_call_handed_the_ports_the_reader_does_not_follow_keeps_it_quiet() {
        let found = found(
            "external::prepare(&self.ports).await?;
             User::imported(input, &authority).map_err(AppError::from_domain)?;
             Ok(())",
        );

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::MissingLimitPath), Some(&1));
    }
}
