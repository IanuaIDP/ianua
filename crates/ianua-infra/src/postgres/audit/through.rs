//! Whom or what an audit record's actor acted through, read back from the
//! word kept for it and the ids kept beside it.

use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OperatorId, SupportImpersonationId, UserId, WorkflowExecutionId};
use uuid::Uuid;

/// What a record keeps of whom its actor acted through.
pub(crate) struct KeptThrough<'a> {
    /// `directly`, `impersonation`, `support_impersonation` or
    /// `workflow_run`.
    pub(crate) word: &'a str,
    /// The operator impersonating.
    pub(crate) operator: Option<Uuid>,
    /// The administrator acting as someone in support.
    pub(crate) admin: Option<Uuid>,
    /// The person acted as.
    pub(crate) as_user: Option<Uuid>,
    /// The support impersonation.
    pub(crate) impersonation: Option<Uuid>,
    /// The workflow run.
    pub(crate) execution: Option<Uuid>,
}

impl KeptThrough<'_> {
    /// The stored identities in the order checked for each attribution kind.
    fn parties(&self) -> [Option<Uuid>; 5] {
        [
            self.operator,
            self.admin,
            self.as_user,
            self.impersonation,
            self.execution,
        ]
    }

    /// Whom the actor acted through, the ids each kind names and no others.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` naming `record` when the word
    /// is unknown or the ids kept do not match it.
    pub(crate) fn read(&self, record: &'static str) -> Result<ActedThrough, DomainError> {
        match (self.word, self.parties()) {
            ("directly", [None, None, None, None, None]) => Ok(ActedThrough::Directly),
            ("impersonation", [Some(operator), None, Some(as_user), None, None]) => {
                Ok(ActedThrough::Impersonation {
                    operator_id: OperatorId::from_uuid(operator),
                    as_user: UserId::from_uuid(as_user),
                })
            }
            (
                "support_impersonation",
                [None, Some(admin), Some(as_user), Some(impersonation), None],
            ) => Ok(ActedThrough::SupportImpersonation {
                admin: UserId::from_uuid(admin),
                as_user: UserId::from_uuid(as_user),
                impersonation: SupportImpersonationId::from_uuid(impersonation),
            }),
            ("workflow_run", [None, None, None, None, Some(execution)]) => {
                Ok(ActedThrough::WorkflowRun {
                    execution: WorkflowExecutionId::from_uuid(execution),
                })
            }
            _ => Err(DomainError::corrupt_row(
                record,
                "who it acted through does not match the ids kept",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(word: &str, execution: Option<Uuid>) -> KeptThrough<'_> {
        KeptThrough {
            word,
            operator: None,
            admin: None,
            as_user: None,
            impersonation: None,
            execution,
        }
    }

    /// A record a run made reads back as made through that run.
    #[test]
    fn a_run_s_record_names_its_run() {
        let run = Uuid::now_v7();

        let through = kept("workflow_run", Some(run))
            .read("audit record")
            .unwrap();

        assert_eq!(
            through,
            ActedThrough::WorkflowRun {
                execution: WorkflowExecutionId::from_uuid(run)
            }
        );
    }

    /// Reading rejects a direct actor with a run ID, a workflow actor without
    /// one, and an unknown way of acting.
    #[test]
    fn a_run_that_does_not_match_its_word_is_refused() {
        let run = Uuid::now_v7();

        assert!(kept("directly", Some(run)).read("audit record").is_err());
        assert!(kept("workflow_run", None).read("audit record").is_err());
        assert!(kept("something_else", None).read("audit record").is_err());
    }
}
