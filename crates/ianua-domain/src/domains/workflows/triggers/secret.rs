//! The secret a workflow's webhook is called with, so that only those
//! given it start runs from outside.
//!
//! A webhook run acts for the person who published the version in service.
//! Anyone who learnt the webhook's address could otherwise start runs with
//! that person's authority. So a call starts a run only with the secret,
//! checked in constant time against the digest kept here. The secret
//! itself is shown once, to the person who issued it, and never kept.
//!
//! A secret starts a version only when the person who issued it, or last
//! replaced it, published that version. Sam may edit workflows. Without
//! this, he issues a secret for Ann's webhook workflow and starts runs
//! acting for Ann whenever he likes. When someone else publishes the next
//! version, they issue a new secret, and so take on what it starts.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::workflow::{Publication, Workflow, WorkflowStatus};
use crate::domains::workflows::events::{
    TriggerSecretRef, WorkflowTriggerSecretIssued, WorkflowTriggerSecretRevoked,
    WorkflowTriggerSecretRotated,
};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{EventLabel, Human, TokenHash, WorkflowId, WorkflowTriggerId};

/// A call of a workflow's webhook, made with its secret.
///
/// Only [`WorkflowTriggerSecret::admit`] makes one, once the secret matched.
/// A webhook starts a run only with one, through
/// [`WorkflowExecution::start_on_webhook`](crate::domains::workflows::execution::WorkflowExecution::start_on_webhook).
#[derive(Debug)]
pub struct WebhookCall {
    workflow_id: WorkflowId,
    version: u32,
}

impl WebhookCall {
    /// Whether it was admitted for `workflow`, this very version. Asking
    /// spends it, so one call starts one run.
    pub(crate) fn admits<T: TenantScope>(self, workflow: &Workflow<T>) -> bool {
        self.workflow_id == *workflow.id() && self.version == workflow.version()
    }
}

/// A workflow's webhook secret, as stored.
pub struct WorkflowTriggerSecretRow {
    /// Its id, which the webhook's address names.
    pub id: WorkflowTriggerId,
    /// The workflow it starts.
    pub workflow_id: WorkflowId,
    /// The digest of the secret.
    pub secret_hash: TokenHash,
    /// The person who issued it, or last replaced it.
    pub issued_by: Human,
    /// When it was first issued.
    pub created_at: OffsetDateTime,
    /// When the secret was last set.
    pub secret_changed_at: OffsetDateTime,
}

/// The secret one workflow's webhook is called with. Storage keeps one per
/// workflow.
#[derive(Debug)]
pub struct WorkflowTriggerSecret<T: TenantScope> {
    id: WorkflowTriggerId,
    workflow_id: WorkflowId,
    secret_hash: TokenHash,
    issued_by: Human,
    created_at: OffsetDateTime,
    secret_changed_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> WorkflowTriggerSecret<T> {
    /// `by` issues a secret for `workflow`'s webhook, the one hashing to
    /// `secret_hash`. The caller shows the secret to `by` once. Raises
    /// `workflows.trigger_secret_issued`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Validation`] when `workflow` does not start on its
    ///   webhook.
    pub fn issue(
        workflow: &Workflow<T>,
        secret_hash: TokenHash,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        if *workflow.trigger() != Trigger::Webhook {
            return Err(DomainError::invalid(message!(
                "workflows-only-a-workflow-that-starts-on",
                "only a workflow that starts on its webhook has a webhook secret"
            )));
        }
        let now = crate::shared::clock::now();
        let mut secret = Self {
            id: WorkflowTriggerId::new(),
            workflow_id: *workflow.id(),
            secret_hash,
            issued_by: by.by().clone(),
            created_at: now,
            secret_changed_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        let issued = secret.secret_ref(workflow, by.by());
        secret.raised.raise(WorkflowTriggerSecretIssued {
            secret: issued,
            occurred_at: now,
        });
        Ok(secret)
    }

    /// Rebuilds a secret from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row's secret was set
    ///   before it was first issued.
    pub fn reconstitute(row: WorkflowTriggerSecretRow) -> Result<Self, DomainError> {
        RowCheck::of("workflow trigger secret")
            .in_order(
                row.created_at,
                row.secret_changed_at,
                "secret set before it was first issued",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            workflow_id: row.workflow_id,
            secret_hash: row.secret_hash,
            issued_by: row.issued_by,
            created_at: row.created_at,
            secret_changed_at: row.secret_changed_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// `by` replaces the secret with the one hashing to `secret_hash`. A
    /// call with the old one starts nothing more, and the new one starts
    /// only the versions `by` publishes.
    ///
    /// Ann's automation server leaked its configuration. Without this, the
    /// only way to shut the leaked secret out is to stop the webhook.
    /// Raises `workflows.trigger_secret_rotated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] when `workflow` is not the workflow this
    ///   secret starts.
    pub fn rotate(
        &mut self,
        workflow: &Workflow<T>,
        secret_hash: TokenHash,
        by: &WorkflowControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_starts(workflow)?;
        self.secret_hash = secret_hash;
        self.issued_by = by.by().clone();
        self.secret_changed_at = crate::shared::clock::now();
        self.raised.raise(WorkflowTriggerSecretRotated {
            secret: self.secret_ref(workflow, by.by()),
            occurred_at: self.secret_changed_at,
        });
        Ok(())
    }

    /// `by` revokes the secret. Raises `workflows.trigger_secret_revoked`;
    /// the caller deletes it, and the webhook starts nothing until a new
    /// one is issued.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit workflows.
    /// - [`DomainError::Conflict`] when `workflow` is not the workflow this
    ///   secret starts.
    pub fn revoke(
        &mut self,
        workflow: &Workflow<T>,
        by: &WorkflowControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Update)?;
        self.ensure_starts(workflow)?;
        self.raised.raise(WorkflowTriggerSecretRevoked {
            secret: self.secret_ref(workflow, by.by()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// The call of `workflow`'s webhook made with the secret hashing to
    /// `presented`.
    ///
    /// The digests are compared in constant time, as every [`TokenHash`]
    /// is, and before anything else, so a caller without the secret learns
    /// nothing about the workflow.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `presented` is not this secret.
    /// - [`DomainError::Forbidden`] when `workflow` is not the workflow it
    ///   starts.
    /// - [`DomainError::Conflict`] when `workflow` is not a version in
    ///   service that starts on its webhook.
    /// - [`DomainError::Forbidden`] when the version was published by
    ///   someone other than the person who issued the secret.
    pub fn admit(
        &self,
        presented: &TokenHash,
        workflow: &Workflow<T>,
    ) -> Result<WebhookCall, DomainError> {
        if *presented != self.secret_hash {
            return Err(DomainError::forbidden(message!(
                "workflows-the-webhook-s-secret-is-wrong",
                "the webhook's secret is wrong"
            )));
        }
        if *workflow.id() != self.workflow_id {
            return Err(DomainError::forbidden(message!(
                "workflows-this-secret-starts-another-workflow",
                "this secret starts another workflow"
            )));
        }
        let publisher = in_service_on_webhook(workflow)?;
        if !publisher.is_same_person_as(&self.issued_by) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-secret-was-issued-by-someone",
                "the secret was issued by someone other than the version's publisher, who issues a new one"
            )));
        }
        Ok(WebhookCall {
            workflow_id: self.workflow_id,
            version: workflow.version(),
        })
    }

    /// Refuses `workflow` unless it is the one this secret starts.
    fn ensure_starts(&self, workflow: &Workflow<T>) -> Result<(), DomainError> {
        if *workflow.id() == self.workflow_id {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-this-secret-starts-another-workflow",
            "this secret starts another workflow"
        )))
    }

    /// This secret as the audit trail names it, changed by `by`.
    fn secret_ref(&self, workflow: &Workflow<T>, by: &Human) -> TriggerSecretRef {
        TriggerSecretRef {
            trigger_id: self.id,
            workflow_id: self.workflow_id,
            label: EventLabel::of(workflow.name().as_str()),
            by: by.principal(),
        }
    }

    /// Its id, which the webhook's address names.
    #[must_use]
    pub fn id(&self) -> &WorkflowTriggerId {
        &self.id
    }

    /// The workflow it starts.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// The digest of the secret, for storage.
    #[must_use]
    pub fn secret_hash(&self) -> &TokenHash {
        &self.secret_hash
    }

    /// The person who issued it, or last replaced it. It starts only the
    /// versions they publish.
    #[must_use]
    pub fn issued_by(&self) -> &Human {
        &self.issued_by
    }

    /// When the secret was last set.
    #[must_use]
    pub fn secret_changed_at(&self) -> OffsetDateTime {
        self.secret_changed_at
    }
}

impl<T: TenantScope> Raises for WorkflowTriggerSecret<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for WorkflowTriggerSecret<T> {
    type Id = WorkflowTriggerId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.secret_changed_at
    }
}

/// The person who published `workflow`, when it is the version in service
/// and starts on its webhook.
fn in_service_on_webhook<T: TenantScope>(workflow: &Workflow<T>) -> Result<&Human, DomainError> {
    let on_webhook = *workflow.trigger() == Trigger::Webhook;
    let Publication::PublishedBy(publisher) = workflow.publication() else {
        return Err(DomainError::conflict(message!(
            "workflows-the-workflow-was-never-published",
            "the workflow was never published"
        )));
    };
    if workflow.status() != WorkflowStatus::Published || !on_webhook {
        return Err(DomainError::conflict(message!(
            "workflows-no-version-in-service-starts-on",
            "no version in service starts on its webhook"
        )));
    }
    Ok(publisher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::tests::fixtures::{
        SeesAll, ann, bob, draft_with, holding_only, managing, publish_as, transform, viewing,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;

    /// A secret's digest, as the token hasher made it.
    fn digest(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    /// Ann's workflow that starts on its webhook, still a draft.
    fn hooked_draft() -> Workflow<ResolvedTenant> {
        draft_with(
            vec![transform("tidy", Join::All)],
            Vec::new(),
            Trigger::Webhook,
        )
    }

    /// Ann's webhook workflow, published by Ann.
    fn hooked() -> Workflow<ResolvedTenant> {
        let mut workflow = hooked_draft();
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        workflow
    }

    /// The secret `by` issued for `workflow`, hashing to "s3cret".
    fn issued_by(
        workflow: &Workflow<ResolvedTenant>,
        by: &Human,
    ) -> WorkflowTriggerSecret<ResolvedTenant> {
        WorkflowTriggerSecret::issue(workflow, digest("s3cret"), &managing(by)).unwrap()
    }

    /// The secret as storage would keep it.
    fn stored(secret: &WorkflowTriggerSecret<ResolvedTenant>) -> WorkflowTriggerSecretRow {
        WorkflowTriggerSecretRow {
            id: secret.id,
            workflow_id: secret.workflow_id,
            secret_hash: secret.secret_hash.clone(),
            issued_by: secret.issued_by.clone(),
            created_at: secret.created_at,
            secret_changed_at: secret.secret_changed_at,
        }
    }

    /// Ann issues a secret for her published webhook workflow. A call with
    /// it is admitted for that very version, and the issue is recorded.
    #[test]
    fn a_call_with_the_secret_is_admitted_for_the_version_in_service() {
        let workflow = hooked();
        let mut secret = issued_by(&workflow, &ann());

        let call = secret.admit(&digest("s3cret"), &workflow).unwrap();

        assert!(call.admits(&workflow));
        assert_eq!(
            raised_names(&mut secret),
            ["workflows.trigger_secret_issued"]
        );
    }

    /// A webhook call presenting the wrong secret is forbidden.
    #[test]
    fn a_call_with_a_wrong_secret_is_refused() {
        let workflow = hooked();
        let secret = issued_by(&workflow, &ann());

        let guessed = secret.admit(&digest("guess"), &workflow);

        assert!(matches!(guessed, Err(DomainError::Forbidden(_))));
    }

    /// Rotating a webhook secret rejects the old secret and admits the new
    /// one, raising a rotation event.
    #[test]
    fn a_replaced_secret_starts_nothing_more() {
        let workflow = hooked();
        let mut secret = issued_by(&workflow, &ann());
        raised_names(&mut secret);

        secret
            .rotate(&workflow, digest("fresh"), &managing(&ann()))
            .unwrap();

        assert!(matches!(
            secret.admit(&digest("s3cret"), &workflow),
            Err(DomainError::Forbidden(_))
        ));
        assert!(secret.admit(&digest("fresh"), &workflow).is_ok());
        assert_eq!(
            raised_names(&mut secret),
            ["workflows.trigger_secret_rotated"]
        );
    }

    /// A workflow viewer cannot issue, rotate or revoke a webhook secret.
    #[test]
    fn changing_a_webhook_secret_needs_the_right_to_edit_workflows() {
        let workflow = hooked();
        let mut secret = issued_by(&workflow, &ann());
        let sam = bob();

        let issued = WorkflowTriggerSecret::issue(&workflow, digest("mine"), &viewing(&sam));
        let rotated = secret.rotate(&workflow, digest("mine"), &viewing(&sam));
        let revoked = secret.revoke(&workflow, &viewing(&sam));

        assert!(matches!(issued, Err(DomainError::Forbidden(_))));
        assert!(matches!(rotated, Err(DomainError::Forbidden(_))));
        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
    }

    /// An editor may issue a webhook secret, but it cannot admit calls for a
    /// version published by someone else.
    #[test]
    fn a_secret_starts_only_versions_its_issuer_published() {
        let workflow = hooked();
        let sam = bob();
        let secret = WorkflowTriggerSecret::issue(
            &workflow,
            digest("s3cret"),
            &holding_only(&sam, WorkflowAction::Update),
        )
        .unwrap();

        let call = secret.admit(&digest("s3cret"), &workflow);

        assert!(matches!(call, Err(DomainError::Forbidden(_))));
    }

    /// A workflow started by hand has no webhook, so issuing it a secret is
    /// refused.
    #[test]
    fn only_a_webhook_workflow_has_a_secret() {
        let by_hand = draft_with(
            vec![transform("tidy", Join::All)],
            Vec::new(),
            Trigger::Manual,
        );

        let issued = WorkflowTriggerSecret::issue(&by_hand, digest("s3cret"), &managing(&ann()));

        assert!(matches!(issued, Err(DomainError::Validation(_))));
    }

    /// A webhook secret cannot admit a call for another workflow, even when
    /// both workflows have the same publisher.
    #[test]
    fn a_secret_starts_only_its_own_workflow() {
        let secret = issued_by(&hooked(), &ann());
        let other = hooked();

        let call = secret.admit(&digest("s3cret"), &other);

        assert!(matches!(call, Err(DomainError::Forbidden(_))));
    }

    /// Ann issues a secret while her webhook workflow is a draft. A call
    /// with it is refused until she publishes, and again once she archives
    /// it.
    #[test]
    fn a_call_starts_only_a_version_in_service() {
        let mut workflow = hooked_draft();
        let secret = issued_by(&workflow, &ann());

        let while_draft = secret.admit(&digest("s3cret"), &workflow);
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        let published = secret.admit(&digest("s3cret"), &workflow);
        workflow.archive(&managing(&ann())).unwrap();
        let archived = secret.admit(&digest("s3cret"), &workflow);

        assert!(matches!(while_draft, Err(DomainError::Conflict(_))));
        assert!(published.is_ok());
        assert!(matches!(archived, Err(DomainError::Conflict(_))));
    }

    /// Ann revokes her webhook secret. The revocation is recorded for the
    /// caller to delete it. Revoking it through another workflow is
    /// refused.
    #[test]
    fn revoking_a_secret_is_recorded_for_its_own_workflow_only() {
        let workflow = hooked();
        let mut secret = issued_by(&workflow, &ann());
        raised_names(&mut secret);

        let elsewhere = secret.revoke(&hooked(), &managing(&ann()));
        secret.revoke(&workflow, &managing(&ann())).unwrap();

        assert!(matches!(elsewhere, Err(DomainError::Conflict(_))));
        assert_eq!(
            raised_names(&mut secret),
            ["workflows.trigger_secret_revoked"]
        );
    }

    /// A stored secret reads back. One whose secret was set before it was
    /// first issued is refused as corrupt.
    #[test]
    fn a_stored_secret_set_before_it_was_issued_is_refused() {
        let secret = issued_by(&hooked(), &ann());
        let backwards = WorkflowTriggerSecretRow {
            secret_changed_at: secret.created_at - time::Duration::SECOND,
            ..stored(&secret)
        };

        assert!(WorkflowTriggerSecret::<ResolvedTenant>::reconstitute(stored(&secret)).is_ok());
        assert!(refused_as_corrupt(
            &WorkflowTriggerSecret::<ResolvedTenant>::reconstitute(backwards)
        ));
    }

    /// Ann's secret printed in a debug log shows no digest, so the log
    /// holds no copy of what a call is checked against.
    #[test]
    fn a_secret_never_prints_its_digest() {
        let secret = issued_by(&hooked(), &ann());

        let printed = format!("{secret:?}");

        assert!(!printed.contains("s3cret"), "{printed}");
    }
}
