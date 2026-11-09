//! Ending what a user is doing when they lose their standing: their
//! sign-ins, and the authority they lent their agents.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, PrincipalRef, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::{DataExportFiles, DataExportStore, UserStore};
use crate::ports::shared::SessionStore;
use crate::services::authorization::grant_revocation::GrantRevocation;
use crate::tenancy::ScopedTenant;

/// Revokes the user's sessions, so nothing the user signed in with keeps
/// authenticating. The cached callers go with the event each such path
/// records.
///
/// # Errors
///
/// Returns `AppError::Internal` if the sessions cannot be revoked.
pub(in crate::use_cases::identity) async fn sign_out_everywhere(
    session_store: &dyn SessionStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<(), AppError> {
    session_store
        .revoke_all_by_user(tenant, user_id)
        .await
        .or_internal()?;
    Ok(())
}

/// What ends everything a user does: their sessions and the delegations
/// they granted.
///
/// Every path that shuts a user out, locks them or deletes them runs it, so
/// their agents stop acting in the name of someone who no longer can.
#[derive(Clone)]
pub struct StandingRemoval {
    /// Revokes the user's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Revokes the delegations the user granted.
    pub grant_revocation: GrantRevocation,
    /// The user's data export requests, whose files go with the account.
    pub exports: Arc<dyn DataExportStore>,
    /// Removes those files, which no database cascade reaches.
    pub export_files: Arc<dyn DataExportFiles>,
}

impl StandingRemoval {
    /// Revokes `account`'s delegations before ending and saving its sessions.
    /// The account must already be locked, disabled or closing for erasure.
    /// Returns delegation events attributed to `actor` and session-revocation
    /// events for the auditor to attribute to the caller. Dispatch follows the
    /// account save; a failed delegation revocation leaves sessions for a retry.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when `account` still signs in.
    /// - `AppError::Internal` when the delegations cannot be revoked or the
    ///   sessions cannot be read or ended.
    pub(crate) async fn cut_off(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let mut revoked = self
            .delegations_revoked(tenant, *account.id(), actor)
            .await?;
        revoked.extend(self.sessions_ended(tenant, account).await?);
        Ok(revoked)
    }

    /// Revokes every delegation `user_id` granted, with what records it,
    /// attributed to `actor`.
    async fn delegations_revoked(
        &self,
        tenant: &ScopedTenant,
        user_id: UserId,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, AppError> {
        self.grant_revocation
            .revoke_all_granted_by(tenant, &PrincipalRef::User(user_id), actor)
            .await
            .or_internal()
    }

    /// Ends and saves every session `account` still holds, with what
    /// records each end.
    async fn sessions_ended(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let store = self.session_store.as_ref();
        let held = store
            .list_active_by_user(tenant, account.id())
            .await
            .or_internal()?;
        let mut ended = Vec::new();
        for mut session in held {
            session
                .end_with_account(account)
                .map_err(AppError::from_domain)?;
            store.save(tenant, &session).await.or_internal()?;
            ended.extend(session.take_events(tenant));
        }
        Ok(ended)
    }

    /// Revokes `user_id`'s delegations and sessions, removes export files, then
    /// deletes the account, returning delegation-revocation events.
    /// Delegations and external files cannot cascade, so they go first; file
    /// removal is retry-safe. Dependent rows cascade with account deletion,
    /// whose `identity.user_deleted` event records the sessions' removal.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the delegations or sessions cannot
    /// be revoked, an export's file cannot be removed or the account cannot
    /// be deleted.
    pub(crate) async fn remove(
        &self,
        users: &dyn UserStore,
        tenant: &ScopedTenant,
        user_id: UserId,
        actor: &ActorRef,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let revoked = self.delegations_revoked(tenant, user_id, actor).await?;
        sign_out_everywhere(self.session_store.as_ref(), tenant, &user_id).await?;
        self.remove_export_files(tenant, &user_id).await?;
        users.delete(tenant, &user_id).await.or_internal()?;
        Ok(revoked)
    }

    /// Removes the file of every data export `user_id` asked for.
    async fn remove_export_files(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), AppError> {
        let exports = self
            .exports
            .list_by_user(tenant, user_id)
            .await
            .or_internal()?;
        for export in &exports {
            self.export_files
                .delete(tenant, export.id())
                .await
                .or_internal()?;
        }
        Ok(())
    }
}
