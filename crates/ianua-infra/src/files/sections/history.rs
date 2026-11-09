//! The export's sections about what happened to the person, rather than
//! what they hold: where they signed in from, the failed sign-ins counted
//! against them, the reset links and invitations they were sent, the
//! emergency access and support access given about them, how they chose
//! to be told, and the notices sent to them.

use ianua_app::ports::authentication::CountedAccount;
use ianua_domain::domains::authentication::recovery::reset::ResetStatus;
use ianua_domain::domains::identity::invitations::status::InvitationStatus;
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, CountryCode, Text};
use serde_json::{Value, json};

use crate::files::records::moment;
use crate::files::sections::{Person, PersonalDataSources, maybe};

impl PersonalDataSources {
    /// The countries the person signed in from, and the place and time of
    /// their latest sign-in.
    pub(crate) async fn sign_in_places(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let history = self
            .sign_in_places
            .history(person.tenant, person.user)
            .await?;
        let countries: Vec<&str> = history
            .countries()
            .iter()
            .map(CountryCode::as_str)
            .collect();
        let latest = history
            .last()
            .known()
            .map(|(place, at)| -> Result<Value, DomainError> {
                Ok(json!({
                    "country": place.country_code().as_str(),
                    "city": place.city(),
                    "latitude": place.latitude(),
                    "longitude": place.longitude(),
                    "signed_in_at": moment(*at)?,
                }))
            })
            .transpose()?;
        Ok(json!({ "countries": countries, "latest": latest }))
    }

    /// The failed sign-ins counted now against the address the person
    /// signs in with, from every network together, or `null` when none are
    /// counted. Which networks were locked out is left out: those are the
    /// guessers' addresses, not the person's. A plain read, so it neither
    /// holds up a sign-in nor leaves a count behind.
    pub(crate) async fn failed_sign_in_count(
        &self,
        person: Person<'_>,
    ) -> Result<Value, DomainError> {
        let address = self.address(person).await?;
        let account = CountedAccount::Tenant {
            tenant: person.tenant,
            email: &address,
        };
        let failures = self.sign_in_counts.account_failures(account).await?;
        if failures.get() == 0 {
            return Ok(Value::Null);
        }
        Ok(json!({ "failed_count": failures.get() }))
    }

    /// The links the person was sent to reset their password, newest
    /// first: who asked, when, and how each ended.
    pub(crate) async fn password_resets(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let resets = self.resets.list_by_user(person.tenant, person.user).await?;
        let items = resets
            .iter()
            .map(|reset| -> Result<Value, DomainError> {
                Ok(json!({
                    "asked_by": reset.initiator().as_str(),
                    "status": reset_word(reset.status()),
                    "requested_at": moment(reset.created_at())?,
                    "expires_at": moment(reset.expires_at())?,
                    "completed_at": maybe(reset.completed_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The invitations sent to the person's account, newest first: who
    /// sent each, to which role, and how it was answered.
    pub(crate) async fn invitations(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let sent = self
            .invitations
            .list_by_user_id(person.tenant, person.user)
            .await?;
        let items = sent
            .iter()
            .map(|invitation| -> Result<Value, DomainError> {
                Ok(json!({
                    "id": invitation.id().to_string(),
                    "email": invitation.email().as_str(),
                    "invited_by": invitation.invited_by().audit_label(),
                    "role_id": invitation.role_id().to_string(),
                    "message": invitation.message().map(Text::as_str),
                    "status": invitation_word(invitation.status()),
                    "sent_at": moment(invitation.created_at())?,
                    "expires_at": moment(invitation.expires_at())?,
                    "accepted_at": maybe(invitation.accepted_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// The emergency access given to the person: what each grant allowed,
    /// why, who approved it, and until when.
    pub(crate) async fn break_glass_grants(
        &self,
        person: Person<'_>,
    ) -> Result<Value, DomainError> {
        let grants = self.break_glass.list(person.tenant).await?;
        let items = grants
            .iter()
            .filter(|grant| grant.user_id() == person.user)
            .map(|grant| -> Result<Value, DomainError> {
                let access = grant.access();
                let system: Vec<String> = access.system().iter().map(ToString::to_string).collect();
                let custom: Vec<String> = access.custom().iter().map(ToString::to_string).collect();
                let approver = grant
                    .approved_by()
                    .approver()
                    .map(|approver| ActorRef::from(approver.account()).audit_label());
                Ok(json!({
                    "id": grant.id().to_string(),
                    "system_permissions": system,
                    "custom_permissions": custom,
                    "reason": grant.reason().as_str(),
                    "approved_by": approver,
                    "granted_at": moment(grant.created_at())?,
                    "expires_at": moment(grant.expires_at())?,
                    "revoked_at": maybe(grant.revoked_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }

    /// How the person chose to be told of each kind of notice.
    pub(crate) async fn notification_choices(
        &self,
        person: Person<'_>,
    ) -> Result<Value, DomainError> {
        let choices = self
            .notification_choices
            .get(person.tenant, person.user)
            .await?;
        let items: Vec<Value> = choices
            .iter()
            .map(|choice| {
                json!({
                    "category": choice.category().as_str(),
                    "channel": choice.channel().as_str(),
                })
            })
            .collect();
        Ok(Value::Array(items))
    }

    /// The times staff asked to act as the person for support, newest
    /// first: who asked, why, and how it went.
    pub(crate) async fn support_access(&self, person: Person<'_>) -> Result<Value, DomainError> {
        let involving = self
            .impersonations
            .list_involving(person.tenant, person.user)
            .await?;
        let items = involving
            .iter()
            .filter(|asked| asked.user_id() == person.user)
            .map(|asked| -> Result<Value, DomainError> {
                Ok(json!({
                    "id": asked.id().to_string(),
                    "admin_id": asked.admin().to_string(),
                    "reason": asked.reason().as_str(),
                    "status": asked.status().as_str(),
                    "requested_at": moment(asked.requested_at())?,
                    "ends_at": maybe(asked.ends_at())?,
                }))
            })
            .collect::<Result<Vec<Value>, DomainError>>()?;
        Ok(Value::Array(items))
    }
}

/// One notice sent to the person, as their inbox shows it.
pub(crate) fn notice_item(notice: &Notification) -> Result<Value, DomainError> {
    Ok(json!({
        "id": notice.id().to_string(),
        "event_type": notice.event_type().as_str(),
        "category": notice.category().as_str(),
        "severity": notice.severity().as_str(),
        "title": notice.title().as_str(),
        "body": notice.body().map(Text::as_str),
        "read": notice.is_read(),
        "created_at": moment(notice.created_at())?,
    }))
}

/// The word a reset's status is written as.
fn reset_word(status: ResetStatus) -> &'static str {
    match status {
        ResetStatus::Pending => "pending",
        ResetStatus::Completed => "completed",
        ResetStatus::Expired => "expired",
        ResetStatus::Cancelled => "cancelled",
    }
}

/// The word an invitation's status is written as.
fn invitation_word(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Declined => "declined",
        InvitationStatus::Expired => "expired",
        InvitationStatus::Revoked => "revoked",
    }
}
