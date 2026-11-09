//! The company steps about people: finding one, inviting one, suspending
//! them, clearing their second factors, signing them out everywhere,
//! forgetting their remembered devices, ending their API keys and sending
//! them a notice.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_status::DeviceStatus;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::notifications::notice::NoticeMessage;
use ianua_domain::domains::notifications::notification::title_label;
use ianua_domain::domains::signals::report::ReportedSignal;
use ianua_domain::domains::signals::signal::{CredentialKind, SignalRiskLevel};
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::{
    EMAIL_INPUT, GROUP_INPUT, KEY_INPUT, MESSAGE_INPUT, NAME_INPUT, PERSON_INPUT, ROLE_INPUT,
    SIGNAL_INPUT, TITLE_INPUT,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    ActorRef, ApiKeyId, DisplayName, Email, GroupId, NotificationId, RoleId, Text, UserId,
};
use uuid::Uuid;

use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::workflows::CompanyCall;
use crate::services::identity::link_scopes::TenantLinkScopes;
use crate::use_case::{Command as _, Query as _};
use crate::use_cases::authentication::sessions::device_trust::{
    ListDevicesUseCase, RevokeDeviceRequest, RevokeDeviceUseCase,
};
use crate::use_cases::identity::invitations::{InviteUserRequest, InviteUserUseCase};
use crate::use_cases::identity::users::{
    GetUseCase, ListRequest, ListSessionsUseCase, ListUseCase, ResetFactorsUseCase,
    RevokeSessionRequest, RevokeSessionUseCase, UpdateStatusRequest, UpdateStatusUseCase,
    UserCriteria,
};
use crate::use_cases::identity::whose::Whose;
use crate::use_cases::notifications::notices;
use crate::use_cases::oauth::api_keys;
use crate::use_cases::signals::reports;
use crate::use_cases::workflows::executions::answers::{data, failed};
use crate::use_cases::workflows::executions::company::inputs::{id, optional_text, text};
use crate::use_cases::workflows::executions::company::{succeeded, unmade};

/// The most people an address is looked up among.
const LOOKED_UP: u32 = 20;

/// The most pages of API keys read while ending a person's keys.
const KEY_PAGES: usize = 20;

/// The dashboard's actions on people.
pub struct PeopleActions {
    /// Reads one person.
    pub get: Arc<GetUseCase>,
    /// Lists people, to find one by their address.
    pub list: Arc<ListUseCase>,
    /// Suspends a person.
    pub update_status: Arc<UpdateStatusUseCase>,
    /// Clears a person's second factors.
    pub reset_factors: Arc<ResetFactorsUseCase>,
    /// Lists a person's sessions.
    pub sessions: Arc<ListSessionsUseCase>,
    /// Ends one of a person's sessions.
    pub revoke_session: Arc<RevokeSessionUseCase>,
    /// Lists the tenant's API keys.
    pub keys: Arc<api_keys::ListUseCase>,
    /// Ends one API key.
    pub revoke_key: Arc<api_keys::RevokeUseCase>,
    /// Pauses one API key.
    pub pause_key: Arc<api_keys::PauseUseCase>,
    /// Resumes one paused API key.
    pub resume_key: Arc<api_keys::ResumeUseCase>,
    /// Reports a signal about a person to the signal streams.
    pub report_signal: Arc<reports::SendUseCase>,
    /// Lists a person's remembered devices.
    pub devices: Arc<ListDevicesUseCase>,
    /// Forgets one of a person's remembered devices.
    pub forget_device: Arc<RevokeDeviceUseCase>,
    /// Invites a person.
    pub invite: Arc<InviteUserUseCase>,
    /// Where an invitation's link points, from the tenant's stored names.
    pub link_scopes: TenantLinkScopes,
    /// Puts a notice in a person's inbox.
    pub notify: Arc<notices::SendUseCase>,
}

impl PeopleActions {
    /// The person `step` names in `input`: their user id, or their address
    /// as the tenant keeps it.
    pub(super) async fn person(
        &self,
        step: &CompanyCall<'_>,
        input: &str,
    ) -> Result<UserId, ActionOutcome> {
        self.named(step, text(step.call, input)?).await
    }

    /// The person `named` names: a user id, or an address the tenant keeps.
    pub(super) async fn named(
        &self,
        step: &CompanyCall<'_>,
        named: &str,
    ) -> Result<UserId, ActionOutcome> {
        if let Ok(id) = Uuid::parse_str(named) {
            return Ok(UserId::from_uuid(id));
        }
        self.by_address(step, named).await.map(|user| *user.id())
    }

    /// The person reached at `address`, read as the run's person may read
    /// people.
    async fn by_address(
        &self,
        step: &CompanyCall<'_>,
        address: &str,
    ) -> Result<User<ResolvedTenant>, ActionOutcome> {
        let request = ListRequest {
            criteria: UserCriteria {
                email_contains: Some(address.to_owned()),
                ..UserCriteria::default()
            },
            invitation: None,
            order: Default::default(),
            page: PageRequest::first(Limit::internal(LOOKED_UP)),
        };
        let page = self
            .list
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        page.items
            .into_iter()
            .map(|listed| listed.user)
            .find(|user| user.email().as_str().eq_ignore_ascii_case(address))
            .ok_or_else(|| failed("nobody in the company is reached at that address"))
    }

    /// Reads the person the step names.
    pub(super) async fn find(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let user = self
            .get
            .execute(step.caller, user_id)
            .await
            .map_err(unmade)?;
        let output = data(vec![
            ("user_id", FlowData::text(user.id().to_string())),
            ("name", FlowData::text(user.display_name().as_str())),
            ("email", FlowData::text(user.email().as_str())),
            ("status", FlowData::text(user.status().to_string())),
        ])?;
        Ok(succeeded(step, output, DataClassLevel::Confidential))
    }

    /// Suspends the person the step names.
    pub(super) async fn suspend(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let request = UpdateStatusRequest {
            user_id,
            target: UserStatus::Locked,
        };
        self.update_status
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("user_id", FlowData::text(user_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Clears the second factors of the person the step names.
    pub(super) async fn reset_factors(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let cleared = self
            .reset_factors
            .execute(step.caller, step.auditor, user_id)
            .await
            .map_err(unmade)?;
        let removed = cleared.enrollments_turned_off + cleared.passkeys_removed;
        let output = data(vec![("factors_removed", count(removed))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Ends every session of the person the step names.
    pub(super) async fn sign_out(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let sessions = self
            .sessions
            .execute(step.caller, Whose::OnBehalfOf(user_id))
            .await
            .map_err(unmade)?;
        for session in &sessions {
            let request = RevokeSessionRequest {
                whose: Whose::OnBehalfOf(user_id),
                session_id: *session.id(),
            };
            self.revoke_session
                .execute(step.caller, step.auditor, request)
                .await
                .map_err(unmade)?;
        }
        let output = data(vec![("sessions_ended", count(sessions.len()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Puts the notice the step writes in the inbox of the person it names,
    /// offering them what `offering` says.
    pub(super) async fn notify(
        &self,
        step: &CompanyCall<'_>,
        offering: notices::Offering,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let recipient = self.person(step, PERSON_INPUT).await?;
        let title = title_label(text(step.call, TITLE_INPUT)?)
            .map_err(|_| failed("the step's title is not a short line of text"))?;
        let message = match optional_text(step.call, MESSAGE_INPUT)? {
            None => NoticeMessage::TitleOnly,
            Some(message) => {
                NoticeMessage::Says(Text::new("message", message).map_err(|_| {
                    failed("the step's message is not text of up to 500 characters")
                })?)
            }
        };
        let request = notices::SendRequest {
            id: notice_of(step),
            recipient,
            title,
            message,
            offering,
        };
        self.notify
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("sent", Ok(FlowData::bool(true)))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Puts a notice in the inbox of the person the step names, offering
    /// them to ask to join the group it names.
    pub(super) async fn offer_access(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let group = id(step.call, GROUP_INPUT, GroupId::from_uuid)?;
        self.notify(step, notices::Offering::JoinGroup(group)).await
    }

    /// Pauses the API key the step names.
    pub(super) async fn pause_key(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let key_id = id(step.call, KEY_INPUT, ApiKeyId::from_uuid)?;
        self.pause_key
            .execute(step.caller, step.auditor, key_id)
            .await
            .map_err(unmade)?;
        let output = data(vec![("key_id", FlowData::text(key_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Reports the signal the step names about the person it names, to
    /// every signal stream that takes it.
    pub(super) async fn send_signal(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let person = self.person(step, PERSON_INPUT).await?;
        let named = text(step.call, SIGNAL_INPUT)?;
        let signal = reported_signal(named).ok_or_else(|| {
            failed("the step's signal is not risk_low, risk_medium, risk_high, password_compromised or device_compromised")
        })?;
        let request = reports::SendRequest { person, signal };
        self.report_signal
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![("reported", FlowData::text(named))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Resumes the paused API key the step names.
    pub(super) async fn resume_key(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let key_id = id(step.call, KEY_INPUT, ApiKeyId::from_uuid)?;
        self.resume_key
            .execute(step.caller, step.auditor, key_id)
            .await
            .map_err(unmade)?;
        let output = data(vec![("key_id", FlowData::text(key_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Forgets every device the person the step names remembered and still
    /// trusts.
    pub(super) async fn forget_devices(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let devices = self
            .devices
            .execute(step.caller, Whose::OnBehalfOf(user_id))
            .await
            .map_err(unmade)?;
        let trusted: Vec<_> = devices
            .iter()
            .filter(|device| device.status() == DeviceStatus::Trusted)
            .map(|device| *device.id())
            .collect();
        for device_id in &trusted {
            let request = RevokeDeviceRequest {
                whose: Whose::OnBehalfOf(user_id),
                device_id: *device_id,
            };
            self.forget_device
                .execute(step.caller, step.auditor, request)
                .await
                .map_err(unmade)?;
        }
        let output = data(vec![("devices_forgotten", count(trusted.len()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Invites the person at the step's address, under its name, with its
    /// role; the invitation's link points at this tenant.
    pub(super) async fn invite(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request = InviteUserRequest {
            email: Email::new(text(step.call, EMAIL_INPUT)?)
                .map_err(|_| failed("the step's email is not an address"))?,
            display_name: DisplayName::try_from(text(step.call, NAME_INPUT)?.to_owned())
                .map_err(|_| failed("the step's name is not a name"))?,
            role_id: id(step.call, ROLE_INPUT, RoleId::from_uuid)?,
            message: None,
            scope: self
                .link_scopes
                .of(&step.caller.tenant())
                .await
                .map_err(unmade)?,
        };
        let invited = self
            .invite
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![(
            "user_id",
            FlowData::text(invited.user_id.to_string()),
        )])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Ends every API key the person the step names made.
    pub(super) async fn revoke_keys(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let user_id = self.person(step, PERSON_INPUT).await?;
        let theirs = self.keys_of(step, user_id).await?;
        for key in &theirs {
            self.revoke_key
                .execute(step.caller, step.auditor, *key)
                .await
                .map_err(unmade)?;
        }
        let output = data(vec![("keys_revoked", count(theirs.len()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// The API keys `user_id` made, read page by page.
    async fn keys_of(
        &self,
        step: &CompanyCall<'_>,
        user_id: UserId,
    ) -> Result<Vec<ianua_domain::types::ApiKeyId>, ActionOutcome> {
        let mut theirs = Vec::new();
        let mut page = PageRequest::first(Limit::internal(100));
        for _ in 0..KEY_PAGES {
            let request = api_keys::ListRequest {
                sort: SortOrder::default(),
                page,
            };
            let read = self
                .keys
                .execute(step.caller, request)
                .await
                .map_err(unmade)?;
            theirs.extend(
                read.items
                    .iter()
                    .filter(|key| matches!(key.created_by(), ActorRef::User(maker) if *maker == user_id))
                    .map(|key| *key.id()),
            );
            let Some(next) = read.next else {
                return Ok(theirs);
            };
            page = PageRequest::new(Some(next), read.limit);
        }
        Err(failed("the person made more API keys than one step ends"))
    }
}

/// How many, as workflow data.
pub(super) fn count(
    how_many: usize,
) -> Result<FlowData, ianua_domain::shared::errors::DomainError> {
    FlowData::number(f64::from(u32::try_from(how_many).unwrap_or(u32::MAX)))
}

/// The signal a step's `signal` input names, or `None` for a name no
/// report goes by.
fn reported_signal(named: &str) -> Option<ReportedSignal> {
    match named {
        "risk_low" => Some(ReportedSignal::RiskLevel(SignalRiskLevel::Low)),
        "risk_medium" => Some(ReportedSignal::RiskLevel(SignalRiskLevel::Medium)),
        "risk_high" => Some(ReportedSignal::RiskLevel(SignalRiskLevel::High)),
        "password_compromised" => Some(ReportedSignal::CredentialCompromised(
            CredentialKind::Password,
        )),
        "device_compromised" => Some(ReportedSignal::DeviceCompromised),
        _ => None,
    }
}

/// The id of the notice the call `step` makes sends: the same each time
/// that call is made, so a call made again after a crash sends one notice.
pub(super) fn notice_of(step: &CompanyCall<'_>) -> NotificationId {
    NotificationId::from_uuid(Uuid::new_v5(step.call.call_id.as_uuid(), b"notice"))
}
