//! The notification use cases the API serves: each inbox's listing, count
//! and marks, the delivery preferences of tenant users, members and
//! operators, and an organization's destinations outside the app.

use std::sync::Arc;

use ianua_app::use_cases::notifications::{
    GetPreferencesPorts, GetPreferencesUseCase, ListPorts, ListUseCase, MarkAllReadPorts,
    MarkAllReadUseCase, MarkReadPorts, MarkReadUseCase, ReaderPorts, UnreadCountPorts,
    UnreadCountUseCase, UpdatePreferencesPorts, UpdatePreferencesUseCase, destinations, notices,
    personal,
};

use crate::deps::Adapters;

/// The notification use cases.
#[derive(Clone)]
pub struct NotificationState {
    pub list: Arc<ListUseCase>,
    pub unread_count: Arc<UnreadCountUseCase>,
    pub mark_read: Arc<MarkReadUseCase>,
    pub mark_all_read: Arc<MarkAllReadUseCase>,
    pub get_preferences: Arc<GetPreferencesUseCase>,
    pub update_preferences: Arc<UpdatePreferencesUseCase>,
    pub personal: PersonalUseCases,
    /// Where an organization's notifications are posted.
    pub destinations: DestinationUseCases,
}

/// The delivery preferences of organization members and operators.
#[derive(Clone)]
pub struct PersonalUseCases {
    pub member: Arc<personal::GetMemberPreferencesUseCase>,
    pub update_member: Arc<personal::UpdateMemberPreferencesUseCase>,
    pub operator: Arc<personal::GetOperatorPreferencesUseCase>,
    pub update_operator: Arc<personal::UpdateOperatorPreferencesUseCase>,
}

/// The places outside the app an organization's notifications are posted
/// to.
#[derive(Clone)]
pub struct DestinationUseCases {
    /// Adds a place the organization's notifications are posted to.
    pub add: Arc<destinations::AddUseCase>,
    pub list: Arc<destinations::ListUseCase>,
    pub reconfigure: Arc<destinations::ReconfigureUseCase>,
    pub pause: Arc<destinations::PauseUseCase>,
    pub resume: Arc<destinations::ResumeUseCase>,
    pub remove: Arc<destinations::RemoveUseCase>,
}

/// Builds the notification use cases over `a`.
pub fn build(a: &Adapters) -> NotificationState {
    NotificationState {
        personal: personal_use_cases(a),
        destinations: destination_use_cases(a),
        list: Arc::new(list(a)),
        unread_count: Arc::new(UnreadCountUseCase::new(UnreadCountPorts {
            platform_store: a.platform_notification_store.clone(),
            org_store: a.org_notification_store.clone(),
            tenant_store: a.tenant_notification_store.clone(),
            readers: readers(a),
        })),
        mark_read: Arc::new(mark_read(a)),
        mark_all_read: Arc::new(MarkAllReadUseCase::new(MarkAllReadPorts {
            platform_store: a.platform_notification_store.clone(),
            org_store: a.org_notification_store.clone(),
            tenant_store: a.tenant_notification_store.clone(),
            readers: readers(a),
        })),
        get_preferences: Arc::new(GetPreferencesUseCase::new(GetPreferencesPorts {
            preference_store: a.notification_preference_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_preferences: Arc::new(UpdatePreferencesUseCase::new(UpdatePreferencesPorts {
            preference_store: a.notification_preference_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Lists notifications from the inbox selected by the caller's authority.
fn list(a: &Adapters) -> ListUseCase {
    ListUseCase::new(ListPorts {
        platform_store: a.platform_notification_store.clone(),
        org_store: a.org_notification_store.clone(),
        tenant_store: a.tenant_notification_store.clone(),
        readers: readers(a),
    })
}

/// Marks an authorized inbox entry read with its audit and control-plane labels.
fn mark_read(a: &Adapters) -> MarkReadUseCase {
    MarkReadUseCase::new(MarkReadPorts {
        platform_store: a.platform_notification_store.clone(),
        org_store: a.org_notification_store.clone(),
        tenant_store: a.tenant_notification_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
        readers: readers(a),
    })
}

/// The use cases that read and change a member's or an operator's own
/// delivery preferences.
fn personal_use_cases(a: &Adapters) -> PersonalUseCases {
    PersonalUseCases {
        member: Arc::new(personal::GetMemberPreferencesUseCase::new(
            personal::GetMemberPreferencesPorts {
                preferences: a.member_preference_store.clone(),
                org_actors: a.org_actors.clone(),
            },
        )),
        update_member: Arc::new(personal::UpdateMemberPreferencesUseCase::new(
            personal::UpdateMemberPreferencesPorts {
                preferences: a.member_preference_store.clone(),
                org_actors: a.org_actors.clone(),
            },
        )),
        operator: Arc::new(personal::GetOperatorPreferencesUseCase::new(
            personal::GetOperatorPreferencesPorts {
                preferences: a.operator_preference_store.clone(),
                operator_authorities: a.operator_authorities.clone(),
            },
        )),
        update_operator: Arc::new(personal::UpdateOperatorPreferencesUseCase::new(
            personal::UpdateOperatorPreferencesPorts {
                preferences: a.operator_preference_store.clone(),
                operator_authorities: a.operator_authorities.clone(),
            },
        )),
    }
}

/// The use cases that add, list, change, pause, resume and remove an
/// organization's notification destinations.
fn destination_use_cases(a: &Adapters) -> DestinationUseCases {
    DestinationUseCases {
        add: Arc::new(add_destination(a)),
        list: Arc::new(destinations::ListUseCase::new(destinations::ListPorts {
            destinations: a.notification_destination_store.clone(),
            org_actors: a.org_actors.clone(),
        })),
        reconfigure: Arc::new(reconfigure_destination(a)),
        pause: Arc::new(destinations::PauseUseCase::new(destinations::PausePorts {
            destinations: a.notification_destination_store.clone(),
            org_actors: a.org_actors.clone(),
        })),
        resume: Arc::new(destinations::ResumeUseCase::new(
            destinations::ResumePorts {
                destinations: a.notification_destination_store.clone(),
                org_actors: a.org_actors.clone(),
            },
        )),
        remove: Arc::new(destinations::RemoveUseCase::new(
            destinations::RemovePorts {
                destinations: a.notification_destination_store.clone(),
                org_actors: a.org_actors.clone(),
            },
        )),
    }
}

/// Adds an organization destination with sealed credentials and plan enforcement.
fn add_destination(a: &Adapters) -> destinations::AddUseCase {
    destinations::AddUseCase::new(destinations::AddPorts {
        destinations: a.notification_destination_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        secrets: a.destination_secret_generator.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// Replaces a destination's settings under organization authority.
fn reconfigure_destination(a: &Adapters) -> destinations::ReconfigureUseCase {
    destinations::ReconfigureUseCase::new(destinations::ReconfigurePorts {
        destinations: a.notification_destination_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        secrets: a.destination_secret_generator.clone(),
        org_actors: a.org_actors.clone(),
    })
}

/// What tells whose inbox a request reads.
fn readers(a: &Adapters) -> ReaderPorts {
    ReaderPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        org_actors: a.org_actors.clone(),
        operator_authorities: a.operator_authorities.clone(),
    }
}

/// Puts a notice in a tenant person's inbox, for a workflow's notify step.
#[must_use]
pub(crate) fn send_notice(a: &Adapters) -> Arc<notices::SendUseCase> {
    Arc::new(notices::SendUseCase::new(notices::SendPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        users: a.user_store.clone(),
        groups: a.group_store.clone(),
        inboxes: a.tenant_notification_store.clone(),
        publisher: a.notification_publisher.clone(),
        unit_of_work: a.unit_of_work.clone(),
    }))
}
