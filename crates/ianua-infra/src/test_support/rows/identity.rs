//! Rows of the identity context.

use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::import::run::UserImportRow;
use ianua_domain::domains::identity::account::import::state::ImportState;
use ianua_domain::domains::identity::account::import::{
    AccountImport, ImportRecord, ImportedPassword,
};
use ianua_domain::domains::identity::account::user::UserRow;
use ianua_domain::domains::identity::account::user_profile::{
    DirectoryRecords, PersonalDetails, UserProfile,
};
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::identity::attribute::definition::AttributeUse;
use ianua_domain::domains::identity::attribute::{
    AttributeDefinitionRow, AttributeKey, AttributeKind, AttributeNamespace, AttributeVisibility,
};
use ianua_domain::domains::identity::impersonation::SupportImpersonationRow;
use ianua_domain::domains::identity::impersonation::state::{
    ImpersonationConsent, ImpersonationState, ImpersonationWindow,
};
use ianua_domain::domains::identity::invitations::invitation::InvitationRow;
use ianua_domain::domains::identity::invitations::offer::OfferState;
use ianua_domain::domains::identity::privacy::consent::{
    ConsentDecision, ConsentRecordRow, ConsentType,
};
use ianua_domain::domains::identity::privacy::erasure::{ErasureRequestRow, ErasureState};
use ianua_domain::domains::identity::privacy::export::{
    DataExportRequestRow, ExportAskedBy, ExportScope,
};
use ianua_domain::domains::identity::privacy::export_state::ExportState;
use ianua_domain::domains::identity::tokens::secure::SecureTokenRow;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActorRef, AttributeDefinitionId, ConsentId, CredentialChange, DataExportId, DisplayName, Email,
    ErasureRequestId, Fact, InvitationId, Joining, Label, Preference, RoleId,
    SupportImpersonationId, Text, TokenHash, Usage, UserId, UserImportId,
};
use time::{Duration, OffsetDateTime};

use crate::test_support::rows::at;

/// An active user at `email` with a verified address, joined at the fixed
/// moment, named after the address.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn user_row(email: &str) -> UserRow {
    user_row_standing(email, UserStatus::Active)
}

/// A user at `email` standing at `status`: one still waiting to join has
/// neither proved its address nor joined, any other has done both.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn user_row_standing(email: &str, status: UserStatus) -> UserRow {
    let waiting = matches!(
        status,
        UserStatus::Invited | UserStatus::PendingVerification
    );
    let (email_standing, joining) = if waiting {
        (AddressStanding::Unverified, Joining::NotYet)
    } else {
        (AddressStanding::Verified, Joining::Joined { at: at(0) })
    };
    UserRow {
        id: UserId::new(),
        email: Email::new(email).expect("a valid address"),
        display_name: DisplayName::new(email, &DisplayNameLimits::default()).expect("a valid name"),
        status,
        email_standing,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        profile: UserProfile {
            details: PersonalDetails::default(),
            records: DirectoryRecords::default(),
        },
        created_at: at(0),
        updated_at: at(0),
        last_login_at: None,
        joining,
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    }
}

/// A declared attribute `key` in `namespace`, holding `kind`, in use, with
/// the kind's own control and every query switch off.
///
/// # Panics
///
/// When `key` is not a valid attribute key, which is a mistake in the test.
#[must_use]
pub fn attribute_row(
    key: &str,
    namespace: AttributeNamespace,
    kind: AttributeKind,
) -> AttributeDefinitionRow {
    AttributeDefinitionRow {
        id: AttributeDefinitionId::new(),
        key: AttributeKey::new(key).expect("a valid attribute key"),
        namespace,
        kind,
        control: kind.default_control(),
        display_name: Label::new("display_name", key).expect("a valid name"),
        description: None,
        options: Vec::new(),
        max_length: Restriction::Unrestricted,
        minimum: Restriction::Unrestricted,
        maximum: Restriction::Unrestricted,
        visibility: AttributeVisibility::default(),
        archived: AttributeUse::InUse,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// `seconds` from now, in whole seconds, for a row the store compares
/// with the clock itself, such as a link it spends now.
///
/// # Panics
///
/// Never: dropping the part of a second always gives a real time.
#[must_use]
pub fn from_now(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("a whole second is a real time")
        .saturating_add(Duration::seconds(seconds))
}

/// An unused link `hash` for `user_id`, mailed to `sent_to` an hour ago
/// and working for an hour more.
///
/// # Panics
///
/// When `sent_to` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn link_row(user_id: UserId, hash: &str, sent_to: &str) -> SecureTokenRow {
    SecureTokenRow {
        token_hash: TokenHash::from_stored(hash.to_owned()),
        user_id,
        sent_to: Email::new(sent_to).expect("a valid address"),
        created_at: from_now(-3600),
        expires_at: from_now(3600),
        usage: Usage::Unused,
    }
}

/// An import of one record per address in `emails`, sent by `by`, not yet
/// taken up.
///
/// # Panics
///
/// When an address is not a valid one, which is a mistake in the test.
#[must_use]
pub fn import_row(by: UserId, emails: &[&str]) -> UserImportRow {
    UserImportRow {
        id: UserImportId::new(),
        records: emails.iter().map(|email| import_record(email)).collect(),
        started_by: ActorRef::User(by),
        state: ImportState::Pending,
        done: 0,
        imported: 0,
        refused: Vec::new(),
        created_at: at(0),
    }
}

/// One record of an import, for an account at `email` with no password.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn import_record(email: &str) -> ImportRecord {
    ImportRecord {
        account: AccountImport {
            email: Email::new(email).expect("a valid address"),
            display_name: DisplayName::new(email, &DisplayNameLimits::default())
                .expect("a valid name"),
            details: PersonalDetails::default(),
            records: DirectoryRecords::default(),
        },
        password: ImportedPassword::NotCarried,
    }
}

/// `admin`'s request, at `seconds` past the fixed moment, to act as
/// `user_id` for half an hour, waiting for the person to approve.
///
/// # Panics
///
/// Never for the reason and window it uses.
#[must_use]
pub fn impersonation_row(admin: UserId, user_id: UserId, seconds: i64) -> SupportImpersonationRow {
    SupportImpersonationRow {
        id: SupportImpersonationId::new(),
        admin,
        user_id,
        reason: Text::new("reason", "ticket 4711").expect("a valid reason"),
        window: ImpersonationWindow::minutes(30).expect("a valid window"),
        consent: ImpersonationConsent::HolderApproves,
        state: ImpersonationState::AwaitingConsent,
        requested_at: at(seconds),
    }
}

/// `user_id`'s own request for everything kept about them, asked at
/// `seconds` past the fixed moment and still being gathered.
#[must_use]
pub fn export_row(user_id: UserId, seconds: i64) -> DataExportRequestRow {
    DataExportRequestRow {
        id: DataExportId::new(),
        user_id,
        scope: ExportScope::Access,
        asked_by: ExportAskedBy::Holder,
        state: ExportState::Requested,
        requested_at: at(seconds),
    }
}

/// `user_id`'s pending request to be erased, asked at the fixed moment and
/// due fourteen days later, with its cancel link `hash`.
///
/// # Panics
///
/// Never for the address it uses.
#[must_use]
pub fn erasure_row(user_id: UserId, hash: &str) -> ErasureRequestRow {
    ErasureRequestRow {
        id: ErasureRequestId::new(),
        user_id,
        reason: None,
        state: ErasureState::Pending,
        requested_at: at(0),
        scheduled_at: at(0).saturating_add(Duration::days(14)),
        cancel_token_hash: TokenHash::from_stored(hash.to_owned()),
        sent_to: Email::new("ann@acme.example").expect("a valid address"),
    }
}

/// `user_id`'s consent of `consent_type` to version `tos-1`, given at
/// `seconds` past the fixed moment, from no known address.
///
/// # Panics
///
/// Never for the version it uses.
#[must_use]
pub fn consent_row(user_id: UserId, consent_type: ConsentType, seconds: i64) -> ConsentRecordRow {
    ConsentRecordRow {
        id: ConsentId::new(),
        user_id,
        consent_type,
        granted: ConsentDecision::Granted,
        version: Label::new("version", "tos-1").expect("a valid version"),
        ip_address: Fact::Unknown,
        recorded_at: at(seconds),
    }
}

/// The recipient, role and link used by an invitation fixture.
#[derive(Clone, Copy)]
pub struct InvitationSeed<'a> {
    /// The account receiving the invitation.
    pub user_id: UserId,
    /// The role offered by the invitation.
    pub role_id: RoleId,
    /// The recipient's mailbox.
    pub email: &'a str,
    /// The stored digest of the invitation link.
    pub hash: &'a str,
    /// The issue time relative to the fixed fixture moment.
    pub seconds: i64,
}

/// A pending invitation for the invited account `user_id` at `email`,
/// giving `role_id`, with the link `hash`, sent by the platform at
/// `seconds` past the fixed moment, working for a week.
///
/// # Panics
///
/// When `email` is not a valid address, which is a mistake in the test.
#[must_use]
pub fn invitation_row(seed: InvitationSeed<'_>) -> InvitationRow {
    let InvitationSeed {
        user_id,
        role_id,
        email,
        hash,
        seconds,
    } = seed;
    InvitationRow {
        id: InvitationId::new(),
        user_id,
        email: Email::new(email).expect("a valid address"),
        invited_by: ActorRef::System,
        role_id,
        token_hash: TokenHash::from_stored(hash.to_owned()),
        state: OfferState::Pending,
        message: None,
        expires_at: at(seconds).saturating_add(Duration::days(7)),
        created_at: at(seconds),
    }
}
