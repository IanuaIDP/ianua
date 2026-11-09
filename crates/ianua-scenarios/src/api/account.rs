//! A person's own account on either plane: their profile and address,
//! consent, exports and erasure, the sessions they end, the accounts of
//! theirs they link across tenants, and their link to an identity
//! provider.

use crate::api::{OrgPath, Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::account::{
    Account, Consent, Download, EmailChange, ErasureRequest, Export, ExportRequest, LinkedSession,
    LinkedSwitch, Preferences, ProviderLinks, ReconfirmLink, Requested, Unlink,
};
use crate::wire::audit::AuditEntry;
use crate::wire::people::{LinkStatus, LinkToken};

/// The header carrying the token of the person's session in an account
/// already in the group of linked accounts.
const LINKED_SESSION_HEADER: &str = "x-linked-session";

/// The account plane whose own profile and address are being managed.
#[derive(Clone, Copy)]
pub enum Plane<'a> {
    /// A tenant user's own session.
    Tenant(&'a TenantPath),
    /// An organization member's own session.
    Member(&'a OrgPath),
}

impl Plane<'_> {
    /// The own-account endpoint on this plane.
    fn me(self) -> String {
        match self {
            Self::Tenant(tenant) => tenant.at("/me"),
            Self::Member(org) => org.at("/me"),
        }
    }

    /// An email-change continuation, kept distinct from other proof purposes.
    fn email(self, action: &str) -> String {
        match self {
            Self::Tenant(tenant) if action == "request-change" => {
                tenant.at("/me/email/request-change")
            }
            Self::Tenant(tenant) => tenant.at(&format!("/users/email/{action}")),
            Self::Member(org) => org.at(&format!("/email/{action}")),
        }
    }
}

/// Reads the profile from the caller's real authenticated identity.
#[must_use]
pub fn me(plane: Plane<'_>) -> Request<Account> {
    Request::of(Call::get(plane.me()))
}

/// Updates only the caller's own preferences and, for members, display name.
#[must_use]
pub fn preferences(plane: Plane<'_>, change: &Preferences) -> Request<()> {
    Request::of(Call::patch(plane.me()).json(change))
}

/// Requests independent confirmation at the new address and a warning at the old one.
#[must_use]
pub fn change_email(plane: Plane<'_>, change: &EmailChange) -> Request<()> {
    Request::of(Call::post(plane.email("request-change")).json(change))
}

/// Confirms only the change whose proof went to its proposed mailbox.
#[must_use]
pub fn confirm_email(plane: Plane<'_>, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(plane.email("confirm-change")).json(proof))
}

/// Cancels a pending change with the proof delivered to the current mailbox.
#[must_use]
pub fn cancel_email(plane: Plane<'_>, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(plane.email("cancel-change")).json(proof))
}

/// Replaces an expired confirmation without changing the requested account or address.
#[must_use]
pub fn resend_email(plane: Plane<'_>, proof: &LinkToken) -> Request<serde::de::IgnoredAny> {
    Request::of(Call::post(plane.email("change-resend")).json(proof))
}

/// Reads what a pending change's link is worth, without spending it.
#[must_use]
pub fn email_status(plane: Plane<'_>, proof: &LinkToken) -> Request<LinkStatus> {
    Request::of(Call::post(plane.email("change-status")).json(proof))
}

/// Grants or withdraws consent for one tenant account.
#[must_use]
pub fn consent(tenant: &TenantPath, user: &str, decision: &Consent) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/users/{user}/consent"))).json(decision))
}

/// Reads the ordered history rather than treating consent as an overwrite.
#[must_use]
pub fn consents(tenant: &TenantPath, user: &str) -> Request<Vec<Consent>> {
    Request::of(Call::get(tenant.at(&format!("/users/{user}/consent"))))
}

/// `POST …/users/{id}/exports`: asks for an export of the account's data,
/// which the worker builds.
#[must_use]
pub fn export(tenant: &TenantPath, user: &str, export: &ExportRequest) -> Request<Requested> {
    Request::of(Call::post(tenant.at(&format!("/users/{user}/exports"))).json(export))
}

/// Lists export progress for the account the path names.
#[must_use]
pub fn exports(tenant: &TenantPath, user: &str) -> Request<Vec<Export>> {
    Request::of(Call::get(tenant.at(&format!("/users/{user}/exports"))))
}

/// Gets a ready export's signed link through the holder's own session.
#[must_use]
pub fn download(tenant: &TenantPath, id: &str) -> Request<Download> {
    Request::of(Call::post(
        tenant.at(&format!("/users/exports/{id}/download")),
    ))
}

/// `POST …/users/{id}/erasure`: closes the tenant account now; the
/// erasure itself is due once its cancellation window has passed.
#[must_use]
pub fn erase(tenant: &TenantPath, user: &str, erasure: &ErasureRequest) -> Request<Requested> {
    Request::of(Call::post(tenant.at(&format!("/users/{user}/erasure"))).json(erasure))
}

/// Cancels an erasure through its independently mailed proof.
#[must_use]
pub fn cancel_erasure(tenant: &TenantPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(tenant.at("/users/erasure/cancel-by-link")).json(proof))
}

/// `POST …/users/erasure/{id}/cancel`: someone who may erase the person
/// calls the erasure off and opens the account again.
#[must_use]
pub fn staff_cancel_erasure(tenant: &TenantPath, erasure_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/users/erasure/{erasure_id}/cancel")),
    ))
}

/// Ends every other session of the signed-in tenant user, preserving this one.
#[must_use]
pub fn sign_out_others(tenant: &TenantPath) -> Request<serde::de::IgnoredAny> {
    Request::of(Call::post(tenant.at("/me/sessions/sign-out-others")))
}

/// Reads the caller's own sign-in history without another account's records.
#[must_use]
pub fn sign_ins(tenant: &TenantPath) -> Request<Page<AuditEntry>> {
    Request::of(Call::get(tenant.at("/me/sign-ins")))
}

/// `POST …/users/erasure/{id}/hold`: staff put an erasure under a legal
/// hold, so it is not carried out whatever its date.
#[must_use]
pub fn hold_erasure(tenant: &TenantPath, erasure_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/users/erasure/{erasure_id}/hold")),
    ))
}

/// `POST …/users/erasure/{id}/release`: staff lift the legal hold, so the
/// erasure is due again on its own date.
#[must_use]
pub fn release_erasure(tenant: &TenantPath, erasure_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/users/erasure/{erasure_id}/release")),
    ))
}

/// `POST …/users/{id}/consent` of an organization: a member grants or
/// withdraws their own consent.
#[must_use]
pub fn member_consent(org: &OrgPath, member: &str, decision: &Consent) -> Request<()> {
    Request::of(Call::post(org.at(&format!("/users/{member}/consent"))).json(decision))
}

/// `GET …/users/{id}/consents` of an organization: a member's decisions,
/// newest first.
#[must_use]
pub fn member_consents(org: &OrgPath, member: &str) -> Request<Vec<Consent>> {
    Request::of(Call::get(org.at(&format!("/users/{member}/consents"))))
}

/// `POST …/users/{id}/erasure` of an organization: closes the member's
/// account now; the erasure is due once its cancellation window has
/// passed.
#[must_use]
pub fn member_erase(org: &OrgPath, member: &str, erasure: &ErasureRequest) -> Request<Requested> {
    Request::of(Call::post(org.at(&format!("/users/{member}/erasure"))).json(erasure))
}

/// `POST …/users/erasure/cancel-by-link` of an organization: calls off a
/// member's erasure with the link mailed to them.
#[must_use]
pub fn member_cancel_erasure(org: &OrgPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(org.at("/users/erasure/cancel-by-link")).json(proof))
}

/// `POST …/identities`: the signed-in person opens a group of linked
/// accounts with the account this session is in.
#[must_use]
pub fn link_accounts(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::post(tenant.at("/identities")))
}

/// `POST …/identities` carrying the token of the person's session in an
/// account already in the group: the account this session is in joins it.
#[must_use]
pub fn join_linked_accounts(tenant: &TenantPath, linked_session_token: &str) -> Request<()> {
    Request::of(
        Call::post(tenant.at("/identities")).header(LINKED_SESSION_HEADER, linked_session_token),
    )
}

/// `POST …/auth/tenant/switch`: the session moves into the person's linked
/// account in another tenant.
#[must_use]
pub fn switch_linked_account(tenant: &TenantPath, switch: &LinkedSwitch) -> Request<LinkedSession> {
    Request::of(Call::post(tenant.at("/auth/tenant/switch")).json(switch))
}

/// `DELETE …/identities`: one account leaves the group of linked
/// accounts; the group is gone once its last account leaves.
#[must_use]
pub fn unlink_account(tenant: &TenantPath, unlink: &Unlink) -> Request<()> {
    Request::of(Call::delete(tenant.at("/identities")).json(unlink))
}

/// `GET …/federation/links`: the caller's links to identity providers.
#[must_use]
pub fn provider_links(tenant: &TenantPath) -> Request<ProviderLinks> {
    Request::of(Call::get(tenant.at("/federation/links")))
}

/// `POST …/federation/connections/{id}/link/reconfirm`: the caller
/// confirms their link through the connection again, proved afresh.
#[must_use]
pub fn reconfirm_provider_link(
    tenant: &TenantPath,
    connection_id: &str,
    reconfirm: &ReconfirmLink,
) -> Request<()> {
    let path = tenant.at(&format!(
        "/federation/connections/{connection_id}/link/reconfirm"
    ));
    Request::of(Call::post(path).json(reconfirm))
}

/// `DELETE …/federation/connections/{id}/link`: the caller removes their
/// own link through the connection.
#[must_use]
pub fn unlink_provider(tenant: &TenantPath, connection_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/federation/connections/{connection_id}/link")),
    ))
}
