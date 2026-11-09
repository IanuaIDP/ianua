//! The credentials a bearer is found by, as their rows answer, and the
//! caller each names.

use ianua_app::context::{CallerIdentity, Credential};
use ianua_app::ports::shared::ResolvedCaller;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ActorRef, ApiKeyId, Expiry, KeyPrefix, OperatorId, OrgApiKeyId, OrgUserId, OrganizationId,
    SessionId, TenantId, UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const OPERATOR_KEY: Stored = Stored("operator key");

/// A tenant session a refresh token names. The lookup query fills it.
pub(super) struct SessionHit {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) expires_at: OffsetDateTime,
}

/// A tenant API key a digest names, before its maker is read. The lookup
/// query fills it.
pub(super) struct KeyHit {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
}

/// An organization session a refresh token names. The lookup query fills
/// it.
pub(super) struct OrgSessionHit {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) org_user_id: Uuid,
    pub(super) expires_at: OffsetDateTime,
}

/// An organization API key a digest names. The lookup query fills it.
pub(super) struct OrgKeyHit {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) created_by: Uuid,
    pub(super) expires_at: Option<OffsetDateTime>,
}

/// An operator key a digest names. The lookup query fills it.
pub(super) struct OperatorKeyHit {
    pub(super) key_prefix: String,
    pub(super) operator_id: Uuid,
    pub(super) expires_at: Option<OffsetDateTime>,
}

impl SessionHit {
    /// The tenant the session is in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// The user signed in to the session, in `organization`'s tenant.
    pub(super) fn into_caller(self, organization: OrganizationId) -> ResolvedCaller {
        ResolvedCaller {
            identity: CallerIdentity::TenantUser(UserId::from_uuid(self.user_id)),
            credential: Credential::TenantSession(SessionId::from_uuid(self.id)),
            organization_id: Some(organization),
            tenant_id: Some(TenantId::from_uuid(self.tenant_id)),
            kept_until: Expiry::At(self.expires_at),
        }
    }
}

impl KeyHit {
    /// The tenant the key is kept in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// The key's id.
    pub(super) fn key(&self) -> ApiKeyId {
        ApiKeyId::from_uuid(self.id)
    }
}

/// A tenant API key once its maker and its tenant's organization are read.
pub(super) struct MadeKey<'a> {
    pub(super) key: ApiKeyId,
    pub(super) maker: &'a ActorRef,
    pub(super) ends: Expiry,
    pub(super) tenant: TenantId,
    pub(super) organization: OrganizationId,
}

impl MadeKey<'_> {
    /// The caller the key names until it ends: the one who made it, a
    /// tenant user or a member of the organization. A key made by anyone
    /// else names no caller, so its bearer is refused.
    pub(super) fn into_caller(self) -> Option<ResolvedCaller> {
        let identity = match self.maker {
            ActorRef::User(user) => CallerIdentity::TenantUser(*user),
            ActorRef::OrgUser(member) => CallerIdentity::OrgUser(*member),
            ActorRef::Operator(_)
            | ActorRef::System
            | ActorRef::Anonymous
            | ActorRef::OAuthClient(_)
            | ActorRef::ApiKey(_)
            | ActorRef::Service(_)
            | ActorRef::Agent { .. } => return None,
        };
        Some(ResolvedCaller {
            identity,
            credential: Credential::TenantApiKey(self.key),
            organization_id: Some(self.organization),
            tenant_id: Some(self.tenant),
            kept_until: self.ends,
        })
    }
}

impl OrgSessionHit {
    /// The member signed in to the session, acting on their organization.
    pub(super) fn into_caller(self) -> ResolvedCaller {
        ResolvedCaller {
            identity: CallerIdentity::OrgUser(OrgUserId::from_uuid(self.org_user_id)),
            credential: Credential::OrgSession(SessionId::from_uuid(self.id)),
            organization_id: Some(OrganizationId::from_uuid(self.organization_id)),
            tenant_id: None,
            kept_until: Expiry::At(self.expires_at),
        }
    }
}

impl OrgKeyHit {
    /// The member who made the key, acting on their organization.
    pub(super) fn into_caller(self) -> ResolvedCaller {
        ResolvedCaller {
            identity: CallerIdentity::OrgUser(OrgUserId::from_uuid(self.created_by)),
            credential: Credential::OrgApiKey(OrgApiKeyId::from_uuid(self.id)),
            organization_id: Some(OrganizationId::from_uuid(self.organization_id)),
            tenant_id: None,
            kept_until: self.expires_at.map_or(Expiry::Never, Expiry::At),
        }
    }
}

impl OperatorKeyHit {
    /// The operator the key belongs to, acting on the platform.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the stored prefix is no
    /// key prefix.
    pub(super) fn into_caller(self) -> Result<ResolvedCaller, DomainError> {
        let prefix = OPERATOR_KEY.value("key prefix", KeyPrefix::new(self.key_prefix))?;
        Ok(ResolvedCaller {
            identity: CallerIdentity::Operator(OperatorId::from_uuid(self.operator_id)),
            credential: Credential::OperatorKey(prefix),
            organization_id: None,
            tenant_id: None,
            kept_until: self.expires_at.map_or(Expiry::Never, Expiry::At),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key a tenant user made names that user; one an organization member
    /// made names the member.
    #[test]
    fn a_tenant_key_names_its_maker() {
        let tenant = TenantId::new();
        let organization = OrganizationId::new();
        let user = UserId::new();
        let member = OrgUserId::new();

        let by_user = MadeKey {
            key: ApiKeyId::new(),
            maker: &ActorRef::User(user),
            ends: Expiry::Never,
            tenant,
            organization,
        }
        .into_caller()
        .unwrap();
        let by_member = MadeKey {
            key: ApiKeyId::new(),
            maker: &ActorRef::OrgUser(member),
            ends: Expiry::Never,
            tenant,
            organization,
        }
        .into_caller()
        .unwrap();

        assert_eq!(by_user.identity, CallerIdentity::TenantUser(user));
        assert_eq!(by_member.identity, CallerIdentity::OrgUser(member));
    }

    /// A tenant API key attributed to the system resolves to no caller.
    #[test]
    fn a_key_made_by_no_person_names_no_caller() {
        let caller = MadeKey {
            key: ApiKeyId::new(),
            maker: &ActorRef::System,
            ends: Expiry::Never,
            tenant: TenantId::new(),
            organization: OrganizationId::new(),
        }
        .into_caller();

        assert!(caller.is_none());
    }
}
