-- The identity provider of the given organization, if it has one.
SELECT id, organization_id, name, saml, oidc, email_trust, assurance_trust,
       status, created_at
FROM org_identity_providers
WHERE organization_id = $1
