-- Keeps an organization's identity provider: a new one is added, a known
-- one takes the new values. Its organization and when it was added never
-- change, and a provider of another organization under the same id is
-- left as it is.
INSERT INTO org_identity_providers
    (id, organization_id, name, saml, oidc, email_trust, assurance_trust,
     status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    saml = EXCLUDED.saml,
    oidc = EXCLUDED.oidc,
    email_trust = EXCLUDED.email_trust,
    assurance_trust = EXCLUDED.assurance_trust,
    status = EXCLUDED.status
WHERE org_identity_providers.organization_id = EXCLUDED.organization_id
