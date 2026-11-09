-- Keeps a connection: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant and creation time never change.
INSERT INTO federation_connections
    (id, tenant_id, provider_name, status, saml, oidc, jit_provisioning,
     jit_default_role_id, email_trust, assurance_trust, domain_hint, allowed_domains,
     mapped_claims, mapped_fields, group_claim, created_at, keyed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (id) DO UPDATE SET
    provider_name = EXCLUDED.provider_name,
    status = EXCLUDED.status,
    saml = EXCLUDED.saml,
    oidc = EXCLUDED.oidc,
    jit_provisioning = EXCLUDED.jit_provisioning,
    jit_default_role_id = EXCLUDED.jit_default_role_id,
    email_trust = EXCLUDED.email_trust,
    assurance_trust = EXCLUDED.assurance_trust,
    domain_hint = EXCLUDED.domain_hint,
    allowed_domains = EXCLUDED.allowed_domains,
    mapped_claims = EXCLUDED.mapped_claims,
    mapped_fields = EXCLUDED.mapped_fields,
    group_claim = EXCLUDED.group_claim,
    keyed_at = EXCLUDED.keyed_at
WHERE federation_connections.tenant_id = EXCLUDED.tenant_id
