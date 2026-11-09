-- The connections of a tenant with the given ids, each with the rules of
-- its group mapping in the order they were given: the provider's group,
-- whether the rule gives a role or a group, and which.
SELECT c.id, c.provider_name, c.status, c.saml, c.oidc, c.jit_provisioning,
       c.jit_default_role_id, c.email_trust, c.assurance_trust, c.domain_hint,
       c.allowed_domains, c.mapped_claims, c.mapped_fields, c.group_claim,
       ARRAY(
           SELECT r.provider_group
           FROM connection_group_rules r
           WHERE r.tenant_id = c.tenant_id AND r.connection_id = c.id
           ORDER BY r.position
       ) AS "rule_groups!",
       ARRAY(
           SELECT CASE WHEN r.role_id IS NULL THEN 'group' ELSE 'role' END
           FROM connection_group_rules r
           WHERE r.tenant_id = c.tenant_id AND r.connection_id = c.id
           ORDER BY r.position
       ) AS "rule_kinds!",
       ARRAY(
           SELECT coalesce(r.role_id, r.group_id)
           FROM connection_group_rules r
           WHERE r.tenant_id = c.tenant_id AND r.connection_id = c.id
           ORDER BY r.position
       ) AS "rule_grants!",
       c.created_at, c.keyed_at
FROM federation_connections c
WHERE c.tenant_id = $1 AND c.id = ANY($2)
