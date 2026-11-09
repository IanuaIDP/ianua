-- The organizations with the given ids, each with the tenants it holds:
-- every one not deleted.
SELECT o.id, o.slug, o.name, o.contact_email, o.display_name, o.plan, o.negotiated_limits,
       o.status, o.suspended_by_member, o.suspended_by_platform, o.auth_config,
       ARRAY(
           SELECT t.id FROM tenants t
           WHERE t.organization_id = o.id AND t.status <> 'deleted'
           ORDER BY t.id
       ) AS "tenant_ids!",
       o.created_at, o.updated_at
FROM organizations o
WHERE o.id = ANY($1)
