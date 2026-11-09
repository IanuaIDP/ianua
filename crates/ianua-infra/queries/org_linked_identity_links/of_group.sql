-- The links of one group, across its tenants, the oldest first.
SELECT tenant_id, user_id, linked_at
FROM org_linked_identity_links
WHERE linked_identity_id = $1
ORDER BY linked_at, tenant_id
