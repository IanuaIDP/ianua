-- Keeps the links of one group, all in one statement: a new link is added,
-- a known one takes the account and time it now names.
INSERT INTO org_linked_identity_links (linked_identity_id, tenant_id, user_id, linked_at)
SELECT $1, link.tenant_id, link.user_id, link.linked_at
FROM UNNEST($2::uuid[], $3::uuid[], $4::timestamptz[]) AS link (tenant_id, user_id, linked_at)
ON CONFLICT (linked_identity_id, tenant_id) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    linked_at = EXCLUDED.linked_at
