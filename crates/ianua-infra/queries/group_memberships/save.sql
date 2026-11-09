-- Puts principals into groups of a tenant, all in one statement, each
-- place once however often it is named. A place someone holds still in
-- force when they join is left as it is; one whose end had come by then,
-- not yet cleared by the sweep, is replaced by the new one.
INSERT INTO group_memberships
    (tenant_id, group_id, principal_kind, principal_id, joined_at, expires_at)
SELECT DISTINCT ON (joined.group_id, joined.principal_kind, joined.principal_id)
       $1, joined.group_id, joined.principal_kind, joined.principal_id, joined.joined_at,
       joined.expires_at
FROM UNNEST($2::uuid[], $3::text[], $4::uuid[], $5::timestamptz[], $6::timestamptz[])
    AS joined (group_id, principal_kind, principal_id, joined_at, expires_at)
ON CONFLICT (tenant_id, group_id, principal_kind, principal_id) DO UPDATE SET
    joined_at = EXCLUDED.joined_at,
    expires_at = EXCLUDED.expires_at
WHERE group_memberships.expires_at IS NOT NULL
  AND group_memberships.expires_at <= EXCLUDED.joined_at
