-- Whether one principal is in a group of a tenant, still in force at the
-- given time. A place whose end has come counts for nothing, whether or
-- not the sweep has cleared it yet.
SELECT EXISTS (
    SELECT 1
    FROM group_memberships
    WHERE tenant_id = $1 AND group_id = $2 AND principal_kind = $3 AND principal_id = $4
      AND (expires_at IS NULL OR expires_at > $5)
) AS "held!"
