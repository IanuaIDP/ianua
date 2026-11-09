-- Whether one principal holds a role of a tenant given straight to them,
-- still in force at the given time. One whose end has come counts for
-- nothing, whether or not the sweep has cleared it yet.
SELECT EXISTS (
    SELECT 1
    FROM role_assignments
    WHERE tenant_id = $1 AND role_id = $2 AND principal_kind = $3 AND principal_id = $4
      AND (expires_at IS NULL OR expires_at > $5)
) AS "held!"
