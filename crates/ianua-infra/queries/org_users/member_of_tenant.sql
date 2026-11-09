-- Whether the given member belongs to the organization that owns the
-- given tenant.
SELECT EXISTS (
    SELECT 1
    FROM tenants t
    JOIN org_users m ON m.organization_id = t.organization_id
    WHERE t.id = $1 AND m.id = $2
) AS "exists!"
