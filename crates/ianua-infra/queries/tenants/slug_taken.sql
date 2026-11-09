-- Whether a tenant of the organization already has the given slug.
SELECT EXISTS (
    SELECT 1 FROM tenants WHERE slug = $1 AND organization_id = $2
) AS "taken!"
