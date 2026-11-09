-- The branding of the given organization, when anyone saved one.
SELECT organization_id, logo_url, primary_color, sender_name, created_at, updated_at
FROM org_branding
WHERE organization_id = $1
