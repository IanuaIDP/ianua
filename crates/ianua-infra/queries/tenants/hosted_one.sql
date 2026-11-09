-- One tenant with its organization's slug, for the gateway, which serves
-- it while it is open to requests.
SELECT t.id, t.slug, t.status, t.platform_label, t.readable_address, o.slug AS organization_slug
FROM tenants t
JOIN organizations o ON o.id = t.organization_id
WHERE t.id = $1
