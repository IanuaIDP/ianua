-- Every tenant not deleted, with its organization's slug, for the gateway,
-- which serves each of them that is open to requests.
SELECT t.id, t.slug, t.status, t.platform_label, t.readable_address, o.slug AS organization_slug
FROM tenants t
JOIN organizations o ON o.id = t.organization_id
WHERE t.status <> 'deleted'
ORDER BY t.id
