-- Saves a destination, new or changed, never moving it to another
-- organization or changing when it was added.
INSERT INTO org_notification_destinations (
    id, organization_id, name, kind, hook, url, signing_secret, categories, minimum_severity,
    state, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    hook = EXCLUDED.hook,
    url = EXCLUDED.url,
    signing_secret = EXCLUDED.signing_secret,
    categories = EXCLUDED.categories,
    minimum_severity = EXCLUDED.minimum_severity,
    state = EXCLUDED.state,
    updated_at = EXCLUDED.updated_at
WHERE org_notification_destinations.organization_id = EXCLUDED.organization_id
