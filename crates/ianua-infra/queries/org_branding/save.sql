-- Keeps an organization's branding: made the first time, changed after.
-- When it was first made never changes.
INSERT INTO org_branding
    (organization_id, logo_url, primary_color, sender_name, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (organization_id) DO UPDATE SET
    logo_url = EXCLUDED.logo_url,
    primary_color = EXCLUDED.primary_color,
    sender_name = EXCLUDED.sender_name,
    updated_at = EXCLUDED.updated_at
