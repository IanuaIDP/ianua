-- Keeps a tenant's branding: made the first time, every part replaced
-- after.
INSERT INTO tenant_branding
    (tenant_id, logo_url, primary_color, background_color, css_source, css_rendered,
     email_from_name, email_from_address)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id) DO UPDATE SET
    logo_url = EXCLUDED.logo_url,
    primary_color = EXCLUDED.primary_color,
    background_color = EXCLUDED.background_color,
    css_source = EXCLUDED.css_source,
    css_rendered = EXCLUDED.css_rendered,
    email_from_name = EXCLUDED.email_from_name,
    email_from_address = EXCLUDED.email_from_address
