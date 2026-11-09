-- The branding of one tenant, when it saved one.
SELECT logo_url, primary_color, background_color, css_source, css_rendered,
       email_from_name, email_from_address
FROM tenant_branding
WHERE tenant_id = $1
