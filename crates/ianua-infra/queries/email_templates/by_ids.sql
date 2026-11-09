-- The templates of one tenant with the given ids.
SELECT id, template_type, locale, subject, body_html, body_text
FROM email_templates
WHERE tenant_id = $1 AND id = ANY($2)
