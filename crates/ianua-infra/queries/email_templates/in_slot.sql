-- The template one tenant keeps for one email and locale, or for every
-- locale when no locale is given.
SELECT id, template_type, locale, subject, body_html, body_text
FROM email_templates
WHERE tenant_id = $1 AND template_type = $2 AND locale IS NOT DISTINCT FROM $3
