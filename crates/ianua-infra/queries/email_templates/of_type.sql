-- Every template one tenant keeps for one email, whatever its locale.
SELECT id, template_type, locale, subject, body_html, body_text
FROM email_templates
WHERE tenant_id = $1 AND template_type = $2
