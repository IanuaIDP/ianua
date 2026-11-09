-- Deletes the template one tenant keeps for one email and locale, or for
-- every locale when no locale is given.
DELETE FROM email_templates
WHERE tenant_id = $1 AND template_type = $2 AND locale IS NOT DISTINCT FROM $3
