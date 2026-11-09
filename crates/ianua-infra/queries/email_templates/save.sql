-- Keeps a template in its slot: a new one is added with a new id, the one
-- kept there takes the new parts. Its id never changes.
INSERT INTO email_templates (id, tenant_id, template_type, locale, subject, body_html, body_text)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
ON CONFLICT ON CONSTRAINT email_templates_slot_key DO UPDATE SET
    subject = EXCLUDED.subject,
    body_html = EXCLUDED.body_html,
    body_text = EXCLUDED.body_text
