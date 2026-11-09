-- Keeps a tenant's mail provider, replacing the one kept, every column the
-- new kind leaves out emptied.
INSERT INTO tenant_mail_providers
    (tenant_id, kind, smtp_host, smtp_port, smtp_security, smtp_username, ses_region,
     ses_access_key_id, mailgun_domain, mailgun_region, credential,
     check_state, checked_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (tenant_id) DO UPDATE SET
    kind = EXCLUDED.kind,
    smtp_host = EXCLUDED.smtp_host,
    smtp_port = EXCLUDED.smtp_port,
    smtp_security = EXCLUDED.smtp_security,
    smtp_username = EXCLUDED.smtp_username,
    ses_region = EXCLUDED.ses_region,
    ses_access_key_id = EXCLUDED.ses_access_key_id,
    mailgun_domain = EXCLUDED.mailgun_domain,
    mailgun_region = EXCLUDED.mailgun_region,
    credential = EXCLUDED.credential,
    check_state = EXCLUDED.check_state,
    checked_at = EXCLUDED.checked_at,
    updated_at = EXCLUDED.updated_at
