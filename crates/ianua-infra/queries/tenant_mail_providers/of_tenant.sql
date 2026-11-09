-- The mail provider one tenant named, if it named one.
SELECT kind, smtp_host, smtp_port, smtp_security, smtp_username, ses_region,
       ses_access_key_id, mailgun_domain, mailgun_region, credential,
       check_state, checked_at, updated_at
FROM tenant_mail_providers
WHERE tenant_id = $1
