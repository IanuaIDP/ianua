-- Delay only the failed lease belonging to this tenant and address.
UPDATE platform_certificates SET attempt_id = NULL, lease_until = NULL,
    next_attempt = now() + interval '30 minutes'
WHERE attempt_id = $1 AND tenant_id = $2 AND root = $3
