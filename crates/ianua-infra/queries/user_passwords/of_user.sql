-- The password of a user of a tenant, with who set it and when, if they
-- have one.
SELECT password_hash, origin, changed_at
FROM user_passwords
WHERE tenant_id = $1 AND user_id = $2
