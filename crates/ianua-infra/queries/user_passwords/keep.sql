-- Sets the password of a user of a tenant: a first one is added, a known
-- one is replaced, with who set it and when.
INSERT INTO user_passwords (tenant_id, user_id, password_hash, origin, changed_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    origin = EXCLUDED.origin,
    changed_at = EXCLUDED.changed_at
