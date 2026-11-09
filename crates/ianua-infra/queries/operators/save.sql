-- Keeps an operator: a new one is added, a known one takes the new values.
-- Its creation time never changes.
INSERT INTO operators (id, email, password_hash, status, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    status = EXCLUDED.status
