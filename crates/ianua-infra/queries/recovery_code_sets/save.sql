-- Keeps a user's set of recovery codes: a new set is added, a known one
-- takes the time it was made again. Its tenant and user never change.
INSERT INTO recovery_code_sets (tenant_id, user_id, generated_at)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
    generated_at = EXCLUDED.generated_at
