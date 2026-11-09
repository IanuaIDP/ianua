-- Keeps a member's set of recovery codes: a new set is added, a known one
-- takes the time it was made again. Its member never changes.
INSERT INTO org_recovery_code_sets (org_user_id, generated_at)
VALUES ($1, $2)
ON CONFLICT (org_user_id) DO UPDATE SET
    generated_at = EXCLUDED.generated_at
