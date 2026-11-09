-- When an organization member's set of recovery codes was made, if they
-- hold one.
SELECT org_user_id, generated_at
FROM org_recovery_code_sets
WHERE org_user_id = $1
