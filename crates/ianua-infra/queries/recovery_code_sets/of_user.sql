-- When the set of recovery codes a user of a tenant holds was made, if
-- they hold one.
SELECT user_id, generated_at
FROM recovery_code_sets
WHERE tenant_id = $1 AND user_id = $2
