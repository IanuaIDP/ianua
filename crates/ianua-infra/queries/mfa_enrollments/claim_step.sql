-- Records a code step as a user's latest accepted one, only when it is
-- later than every step accepted before: a row changed means this call won.
UPDATE mfa_enrollments
SET last_claimed_step = $3
WHERE tenant_id = $1 AND user_id = $2
    AND (last_claimed_step IS NULL OR last_claimed_step < $3)
