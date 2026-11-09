-- Records a code step as the member's latest accepted one, only when it is
-- later than every step accepted before: a row changed means this call won.
UPDATE org_mfa_enrollments
SET last_claimed_step = $2
WHERE org_user_id = $1 AND (last_claimed_step IS NULL OR last_claimed_step < $2)
