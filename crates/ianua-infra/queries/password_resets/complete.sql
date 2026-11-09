-- Completes a password reset of a tenant at the given time, only while it
-- is still pending: a row changed means this call completed it.
UPDATE password_resets
SET status = 'completed', completed_at = $3
WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
