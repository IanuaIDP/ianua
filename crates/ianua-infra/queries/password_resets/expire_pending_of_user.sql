-- Expires every pending password reset a user of a tenant holds.
UPDATE password_resets
SET status = 'expired'
WHERE tenant_id = $1 AND user_id = $2 AND status = 'pending'
