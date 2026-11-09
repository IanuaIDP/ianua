-- Withdraws every recovery code of a user's set, before the set's codes
-- are written again.
DELETE FROM recovery_codes
WHERE tenant_id = $1 AND user_id = $2
