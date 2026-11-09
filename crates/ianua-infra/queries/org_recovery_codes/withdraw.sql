-- Withdraws every recovery code of a member's set, before the set's codes
-- are written again.
DELETE FROM org_recovery_codes
WHERE org_user_id = $1
