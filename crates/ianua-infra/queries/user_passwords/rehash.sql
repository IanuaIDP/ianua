-- Replaces the hash of a user's password with a new hash of the same
-- password, keeping who set it and when, only while the stored hash is
-- still the one the sign-in proved: a password changed meanwhile is never
-- put back.
UPDATE user_passwords
SET password_hash = $4
WHERE tenant_id = $1 AND user_id = $2 AND password_hash = $3
