-- The second factor a user of a tenant enrolled, if any.
SELECT user_id, method, sealed_secret, phone_number, status, verified_at,
       recovery_codes_hash, disabled_at, failed_attempts, last_failed_at, enrolled_at
FROM mfa_enrollments
WHERE tenant_id = $1 AND user_id = $2
