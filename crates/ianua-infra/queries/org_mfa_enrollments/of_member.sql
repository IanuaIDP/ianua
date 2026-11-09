-- The second factor an organization member enrolled, if any.
SELECT org_user_id, method, sealed_secret, phone_number, status, verified_at,
       recovery_codes_hash, disabled_at, failed_attempts, last_failed_at, enrolled_at
FROM org_mfa_enrollments
WHERE org_user_id = $1
